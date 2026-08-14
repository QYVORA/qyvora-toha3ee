// Package ports implements a raw SYN port scanner with banner grabbing and
// lightweight service fingerprinting.
package ports

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"github.com/QYVORA/qyvora-toha3ee/internal/netx"
	"github.com/QYVORA/qyvora-toha3ee/internal/netx/arp"
	"github.com/QYVORA/qyvora-toha3ee/internal/stealth"
)

// State is the verdict for a scanned TCP port.
type State string

// Port states.
const (
	Open         State = "open"          // a SYN-ACK was received
	Closed       State = "closed"        // a RST was received
	Filtered     State = "filtered"      // no response (firewall drops)
	Unfiltered   State = "unfiltered"    // ACK probe reached the port, RST came back
	OpenFiltered State = "open|filtered" // no reply, cannot tell apart
)

// Result describes the outcome of probing one port.
type Result struct {
	Port  uint16
	State State
}

// Scanner performs raw SYN scans from a pcap handle.
type Scanner struct {
	iface           *netx.Iface
	handle          *pcap.Handle
	stealth         *stealth.Config
	decoys          []net.IP // spoofed source addresses, see SetDecoys
	fragment        bool     // fragment outgoing probes, see SetFragment
	zombieProbePort uint16   // port used to read the zombie's IP ID counter
}

// NewScanner opens a pcap handle on iface for scanning. The snapshot length
// of 65535 captures whole frames, promiscuous mode lets us see traffic not
// addressed to this host, and the 500ms timeout bounds blocking reads.
func NewScanner(iface *netx.Iface) (*Scanner, error) {
	handle, err := pcap.OpenLive(iface.Name, 65535, true, 500*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", iface.Name, err)
	}
	return &Scanner{iface: iface, handle: handle, stealth: stealth.New()}, nil
}

// SetStealth applies a stealth profile to probes and banner grabs.
func (s *Scanner) SetStealth(cfg *stealth.Config) {
	if cfg != nil {
		s.stealth = cfg
	}
}

// Close releases the pcap handle.
func (s *Scanner) Close() { s.handle.Close() }

// CommonPorts is the default scan set: well-known service ports.
var CommonPorts = []uint16{
	21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445,
	465, 587, 631, 636, 993, 995, 1080, 1433, 1521, 2049, 2375, 3000, 3306,
	3389, 5432, 5900, 5985, 6379, 7001, 8000, 8080, 8443, 8888, 9000, 9090,
	9100, 9200, 11211, 27017,
}

// Scan probes ip on the given ports with a half-open SYN. It returns the
// results sorted by port. Targets that drop probes report filtered.
func (s *Scanner) Scan(ip net.IP, ports []uint16, timeout time.Duration) ([]Result, error) {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	dstMAC, err := s.resolveMAC(ip, timeout/2)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", ip, err)
	}

	// Watch only for the two signals that matter in a SYN scan: SYN-ACK
	// (open) and RST (closed) coming back from the target. Filtering at the
	// BPF level keeps the userspace packet loop cheap.
	if err := s.handle.SetBPFFilter(fmt.Sprintf(
		"tcp and host %s and (tcp[tcpflags] & (tcp-syn|tcp-rst) != 0)", ip)); err != nil {
		return nil, fmt.Errorf("set bpf: %w", err)
	}

	var sent atomic.Int64
	var got sync.Map // port -> State
	done := make(chan struct{})
	// Reader goroutine: record replies for the duration of the scan.
	go func() {
		ps := gopacket.NewPacketSource(s.handle, layers.LayerTypeEthernet)
		ps.NoCopy = true
		for {
			select {
			case <-done:
				return
			default:
			}
			pkt, err := ps.NextPacket()
			if err != nil {
				select {
				case <-done:
				default:
				}
				return
			}
			tcpL := pkt.Layer(layers.LayerTypeTCP)
			ipL := pkt.Layer(layers.LayerTypeIPv4)
			if tcpL == nil || ipL == nil {
				continue
			}
			tcp := tcpL.(*layers.TCP)
			ip4 := ipL.(*layers.IPv4)
			// Ignore anything not sourced from the target itself (e.g. other
			// hosts answering our spoofed source ports).
			if !ip4.SrcIP.Equal(ip) {
				continue
			}
			// The scanned port is the TCP source port of the reply.
			port := uint16(tcp.SrcPort)
			switch {
			case tcp.SYN && tcp.ACK:
				got.Store(port, Open)
			case tcp.RST:
				// First verdict wins: a port that already reported open must
				// not be overwritten by a spurious late RST.
				if _, exists := got.Load(port); !exists {
					got.Store(port, Closed)
				}
			}
		}
	}()

	// Fire all SYN probes with burst pacing.
	pace := stealth.NewPacer(s.stealth)
	for _, port := range ports {
		if err := s.sendSYN(ip, dstMAC, port); err != nil {
			close(done)
			return nil, err
		}
		sent.Add(1)
		pace.Wait()
	}

	// Give the target time to answer, then stop the reader.
	time.Sleep(timeout)
	close(done)

	results := make([]Result, 0, len(ports))
	for _, port := range ports {
		st, ok := got.Load(port)
		if !ok {
			// No SYN-ACK and no RST: the probe was dropped by a firewall.
			results = append(results, Result{Port: port, State: Filtered})
			continue
		}
		results = append(results, Result{Port: port, State: st.(State)})
	}
	sort.Slice(results, func(i, j int) bool { return results[i].Port < results[j].Port })
	return results, nil
}

// ScanMode selects the crafted TCP control-flag pattern for a scan.
type ScanMode int

// Scan modes. The flag sets follow the classic Nmap taxonomy: RFC-793-compliant
// stacks must RST when a port is closed, regardless of the flags; open ports
// drop flag-combination probes, which makes the silence meaningful.
const (
	ScanSYN  ScanMode = iota // SYN (half-open)
	ScanFIN                  // FIN only
	ScanNULL                 // no flags at all
	ScanXMAS                 // FIN|PSH|URG
	ScanACK                  // ACK only
)

// flags returns the TCP control-flag set for the scan mode.
func (m ScanMode) flags() ProbeFlags {
	switch m {
	case ScanFIN:
		return ProbeFlags{FIN: true}
	case ScanNULL:
		return ProbeFlags{} // a packet with an empty flags octet
	case ScanXMAS:
		return ProbeFlags{FIN: true, PSH: true, URG: true}
	case ScanACK:
		return ProbeFlags{ACK: true}
	default:
		return ProbeFlags{SYN: true}
	}
}

// String returns the scan mode name.
func (m ScanMode) String() string {
	switch m {
	case ScanFIN:
		return "fin"
	case ScanNULL:
		return "null"
	case ScanXMAS:
		return "xmas"
	case ScanACK:
		return "ack"
	default:
		return "syn"
	}
}

// ParseScanMode converts a name to a ScanMode.
func ParseScanMode(s string) ScanMode {
	switch s {
	case "fin":
		return ScanFIN
	case "null":
		return ScanNULL
	case "xmas", "xmass":
		return ScanXMAS
	case "ack":
		return ScanACK
	default:
		return ScanSYN
	}
}

// ScanFlags probes ip on the given ports using a crafted control-flag pattern.
// RST replies mark closed ports (FIN/NULL/XMAS) or unfiltered ports (ACK);
// silence marks filtered (or, for FIN/NULL/XMAS, open-but-silent) ports.
func (s *Scanner) ScanFlags(ip net.IP, ports []uint16, timeout time.Duration, mode ScanMode) ([]Result, error) {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	dstMAC, err := s.resolveMAC(ip, timeout/2)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", ip, err)
	}

	// RST replies are the only signal for non-SYN flag patterns.
	if err := s.handle.SetBPFFilter(fmt.Sprintf(
		"tcp and host %s and tcp[tcpflags] & tcp-rst != 0", ip)); err != nil {
		return nil, fmt.Errorf("set bpf: %w", err)
	}

	var got sync.Map // port -> State
	done := make(chan struct{})
	go func() {
		ps := gopacket.NewPacketSource(s.handle, layers.LayerTypeEthernet)
		ps.NoCopy = true
		for {
			select {
			case <-done:
				return
			default:
			}
			pkt, err := ps.NextPacket()
			if err != nil {
				return
			}
			tcpL := pkt.Layer(layers.LayerTypeTCP)
			ipL := pkt.Layer(layers.LayerTypeIPv4)
			if tcpL == nil || ipL == nil {
				continue
			}
			tcp := tcpL.(*layers.TCP)
			ip4 := ipL.(*layers.IPv4)
			// Only a RST from the target means "closed" for these modes.
			if !ip4.SrcIP.Equal(ip) || !tcp.RST {
				continue
			}
			if _, exists := got.Load(uint16(tcp.SrcPort)); !exists {
				got.Store(uint16(tcp.SrcPort), Closed)
			}
		}
	}()

	pace := stealth.NewPacer(s.stealth)
	fl := mode.flags()
	for _, port := range ports {
		if err := s.sendProbe(ip, dstMAC, port, fl); err != nil {
			close(done)
			return nil, err
		}
		pace.Wait()
	}

	time.Sleep(timeout)
	close(done)

	results := make([]Result, 0, len(ports))
	for _, port := range ports {
		st, ok := got.Load(port)
		if !ok {
			// FIN/NULL/XMAS silence means open or filtered; ACK silence means filtered.
			// An ACK probe is answered by every reached host, so silence proves
			// a firewall; the other modes only elicit a response on closed ports.
			if mode == ScanACK {
				results = append(results, Result{Port: port, State: Filtered})
			} else {
				results = append(results, Result{Port: port, State: OpenFiltered})
			}
			continue
		}
		if mode == ScanACK {
			// Any RST proves the target is reachable (not firewalled).
			results = append(results, Result{Port: port, State: Unfiltered})
			continue
		}
		results = append(results, Result{Port: port, State: st.(State)})
	}
	sort.Slice(results, func(i, j int) bool { return results[i].Port < results[j].Port })
	return results, nil
}

// sendProbe writes a crafted TCP probe with the given flag pattern and
// stealth-randomized IP/TCP fields. Each field is either randomized (when the
// stealth profile enables it) or kept at a conservative default.
func (s *Scanner) sendProbe(dstIP net.IP, dstMAC net.HardwareAddr, port uint16, fl ProbeFlags) error {
	st := s.stealth
	sport := port
	seq := uint32(time.Now().UnixNano() & 0xffffffff)
	var ack uint32
	// Fingerprintable defaults: TTL 64, window 64240, IP ID 0 (let the NIC
	// assign), DF set.
	ttl, window, id := uint8(64), uint16(64240), uint16(0)
	df := true
	if st.Feature(st.RandomizePort) {
		sport = st.RandomSrcPort()
	}
	if st.Feature(st.RandomizeTTL) {
		ttl = st.TTL(64, 8)
		if st.DF(0.15) {
			df = false
		}
	}
	if st.Feature(st.RandomizeID) {
		id = st.RandomIPID()
		window = st.Window()
		seq = st.RandomSeq()
	}
	// ACK probes carry an acknowledgment number; randomize it so stateful
	// firewalls cannot tie the probe to a real connection.
	if fl.ACK {
		ack = st.RandomSeq()
	}
	raw, err := BuildProbe(s.iface.IP, dstIP, s.iface.MAC, dstMAC, sport, port, seq, ack, fl, ttl, df, window, id)
	if err != nil {
		return err
	}
	return s.writeRaw(raw)
}

// TCPFingerprint is the TCP-stack answer parsed from a target's SYN-ACK,
// used to identify the operating system from network behavior.
type TCPFingerprint struct {
	TTL     uint8
	Window  uint16
	MSS     uint16
	WS      uint8
	SACKOK  bool
	DF      bool
	Options string // canonical options string for signature matching
}

// Fingerprint sends one SYN to a single port and parses the SYN-ACK reply
// into a TCPFingerprint. It returns an error when no SYN-ACK is seen.
func (s *Scanner) Fingerprint(ip net.IP, port uint16, timeout time.Duration) (*TCPFingerprint, error) {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	dstMAC, err := s.resolveMAC(ip, timeout/3)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", ip, err)
	}
	// Only SYN-ACKs from the target are interesting; filter everything else
	// out at the kernel level.
	if err := s.handle.SetBPFFilter(fmt.Sprintf(
		"tcp and host %s and tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack)", ip)); err != nil {
		return nil, fmt.Errorf("set bpf: %w", err)
	}

	sport := port
	seq := uint32(time.Now().UnixNano() & 0xffffffff)
	if s.stealth.Feature(s.stealth.RandomizePort) {
		sport = s.stealth.RandomSrcPort()
	}
	ttl := uint8(64)
	if s.stealth.Feature(s.stealth.RandomizeTTL) {
		ttl = s.stealth.TTL(64, 8)
	}
	raw, err := BuildSYNEx(s.iface.IP, ip, s.iface.MAC, dstMAC, sport, port, seq, ttl, true, 64240, 0)
	if err != nil {
		return nil, err
	}
	if err := s.handle.WritePacketData(raw); err != nil {
		return nil, err
	}

	deadline := time.Now().Add(timeout)
	ps := gopacket.NewPacketSource(s.handle, layers.LayerTypeEthernet)
	ps.NoCopy = true
	for time.Now().Before(deadline) {
		pkt, err := ps.NextPacket()
		if err != nil {
			continue
		}
		ipL := pkt.Layer(layers.LayerTypeIPv4)
		tcpL := pkt.Layer(layers.LayerTypeTCP)
		if ipL == nil || tcpL == nil {
			continue
		}
		ip4 := ipL.(*layers.IPv4)
		tcp := tcpL.(*layers.TCP)
		// Match a SYN-ACK from the target to our exact probe tuple.
		if !ip4.SrcIP.Equal(ip) || tcp.SrcPort != layers.TCPPort(port) || !tcp.SYN || !tcp.ACK {
			continue
		}
		// The target's own TTL (after its initial decrement), window and DF
		// bit are the classic OS fingerprinting signals.
		fp := &TCPFingerprint{
			TTL:    ip4.TTL,
			Window: tcp.Window,
			DF:     ip4.Flags&layers.IPv4DontFragment != 0,
		}
		parseTCPOptions(tcp.Options, fp)
		return fp, nil
	}
	return nil, fmt.Errorf("no SYN-ACK from %s:%d", ip, port)
}

// parseTCPOptions extracts MSS, window scale and SACK-permitted from the
// SYN-ACK option list and builds the canonical options signature.
func parseTCPOptions(opts []layers.TCPOption, fp *TCPFingerprint) {
	var parts []string
	for _, o := range opts {
		switch o.OptionType {
		case 2: // MSS: 2-byte big-endian max segment size
			if len(o.OptionData) == 2 {
				fp.MSS = uint16(o.OptionData[0])<<8 | uint16(o.OptionData[1])
			}
			parts = append(parts, "mss")
		case 3: // window scale: single shift-count byte
			if len(o.OptionData) == 1 {
				fp.WS = o.OptionData[0]
			}
			parts = append(parts, "ws")
		case 4: // SACK permitted (no payload)
			fp.SACKOK = true
			parts = append(parts, "sackok")
		default:
			parts = append(parts, fmt.Sprintf("opt%d", o.OptionType))
		}
	}
	fp.Options = fmt.Sprintf("ttl:%d win:%d mss:%d ws:%d sackok:%v df:%v [%s]",
		fp.TTL, fp.Window, fp.MSS, fp.WS, fp.SACKOK, fp.DF, strings.Join(parts, ","))
}

// resolveMAC finds the MAC address for ip on the local link via ARP, so raw
// frames can be addressed to the correct destination.
func (s *Scanner) resolveMAC(ip net.IP, timeout time.Duration) (net.HardwareAddr, error) {
	raw, err := arp.BuildRequest(s.iface.MAC, s.iface.IP, broadcastMAC, ip)
	if err != nil {
		return nil, err
	}
	if err := s.handle.WritePacketData(raw); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		pkt, err := gopacket.NewPacketSource(s.handle, layers.LayerTypeEthernet).NextPacket()
		if err != nil {
			continue
		}
		arpL := pkt.Layer(layers.LayerTypeARP)
		eth := pkt.Layer(layers.LayerTypeEthernet)
		if arpL == nil || eth == nil {
			continue
		}
		a := arpL.(*layers.ARP)
		// An ARP reply whose sender protocol address matches the target gives
		// us its MAC in the ethernet source address.
		if a.Operation == layers.ARPReply && len(a.SourceProtAddress) >= 4 && net.IP(a.SourceProtAddress[:4]).Equal(ip) {
			return eth.(*layers.Ethernet).SrcMAC, nil
		}
	}
	return nil, fmt.Errorf("no ARP reply")
}

// sendSYN writes one half-open SYN probe, applying the configured stealth
// randomization to the source port, TTL, DF bit, window and IP identification.
func (s *Scanner) sendSYN(dstIP net.IP, dstMAC net.HardwareAddr, port uint16) error {
	st := s.stealth

	// Defaults: source port mirrors the scanned port, TTL 64, window 64240,
	// IP ID 0 and DF set. Stealth features replace them when enabled.
	sport := port
	seq := uint32(time.Now().UnixNano() & 0xffffffff)
	ttl, window, id := uint8(64), uint16(64240), uint16(0)
	df := true
	if st.Feature(st.RandomizePort) {
		sport = st.RandomSrcPort()
	}
	if st.Feature(st.RandomizeTTL) {
		ttl = st.TTL(64, 8)
		// Occasionally clear DF so the probes do not share a uniform shape.
		if st.DF(0.15) {
			df = false
		}
	}
	if st.Feature(st.RandomizeID) {
		id = st.RandomIPID()
		window = st.Window()
		seq = st.RandomSeq()
	}
	raw, err := BuildSYNEx(s.iface.IP, dstIP, s.iface.MAC, dstMAC, sport, port, seq, ttl, df, window, id)
	if err != nil {
		return err
	}
	return s.writeRaw(raw)
}

// Banner is the result of a banner grab on an open port.
type Banner struct {
	Port    uint16
	Banner  string
	Service string
	Secure  bool
}

// GrabBanners connects to each open port and reads a short banner.
func (s *Scanner) GrabBanners(ip net.IP, ports []uint16, timeout time.Duration) []Banner {
	var out []Banner
	for _, p := range ports {
		s.stealth.JitterSleep()
		svc := GuessService(p)
		addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", p))
		conn, err := net.DialTimeout("tcp", addr, timeout)
		if err != nil {
			continue // connect refused / filtered: nothing to grab
		}
		_ = conn.SetDeadline(time.Now().Add(timeout))
		buf := make([]byte, 512)
		n, _ := conn.Read(buf)
		conn.Close()
		banner := sanitize(string(buf[:n]))
		out = append(out, Banner{Port: p, Banner: banner, Service: svc, Secure: isTLS(p)})
	}
	return out
}

// sanitize strips non-printable bytes from a banner so it is safe to store and
// display, collapsing newlines into " | " and capping at 256 characters.
func sanitize(s string) string {
	clean := make([]byte, 0, len(s))
	for i := 0; i < len(s) && i < 256; i++ {
		c := s[i]
		if c >= 0x20 && c < 0x7f {
			clean = append(clean, c)
		} else if c == '\n' {
			clean = append(clean, ' ', '|', ' ')
		}
	}
	return string(clean)
}

// GuessService maps a well-known port to a service name.
func GuessService(port uint16) string {
	switch port {
	case 21:
		return "ftp"
	case 22:
		return "ssh"
	case 23:
		return "telnet"
	case 25:
		return "smtp"
	case 53:
		return "dns"
	case 80:
		return "http"
	case 110:
		return "pop3"
	case 111:
		return "rpcbind"
	case 135:
		return "msrpc"
	case 139:
		return "netbios-ssn"
	case 143:
		return "imap"
	case 389:
		return "ldap"
	case 443:
		return "https"
	case 445:
		return "microsoft-ds"
	case 587:
		return "smtp-submission"
	case 631:
		return "ipp"
	case 636:
		return "ldaps"
	case 993:
		return "imaps"
	case 995:
		return "pop3s"
	case 1433:
		return "mssql"
	case 1521:
		return "oracle"
	case 2049:
		return "nfs"
	case 3306:
		return "mysql"
	case 3389:
		return "rdp"
	case 5432:
		return "postgresql"
	case 5900:
		return "vnc"
	case 5985:
		return "winrm"
	case 6379:
		return "redis"
	case 8080:
		return "http-proxy"
	case 8443:
		return "https-alt"
	case 9200:
		return "elasticsearch"
	case 11211:
		return "memcached"
	case 27017:
		return "mongodb"
	}
	return "unknown"
}

// isTLS reports whether the port is expected to speak TLS by default, so
// banner results can be flagged as encrypted.
func isTLS(port uint16) bool {
	switch port {
	case 443, 636, 993, 995, 8443:
		return true
	}
	return false
}

// broadcastMAC is the all-ones ethernet destination used for ARP requests.
var broadcastMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

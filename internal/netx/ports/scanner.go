// Package ports implements a raw SYN port scanner with banner grabbing and
// lightweight service fingerprinting.
package ports

import (
	"fmt"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"github.com/qyvora/toha3ee/internal/netx"
	"github.com/qyvora/toha3ee/internal/netx/arp"
	"github.com/qyvora/toha3ee/internal/stealth"
)

// State is the verdict for a scanned TCP port.
type State string

// Port states.
const (
	Open     State = "open"
	Closed   State = "closed"
	Filtered State = "filtered"
)

// Result describes the outcome of probing one port.
type Result struct {
	Port  uint16
	State State
}

// Scanner performs raw SYN scans from a pcap handle.
type Scanner struct {
	iface   *netx.Iface
	handle  *pcap.Handle
	stealth *stealth.Config
}

// NewScanner opens a pcap handle on iface for scanning.
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

	if err := s.handle.SetBPFFilter(fmt.Sprintf(
		"tcp and host %s and (tcp[tcpflags] & (tcp-syn|tcp-rst) != 0)", ip)); err != nil {
		return nil, fmt.Errorf("set bpf: %w", err)
	}

	var sent atomic.Int64
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
			if !ip4.SrcIP.Equal(ip) {
				continue
			}
			port := uint16(tcp.SrcPort)
			switch {
			case tcp.SYN && tcp.ACK:
				got.Store(port, Open)
			case tcp.RST:
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

	time.Sleep(timeout)
	close(done)

	results := make([]Result, 0, len(ports))
	for _, port := range ports {
		st, ok := got.Load(port)
		if !ok {
			results = append(results, Result{Port: port, State: Filtered})
			continue
		}
		results = append(results, Result{Port: port, State: st.(State)})
	}
	sort.Slice(results, func(i, j int) bool { return results[i].Port < results[j].Port })
	return results, nil
}

// resolveMAC resolves the target's L2 address via an ARP who-has probe.
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
		if a.Operation == layers.ARPReply && len(a.SourceProtAddress) >= 4 && net.IP(a.SourceProtAddress[:4]).Equal(ip) {
			return eth.(*layers.Ethernet).SrcMAC, nil
		}
	}
	return nil, fmt.Errorf("no ARP reply")
}

func (s *Scanner) sendSYN(dstIP net.IP, dstMAC net.HardwareAddr, port uint16) error {
	st := s.stealth

	sport := port
	seq := uint32(time.Now().UnixNano() & 0xffffffff)
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
	raw, err := BuildSYNEx(s.iface.IP, dstIP, s.iface.MAC, dstMAC, sport, port, seq, ttl, df, window, id)
	if err != nil {
		return err
	}
	return s.handle.WritePacketData(raw)
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
			continue
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

func isTLS(port uint16) bool {
	switch port {
	case 443, 636, 993, 995, 8443:
		return true
	}
	return false
}

var broadcastMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

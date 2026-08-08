package ports

import (
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/qyvora/toha3ee/internal/stealth"
)

// Decoys and fragmentation are transport-level stealth options applied to the
// same crafted probes used by the half-open scanner. Decoys make a probe burst
// look like it originates from several source hosts; fragmentation splits each
// probe so middleboxes that inspect whole streams may skip it.

// SetDecoys makes every probe also be sent from the given spoofed source
// addresses, in addition to the real source. The target receives identical
// probes from many IPs, obscuring which host is the real scanner; replies to
// decoy addresses are simply dropped at the spoofed source, so results are
// unaffected.
func (s *Scanner) SetDecoys(decoys []net.IP) { s.decoys = decoys }

// SetFragment enables two-fragment IP fragmentation for outgoing probes, so
// each crafted SYN is sent as two small fragments. Firewalls that only
// inspect whole reassembled datagrams may pass the probe.
func (s *Scanner) SetFragment(enabled bool) { s.fragment = enabled }

// DecoyProbes reports how many spoofed source addresses are configured.
func (s *Scanner) DecoyProbes() int { return len(s.decoys) }

// writeRaw sends one raw ethernet frame, optionally fragmenting it and
// duplicating it for each configured decoy.
func (s *Scanner) writeRaw(raw []byte) error {
	pkts := [][]byte{raw}
	if s.fragment {
		frags, err := fragmentPacket(raw, 8)
		if err != nil {
			return err
		}
		pkts = frags
	}
	for _, p := range pkts {
		if err := s.handle.WritePacketData(p); err != nil {
			return err
		}
	}
	for _, dec := range s.decoys {
		for _, p := range pkts {
			d := applySourceIP(p, dec)
			if d == nil {
				continue
			}
			if err := s.handle.WritePacketData(d); err != nil {
				return err
			}
		}
	}
	return nil
}

// applySourceIP rewrites the IPv4 source address and header checksum of a raw
// ethernet+IPv4 packet, and varies the IP identification so the decoy packet
// is not byte-identical to the real one.
func applySourceIP(raw []byte, src net.IP) []byte {
	if len(raw) < 34 || raw[12] != 0x08 || raw[13] != 0x00 {
		return nil
	}
	ipStart := 14
	out := make([]byte, len(raw))
	copy(out, raw)
	id := uint16(time.Now().UnixNano() & 0xffff)
	out[ipStart+4] = byte(id >> 8)
	out[ipStart+5] = byte(id)
	copy(out[ipStart+12:ipStart+16], src.To4())
	fixChecksum(out, ipStart, 20)
	return out
}

// fragmentPacket splits the IP payload of a raw ethernet frame into two
// fragments of at most fragSize bytes each, producing two complete frames.
// Because crafted probes typically carry no TCP payload, fragSize must be
// smaller than the TCP header itself (Nmap uses 8 bytes with -f) so the header
// is split across fragments and middleboxes cannot inspect the full flags.
func fragmentPacket(raw []byte, fragSize int) ([][]byte, error) {
	if len(raw) < 14+20 {
		return [][]byte{raw}, nil
	}
	ipStart := 14
	ihl := int(raw[ipStart]&0x0f) * 4
	total := int(raw[ipStart+2])<<8 | int(raw[ipStart+3])
	// Trim ethernet padding/FCS: the IP total-length field is authoritative.
	if end := ipStart + total; end <= len(raw) && end >= ipStart+ihl {
		raw = raw[:end]
	}
	payload := raw[ipStart+ihl:]
	if len(payload) <= fragSize {
		return [][]byte{raw}, nil
	}
	rest := raw[ipStart+ihl+fragSize:]
	off := (fragSize / 8) & 0x1fff

	f1 := make([]byte, ipStart+ihl+fragSize)
	copy(f1, raw[:ipStart+ihl+fragSize])
	f2 := make([]byte, ipStart+ihl+len(rest))
	copy(f2, raw[:ipStart+ihl])
	copy(f2[ipStart+ihl:], rest)

	// Fragment 1: more-fragments set, new total length.
	f1[ipStart+2] = byte((ipStart + ihl + fragSize) >> 8)
	f1[ipStart+3] = byte(ipStart + ihl + fragSize)
	f1[ipStart+6] |= 0x20
	fixChecksum(f1, ipStart, ihl)

	// Fragment 2: fragment offset set, MF cleared, new total length.
	f2[ipStart+2] = byte((ipStart + ihl + len(rest)) >> 8)
	f2[ipStart+3] = byte(ipStart + ihl + len(rest))
	f2[ipStart+6] = byte(off >> 8)
	f2[ipStart+7] = byte(off)
	fixChecksum(f2, ipStart, ihl)

	return [][]byte{f1, f2}, nil
}

// fixChecksum zeroes and recomputes the IPv4 header checksum after edits.
func fixChecksum(pkt []byte, ipStart, ihl int) {
	pkt[ipStart+10], pkt[ipStart+11] = 0, 0
	cs := ipChecksum(pkt[ipStart : ipStart+ihl])
	pkt[ipStart+10] = byte(cs >> 8)
	pkt[ipStart+11] = byte(cs)
}

func ipChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// ProtocolSet is the default IP protocol numbers probed by a protocol scan,
// skipping ICMP(1) and IGMP(2), which have dedicated probes.
var ProtocolSet = []uint8{0, 4, 6, 17, 41, 47, 50, 51, 58, 88, 89, 103, 115, 132, 136, 143}

// ProtocolResult reports the verdict for one IP protocol number.
type ProtocolResult struct {
	Protocol uint8
	State    State
}

// ScanProtocols probes a host with raw IP packets carrying each protocol
// number. A reply of ICMP dest-unreachable/protocol-unreachable means the
// protocol is closed; silence means it is open or filtered.
func (s *Scanner) ScanProtocols(ip net.IP, protocols []uint8, timeout time.Duration) ([]ProtocolResult, error) {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	dstMAC, err := s.resolveMAC(ip, timeout/2)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", ip, err)
	}
	if err := s.handle.SetBPFFilter(fmt.Sprintf("icmp and host %s", ip)); err != nil {
		return nil, fmt.Errorf("set bpf: %w", err)
	}

	var got sync.Map // protocol -> true
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
			icmpL := pkt.Layer(layers.LayerTypeICMPv4)
			ipL := pkt.Layer(layers.LayerTypeIPv4)
			if icmpL == nil || ipL == nil {
				continue
			}
			icmp4 := icmpL.(*layers.ICMPv4)
			ip4 := ipL.(*layers.IPv4)
			if !ip4.SrcIP.Equal(ip) || icmp4.TypeCode.Type() != 3 || icmp4.TypeCode.Code() != 2 {
				continue
			}
			// The ICMP body quotes the original IP header; protocol is at +9.
			if len(icmp4.Payload) < 12 {
				continue
			}
			got.Store(icmp4.Payload[9], true)
		}
	}()

	pace := stealth.NewPacer(s.stealth)
	for _, p := range protocols {
		raw, err := BuildProtocolProbe(s.iface.IP, ip, s.iface.MAC, dstMAC, p)
		if err != nil {
			close(done)
			return nil, err
		}
		if err := s.writeRaw(raw); err != nil {
			close(done)
			return nil, err
		}
		pace.Wait()
	}
	time.Sleep(timeout)
	close(done)

	results := make([]ProtocolResult, 0, len(protocols))
	for _, p := range protocols {
		st := OpenFiltered
		if _, ok := got.Load(p); ok {
			st = Closed
		}
		results = append(results, ProtocolResult{Protocol: p, State: st})
	}
	return results, nil
}

// IdleResult is the verdict from an idle/zombie scan for one port.
type IdleResult struct {
	Port  uint16
	State State
}

// IdleScan runs a classic idle (zombie) port scan through an idle third host.
// The zombie must have an open probe port with a predictable IP-identification
// counter. The scanner observes how the counter reacts to a SYN spoofed from
// the zombie to the target: an open target port makes the zombie emit a RST to
// the target (counter +1); closed or filtered ports leave the counter
// unchanged. The scanner's real address is never revealed to either peer.
func (s *Scanner) IdleScan(ip, zombie net.IP, ports []uint16, timeout time.Duration) ([]IdleResult, error) {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	zbMAC, err := s.resolveMAC(zombie, timeout/3)
	if err != nil {
		return nil, fmt.Errorf("resolve zombie %s: %w", zombie, err)
	}
	tgtMAC, err := s.resolveMAC(ip, timeout/3)
	if err != nil {
		return nil, fmt.Errorf("resolve target %s: %w", ip, err)
	}
	if err := s.handle.SetBPFFilter(fmt.Sprintf(
		"tcp and host %s and tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack)", zombie)); err != nil {
		return nil, fmt.Errorf("set bpf: %w", err)
	}

	zport := s.zombieProbePort
	if zport == 0 {
		zport = 80
	}
	// Confirm the zombie answers SYN on its probe port.
	if _, err := s.zombieProbe(zombie, zbMAC, zport, timeout); err != nil {
		return nil, fmt.Errorf("zombie %s is not answering SYN on port %d: %w", zombie, zport, err)
	}

	var results []IdleResult
	for _, port := range ports {
		id1, err := s.zombieProbe(zombie, zbMAC, zport, timeout)
		if err != nil {
			continue
		}
		// Spoof a SYN from the zombie to the target port.
		seq := uint32(time.Now().UnixNano() & 0xffffffff)
		raw, err := BuildProbe(zombie, ip, s.iface.MAC, tgtMAC, zport, port, seq, 0,
			ProbeFlags{SYN: true}, 64, true, 64240, uint16(time.Now().UnixNano()))
		if err != nil {
			continue
		}
		if err := s.handle.WritePacketData(raw); err != nil {
			continue
		}
		id2, err := s.zombieProbe(zombie, zbMAC, zport, timeout)
		if err != nil {
			continue
		}
		st := Closed
		if id2 == id1+1 || (id1 == 0xffff && id2 == 0) {
			st = Open
		}
		results = append(results, IdleResult{Port: port, State: st})
	}
	sort.Slice(results, func(i, j int) bool { return results[i].Port < results[j].Port })
	return results, nil
}

// SetIdleProbePort sets the TCP port used to read the zombie's IP counter.
func (s *Scanner) SetIdleProbePort(port uint16) { s.zombieProbePort = port }

// zombieProbe sends a SYN to the zombie's probe port and returns the IPv4
// identification value from its SYN-ACK reply.
func (s *Scanner) zombieProbe(zombie net.IP, zbMAC net.HardwareAddr, port uint16, timeout time.Duration) (uint16, error) {
	sport := s.stealth.RandomSrcPort()
	seq := uint32(time.Now().UnixNano() & 0xffffffff)
	raw, err := BuildSYNEx(s.iface.IP, zombie, s.iface.MAC, zbMAC, sport, port, seq, 64, true, 64240, 0)
	if err != nil {
		return 0, err
	}
	if err := s.handle.WritePacketData(raw); err != nil {
		return 0, err
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
		if !ip4.SrcIP.Equal(zombie) || tcp.SrcPort != layers.TCPPort(port) || tcp.DstPort != layers.TCPPort(sport) {
			continue
		}
		if tcp.SYN && tcp.ACK {
			return ip4.Id, nil
		}
	}
	return 0, fmt.Errorf("no SYN-ACK from zombie %s", zombie)
}

// BuildProtocolProbe crafts a raw IPv4 packet carrying the given protocol
// number with an empty payload.
func BuildProtocolProbe(srcIP, dstIP net.IP, srcMAC, dstMAC net.HardwareAddr, proto uint8) ([]byte, error) {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	ip := &layers.IPv4{
		SrcIP:    srcIP.To4(),
		DstIP:    dstIP.To4(),
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocol(proto),
		Flags:    layers.IPv4DontFragment,
	}
	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

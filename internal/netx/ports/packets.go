package ports

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// BuildSYN crafts a raw TCP SYN packet with correct IP and TCP checksums and
// conservative fingerprintable defaults (TTL 64, DF set, window 64240).
func BuildSYN(srcIP, dstIP net.IP, srcMAC, dstMAC net.HardwareAddr, sport, dport uint16, seq uint32) ([]byte, error) {
	// Delegate with the canonical defaults: no ACK, SYN set, TTL 64, DF set,
	// window 64240 (Windows-ish), IP identification 0 (let the NIC assign it).
	return BuildSYNEx(srcIP, dstIP, srcMAC, dstMAC, sport, dport, seq, 64, true, 64240, 0)
}

// BuildSYNEx is BuildSYN with full control over the fingerprintable IP/TCP
// fields so callers can vary TTL, DF, window and IP identification per probe.
func BuildSYNEx(srcIP, dstIP net.IP, srcMAC, dstMAC net.HardwareAddr, sport, dport uint16, seq uint32, ttl uint8, df bool, window, id uint16) ([]byte, error) {
	// A SYN probe carries no ACK number and only the SYN control flag set.
	return BuildProbe(srcIP, dstIP, srcMAC, dstMAC, sport, dport, seq, 0, ProbeFlags{SYN: true}, ttl, df, window, id)
}

// ProbeFlags is the TCP control-flag set for a crafted probe. Each field maps
// to the corresponding bit in the TCP flags octet (byte 13 of the TCP header).
type ProbeFlags struct {
	FIN, SYN, RST, PSH, ACK, URG bool
}

// BuildProbe crafts a raw TCP probe packet with an arbitrary control-flag set
// and full control over the fingerprintable IP/TCP fields. It backs the
// half-open SYN scan and the FIN/NULL/XMAS/ACK scan modes.
func BuildProbe(srcIP, dstIP net.IP, srcMAC, dstMAC net.HardwareAddr, sport, dport uint16, seq, ack uint32, flags ProbeFlags, ttl uint8, df bool, window, id uint16) ([]byte, error) {
	buf := gopacket.NewSerializeBuffer()
	// FixLengths fills in the IP/TCP length fields; ComputeChecksums fills in
	// both the IP header checksum and the TCP pseudo-header checksum.
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	var ipflags layers.IPv4Flag
	if df {
		ipflags = layers.IPv4DontFragment
	}
	ip := &layers.IPv4{
		SrcIP:    srcIP.To4(),
		DstIP:    dstIP.To4(),
		Version:  4,
		TTL:      ttl,
		Id:       id,
		Protocol: layers.IPProtocolTCP,
		Flags:    ipflags,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(sport),
		DstPort: layers.TCPPort(dport),
		Seq:     seq,
		Ack:     ack,
		FIN:     flags.FIN,
		SYN:     flags.SYN,
		RST:     flags.RST,
		PSH:     flags.PSH,
		ACK:     flags.ACK,
		URG:     flags.URG,
		Window:  window,
	}
	// The TCP checksum covers a 12-byte pseudo-header derived from the IP
	// addresses; gopacket needs the network layer to compute it correctly.
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		return nil, err
	}

	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

package ports

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// BuildSYN crafts a raw TCP SYN packet with correct IP and TCP checksums and
// conservative fingerprintable defaults (TTL 64, DF set, window 64240).
func BuildSYN(srcIP, dstIP net.IP, srcMAC, dstMAC net.HardwareAddr, sport, dport uint16, seq uint32) ([]byte, error) {
	return BuildSYNEx(srcIP, dstIP, srcMAC, dstMAC, sport, dport, seq, 64, true, 64240, 0)
}

// BuildSYNEx is BuildSYN with full control over the fingerprintable IP/TCP
// fields so callers can vary TTL, DF, window and IP identification per probe.
func BuildSYNEx(srcIP, dstIP net.IP, srcMAC, dstMAC net.HardwareAddr, sport, dport uint16, seq uint32, ttl uint8, df bool, window, id uint16) ([]byte, error) {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	var flags layers.IPv4Flag
	if df {
		flags = layers.IPv4DontFragment
	}
	ip := &layers.IPv4{
		SrcIP:    srcIP.To4(),
		DstIP:    dstIP.To4(),
		Version:  4,
		TTL:      ttl,
		Id:       id,
		Protocol: layers.IPProtocolTCP,
		Flags:    flags,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(sport),
		DstPort: layers.TCPPort(dport),
		Seq:     seq,
		SYN:     true,
		Window:  window,
	}
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

package ports

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// BuildSYN crafts a raw TCP SYN packet with correct IP and TCP checksums.
func BuildSYN(srcIP, dstIP net.IP, srcMAC, dstMAC net.HardwareAddr, sport, dport uint16, seq uint32) ([]byte, error) {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	ip := &layers.IPv4{
		SrcIP:    srcIP.To4(),
		DstIP:    dstIP.To4(),
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		Flags:    layers.IPv4DontFragment,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(sport),
		DstPort: layers.TCPPort(dport),
		Seq:     seq,
		SYN:     true,
		Window:  64240,
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

package arp

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// BuildRequest crafts a who-has ARP request as raw bytes, padded to the
// 60-byte Ethernet minimum frame size.
func BuildRequest(srcMAC net.HardwareAddr, srcIP net.IP, dstMAC net.HardwareAddr, dstIP net.IP) ([]byte, error) {
	return buildARP(layers.ARPRequest, srcMAC, srcIP, dstMAC, dstIP)
}

// BuildReply crafts an ARP reply (op=2) as raw bytes.
func BuildReply(srcMAC net.HardwareAddr, srcIP net.IP, dstMAC net.HardwareAddr, dstIP net.IP) ([]byte, error) {
	return buildARP(layers.ARPReply, srcMAC, srcIP, dstMAC, dstIP)
}

func buildARP(op uint16, srcMAC net.HardwareAddr, srcIP net.IP, dstMAC net.HardwareAddr, dstIP net.IP) ([]byte, error) {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeARP,
	}
	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         op,
		SourceHwAddress:   srcMAC,
		SourceProtAddress: srcIP.To4(),
		DstHwAddress:      dstMAC,
		DstProtAddress:    dstIP.To4(),
	}
	if err := gopacket.SerializeLayers(buf, opts, eth, arp, gopacket.Payload(padARP())); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// padARP returns 18 zero bytes so the frame meets the 60-byte Ethernet
// minimum.
func padARP() []byte {
	return make([]byte, 18)
}

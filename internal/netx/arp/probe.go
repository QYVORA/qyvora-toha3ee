package arp

import (
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"github.com/QYVORA/qyvora-toha3ee/internal/netx"
)

// Probe sends a who-has request for targetIP to dstMAC (or the broadcast
// address when dstMAC is nil) and returns the MAC address the responder
// claims for targetIP. This is used to verify an active ARP poison: the
// victim's reply will advertise the attacker's MAC for the spoofed IP.
func Probe(iface *netx.Iface, dstMAC net.HardwareAddr, targetIP net.IP, timeout time.Duration) (net.HardwareAddr, error) {
	// A nil dstMAC means we do not know who owns targetIP yet, so ask everyone
	// on the link via the Ethernet broadcast address.
	if dstMAC == nil {
		dstMAC = broadcastMAC
	}
	// Promiscuous mode plus a 65535 snaplen guarantees we capture whole frames;
	// the 100ms read timeout just bounds the wait on a quiet network.
	handle, err := pcap.OpenLive(iface.Name, 65535, true, 100*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", iface.Name, err)
	}
	defer handle.Close()
	// Only ARP frames are relevant; the BPF filter drops the rest and lowers
	// CPU usage on busy links.
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

	// Keep reading replies until the caller's overall timeout elapses.
	deadline := time.Now().Add(timeout)
	ps := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	ps.NoCopy = true
	for time.Now().Before(deadline) {
		pkt, err := ps.NextPacket()
		if err != nil {
			continue // transient read errors (e.g. pcap timeouts) mean "try again"
		}
		arpL := pkt.Layer(layers.LayerTypeARP)
		eth := pkt.Layer(layers.LayerTypeEthernet)
		if arpL == nil || eth == nil {
			continue
		}
		a := arpL.(*layers.ARP)
		// Only an is-at reply (op=2) for the exact queried IP counts. Anything
		// else — requests, replies for other hosts, stale announcements — is
		// ignored so a poison cannot be validated against unrelated traffic.
		if a.Operation == layers.ARPReply && len(a.SourceProtAddress) >= 4 &&
			net.IP(a.SourceProtAddress[:4]).Equal(targetIP) {
			return a.SourceHwAddress, nil
		}
	}
	return nil, fmt.Errorf("no ARP reply for %s", targetIP)
}

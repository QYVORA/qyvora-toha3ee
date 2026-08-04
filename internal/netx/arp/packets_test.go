package arp

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestBuildRequest(t *testing.T) {
	srcMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	dstMAC, _ := net.ParseMAC("11:22:33:44:55:66")
	raw, err := BuildRequest(srcMAC, net.ParseIP("192.168.8.1"), dstMAC, net.ParseIP("192.168.8.100"))
	if err != nil {
		t.Fatalf("BuildRequest: %v", err)
	}
	if len(raw) != 60 {
		t.Fatalf("expected 60-byte frame, got %d", len(raw))
	}

	pkt := gopacket.NewPacket(raw, layers.LayerTypeEthernet, gopacket.Default)
	eth := pkt.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	if eth.EthernetType != layers.EthernetTypeARP {
		t.Fatalf("wrong ethertype %v", eth.EthernetType)
	}
	if !srcEqual(eth.SrcMAC, srcMAC) || !srcEqual(eth.DstMAC, dstMAC) {
		t.Fatalf("wrong ethernet addrs: src=%s dst=%s", eth.SrcMAC, eth.DstMAC)
	}
	a := pkt.Layer(layers.LayerTypeARP).(*layers.ARP)
	if a.Operation != layers.ARPRequest {
		t.Fatalf("expected request, got op %d", a.Operation)
	}
	if !net.IP(a.SourceProtAddress[:4]).Equal(net.ParseIP("192.168.8.1")) {
		t.Fatalf("wrong source IP %v", a.SourceProtAddress)
	}
	if !net.IP(a.DstProtAddress[:4]).Equal(net.ParseIP("192.168.8.100")) {
		t.Fatalf("wrong dst IP %v", a.DstProtAddress)
	}
	if !srcEqual(a.SourceHwAddress, srcMAC) {
		t.Fatalf("wrong source hw %s", a.SourceHwAddress)
	}
}

func TestBuildReply(t *testing.T) {
	attackerMAC, _ := net.ParseMAC("00:11:22:33:44:55")
	victimMAC, _ := net.ParseMAC("66:77:88:99:aa:bb")
	raw, err := BuildReply(attackerMAC, net.ParseIP("192.168.8.1"), victimMAC, net.ParseIP("192.168.8.100"))
	if err != nil {
		t.Fatalf("BuildReply: %v", err)
	}
	pkt := gopacket.NewPacket(raw, layers.LayerTypeEthernet, gopacket.Default)
	a := pkt.Layer(layers.LayerTypeARP).(*layers.ARP)
	if a.Operation != layers.ARPReply {
		t.Fatalf("expected reply op, got %d", a.Operation)
	}
	// The poisoning semantics: attacker MAC is advertised for the spoofed IP.
	if !srcEqual(a.SourceHwAddress, attackerMAC) {
		t.Fatalf("expected attacker MAC advertised, got %s", a.SourceHwAddress)
	}
}

func TestCIDRHosts(t *testing.T) {
	_, ipnet, err := net.ParseCIDR("192.168.8.0/30")
	if err != nil {
		t.Fatal(err)
	}
	hosts := CIDRHosts(ipnet)
	if len(hosts) != 2 { // .1 and .2 (.0 network, .3 broadcast)
		t.Fatalf("expected 2 hosts, got %v", hosts)
	}
	if hosts[0].String() != "192.168.8.1" {
		t.Fatalf("first host = %s", hosts[0])
	}
}

func TestCIDRHostsLarge(t *testing.T) {
	_, ipnet, err := net.ParseCIDR("10.0.0.0/16")
	if err != nil {
		t.Fatal(err)
	}
	if got := len(CIDRHosts(ipnet)); got != 65534 {
		t.Fatalf("expected 65534 hosts, got %d", got)
	}
}

func TestDecodeIP(t *testing.T) {
	if got := DecodeIP([]byte{192, 168, 8, 1}); got.String() != "192.168.8.1" {
		t.Fatalf("DecodeIP = %v", got)
	}
	if DecodeIP([]byte{1, 2}) != nil {
		t.Fatal("expected nil for short input")
	}
}

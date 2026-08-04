package ports

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestBuildSYN(t *testing.T) {
	srcIP := net.ParseIP("192.168.8.116")
	dstIP := net.ParseIP("192.168.8.1")
	srcMAC, _ := net.ParseMAC("aa:aa:aa:aa:aa:aa")
	dstMAC, _ := net.ParseMAC("bb:bb:bb:bb:bb:bb")

	raw, err := BuildSYN(srcIP, dstIP, srcMAC, dstMAC, 443, 443, 12345)
	if err != nil {
		t.Fatalf("BuildSYN: %v", err)
	}
	pkt := gopacket.NewPacket(raw, layers.LayerTypeEthernet, gopacket.Default)
	eth := pkt.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	if eth.EthernetType != layers.EthernetTypeIPv4 {
		t.Fatalf("ethertype = %v", eth.EthernetType)
	}
	ip := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if !ip.SrcIP.Equal(srcIP) || !ip.DstIP.Equal(dstIP) {
		t.Fatalf("ip = %s -> %s", ip.SrcIP, ip.DstIP)
	}
	tcp := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if !tcp.SYN || tcp.ACK {
		t.Fatalf("expected bare SYN: %+v", tcp)
	}
	if tcp.SrcPort != 443 || tcp.DstPort != 443 {
		t.Fatalf("ports = %d->%d", tcp.SrcPort, tcp.DstPort)
	}
	if tcp.Seq != 12345 {
		t.Fatalf("seq = %d", tcp.Seq)
	}
	if ip.Checksum == 0 || tcp.Checksum == 0 {
		t.Fatal("checksums not computed")
	}
}

func TestGuessService(t *testing.T) {
	cases := map[uint16]string{22: "ssh", 80: "http", 445: "microsoft-ds", 3306: "mysql", 9999: "unknown"}
	for port, want := range cases {
		if got := GuessService(port); got != want {
			t.Errorf("GuessService(%d) = %q, want %q", port, got, want)
		}
	}
}

func TestSanitize(t *testing.T) {
	got := sanitize("SSH-2.0-OpenSSH\r\n\x00\x01\xff")
	if len(got) == 0 {
		t.Fatal("empty banner")
	}
	for _, c := range got {
		if c >= 0x7f || c < 0x20 {
			t.Fatalf("unsanitized byte %#x", c)
		}
	}
}

func TestIsTLSPort(t *testing.T) {
	if !isTLS(443) || !isTLS(8443) || isTLS(80) {
		t.Fatal("isTLS wrong")
	}
}

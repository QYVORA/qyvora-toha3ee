package netx

import (
	"net"
	"strings"
	"testing"
)

func TestHexToIP(t *testing.T) {
	ip, err := hexToIP("0101A8C0")
	if err != nil {
		t.Fatalf("hexToIP: %v", err)
	}
	if !ip.Equal(net.ParseIP("192.168.1.1")) {
		t.Errorf("hexToIP(0101A8C0) = %v, want 192.168.1.1", ip)
	}
}

func TestHexToIPRejectsBadInput(t *testing.T) {
	for _, s := range []string{"", "0101A8", "0101A8C01", "zzzzzzzz", "0000000"} {
		if _, err := hexToIP(s); err == nil {
			t.Errorf("hexToIP(%q) should error", s)
		}
	}
}

func TestIPToHexRoundTrip(t *testing.T) {
	ip := net.ParseIP("10.20.30.40")
	if got := IPToHex(ip); got != "281E140A" {
		t.Errorf("IPToHex(10.20.30.40) = %s, want 281E140A", got)
	}
	back, err := hexToIP(IPToHex(ip))
	if err != nil || !back.Equal(ip) {
		t.Errorf("round trip failed: %v, %v", back, err)
	}
}

func TestIPToHexNonIPv4(t *testing.T) {
	if got := IPToHex(net.ParseIP("::1")); got != "00000000" {
		t.Errorf("IPToHex(::1) = %s, want 00000000", got)
	}
}

func TestIfaceStringAndCIDR(t *testing.T) {
	_, ipnet, err := net.ParseCIDR("192.168.8.0/24")
	if err != nil {
		t.Fatal(err)
	}
	i := &Iface{Name: "eth0", IP: net.ParseIP("192.168.8.5"), MAC: net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}, Net: ipnet}
	if s := i.String(); !strings.Contains(s, "eth0") || !strings.Contains(s, "192.168.8.5") {
		t.Errorf("String() = %q", s)
	}
	if c := i.CIDR(); c != "192.168.8.0/24" {
		t.Errorf("CIDR() = %q, want 192.168.8.0/24", c)
	}
	if m := i.NetworkMask(); m == nil || m.String() != "ffffff00" {
		t.Errorf("NetworkMask() = %v", m)
	}
}

func TestIfaceStringWithoutNet(t *testing.T) {
	i := &Iface{Name: "lo"}
	if c := i.CIDR(); c != "" {
		t.Errorf("CIDR() with nil Net = %q, want empty", c)
	}
	if m := i.NetworkMask(); m != nil {
		t.Errorf("NetworkMask() with nil Net = %v, want nil", m)
	}
}

func TestParseRouteFile(t *testing.T) {
	// Little-endian: gateway 192.168.1.1 -> 0101A8C0, dest 10.0.0.0 -> 0000000A.
	body := "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
		"eth0\t00000000\t0101A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n" +
		"eth0\t0000000A\t00000000\t0001\t0\t0\t0\t000000FF\t0\t0\t0\n" +
		"wlan0\t00000000\t0101A8C1\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"
	gw, err := parseRouteFile([]byte(body), "eth0")
	if err != nil {
		t.Fatalf("parseRouteFile: %v", err)
	}
	if !gw.Equal(net.ParseIP("192.168.1.1")) {
		t.Errorf("gateway = %v, want 192.168.1.1", gw)
	}
}

func TestParseRouteFileNoDefaultRoute(t *testing.T) {
	body := "Iface\tDestination\tGateway\tFlags\neth0\t0000000A\t00000000\t0001\n"
	if _, err := parseRouteFile([]byte(body), "eth0"); err == nil {
		t.Error("expected an error when no default route exists")
	}
}

func TestParseRouteFileWrongInterface(t *testing.T) {
	body := "Iface\tDestination\tGateway\tFlags\nwlan0\t00000000\t0101A8C1\t0003\n"
	if _, err := parseRouteFile([]byte(body), "eth0"); err == nil {
		t.Error("expected an error when the interface has no routes")
	}
}

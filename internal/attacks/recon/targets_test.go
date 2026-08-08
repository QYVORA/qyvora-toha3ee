package recon

import (
	"errors"
	"net"
	"testing"
)

func TestParseIPsAndCIDRs(t *testing.T) {
	got, err := parseIPsAndCIDRs("192.168.1.1, 10.0.0.0/30")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var want []string
	for _, ip := range []string{"192.168.1.1", "10.0.0.1", "10.0.0.2"} {
		want = append(want, net.ParseIP(ip).String())
	}
	if len(got) != len(want) {
		t.Fatalf("got %d hosts, want %d (%v)", len(got), len(want), got)
	}
	for i, w := range want {
		if got[i].String() != w {
			t.Errorf("host[%d] = %s, want %s", i, got[i], w)
		}
	}
}

func TestParseIPsAndCIDRsBad(t *testing.T) {
	if _, err := parseIPsAndCIDRs("not-an-ip"); err == nil {
		t.Error("expected error for invalid target")
	}
	if _, err := parseIPsAndCIDRs(""); err == nil {
		t.Error("expected error for empty target list")
	}
}

func TestHostsInNetDropsBroadcast(t *testing.T) {
	_, ipnet, err := net.ParseCIDR("192.168.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	hosts, err := hostsInNet(ipnet)
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 254 {
		t.Fatalf("got %d hosts for /24, want 254", len(hosts))
	}
	if hosts[0].String() != "192.168.0.1" {
		t.Errorf("first host = %s, want 192.168.0.1", hosts[0])
	}
	if hosts[len(hosts)-1].String() != "192.168.0.254" {
		t.Errorf("last host = %s, want 192.168.0.254", hosts[len(hosts)-1])
	}
}

func TestHostsInNetIPv6Rejected(t *testing.T) {
	_, ipnet, err := net.ParseCIDR("fe80::/64")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hostsInNet(ipnet); err == nil {
		t.Error("expected IPv6 rejection")
	}
}

func TestParsePorts(t *testing.T) {
	got := parsePorts([]string{"22", " 80 ", "bad", "99999", "443"})
	if len(got) != 3 {
		t.Fatalf("got %v, want 3 ports", got)
	}
	if got[0] != 22 || got[1] != 80 || got[2] != 443 {
		t.Errorf("unexpected ports %v", got)
	}
	if out := parsePorts(nil); len(out) == 0 {
		t.Error("empty parse should fall back to common ports")
	}
}

func TestIsConnRefused(t *testing.T) {
	if !isConnRefused(&net.OpError{Err: errors.New("connection refused")}) {
		t.Error("expected OpError to be recognized")
	}
	if isConnRefused(nil) {
		t.Error("nil must not be a refusal")
	}
	if !isConnRefused(errors.New("read: connection refused")) {
		t.Error("connection refused string should match")
	}
}

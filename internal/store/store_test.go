package store

import (
	"net"
	"testing"
	"time"
)

func TestUpsertHostNewAndRefresh(t *testing.T) {
	s := New(0)
	ip := net.ParseIP("192.168.8.10")
	h := s.UpsertHost(&Host{IP: ip, MAC: net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}, Vendor: "Intel"})
	if h.Vendor != "Intel" {
		t.Fatalf("vendor = %q", h.Vendor)
	}
	got := s.Host(ip)
	if got == nil {
		t.Fatal("host not stored")
	}
	// Refresh with a name, vendor preserved.
	h2 := s.UpsertHost(&Host{IP: ip, Name: "laptop"})
	if h2.Vendor != "Intel" || h2.Name != "laptop" {
		t.Fatalf("refresh lost data: %+v", h2)
	}
	if len(s.Hosts()) != 1 {
		t.Fatalf("expected 1 host, got %d", len(s.Hosts()))
	}
}

func TestHostPortsConcurrent(t *testing.T) {
	s := New(0)
	h := s.UpsertHost(&Host{IP: net.ParseIP("10.0.0.1")})
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func(port uint16) {
			for j := 0; j < 100; j++ {
				h.SetPort(port, "banner")
			}
			done <- struct{}{}
		}(uint16(i))
	}
	for i := 0; i < 8; i++ {
		<-done
	}
	if len(h.OpenPorts()) != 8 {
		t.Fatalf("expected 8 open ports, got %d", len(h.OpenPorts()))
	}
}

func TestCredDBSourceTracking(t *testing.T) {
	s := New(0)
	c1 := s.AddCred(Cred{Service: "http.post", Username: "admin", Password: "secret", Source: "sniff:192.168.8.10:80"})
	c2 := s.AddCred(Cred{Service: "phish", Username: "bob", Password: "pw", Source: "phish:facebook"})
	creds := s.Creds()
	if len(creds) != 2 {
		t.Fatalf("expected 2 creds, got %d", len(creds))
	}
	if creds[0].ID != c1.ID || c1.ID >= c2.ID {
		t.Fatalf("ids not sequential: %d, %d", c1.ID, c2.ID)
	}
	if creds[1].Source != "phish:facebook" {
		t.Fatalf("source lost: %q", creds[1].Source)
	}
}

func TestSessions(t *testing.T) {
	s := New(0)
	s1 := s.AddSession(Session{VictimIP: "192.168.8.10", Host: "bank.com", Cookies: map[string]string{"sid": "abc"}})
	s.AddSession(Session{VictimIP: "192.168.8.11"})
	sess := s.Sessions()
	if len(sess) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(sess))
	}
	if sess[0].Cookies["sid"] != "abc" || sess[0].ID != s1.ID {
		t.Fatalf("session data wrong: %+v", sess[0])
	}
}

func TestEventLogCapped(t *testing.T) {
	s := New(10)
	for i := 0; i < 25; i++ {
		s.LogEvent("t", "msg")
	}
	ev := s.Events()
	if len(ev) != 10 {
		t.Fatalf("expected capped 10 events, got %d", len(ev))
	}
	if ev[0].Time.After(time.Now()) {
		t.Fatal("future event timestamp")
	}
}

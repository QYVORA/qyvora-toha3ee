package session

import (
	"net"
	"testing"
	"time"

	"github.com/QYVORA/qyvora-toha3ee/internal/store"
)

func TestDeepReconChainOrder(t *testing.T) {
	got := deepReconChain()
	want := []string{"service.synscan", "service.fingerprint"}
	if len(got) != len(want) {
		t.Fatalf("deepReconChain length = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("deepReconChain[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestServiceEnumModuleMapping(t *testing.T) {
	cases := []struct {
		svc  string
		port uint16
		want string
	}{
		{"microsoft-ds", 445, "smb.enum"},
		{"netbios-ssn", 139, "smb.enum"},
		{"ldap", 389, "ldap.enum"},
		{"ldaps", 636, "ldap.enum"},
		{"nfs", 2049, "nfs.enum"},
		{"smtp", 25, "smtp.enum"},
		{"smtp-submission", 587, "smtp.enum"},
		{"http", 80, "web.dir"},
		{"https", 443, "web.dir"},
		{"http-proxy", 8080, "web.dir"},
		{"https-alt", 8443, "web.dir"},
		{"unknown", 161, "snmp.enum"},
		{"unknown", 162, "snmp.enum"},
		{"ssh", 22, ""},
		{"unknown", 9999, ""},
	}
	for _, tc := range cases {
		if got := serviceEnumModule(tc.svc, tc.port); got != tc.want {
			t.Errorf("serviceEnumModule(%q, %d) = %q, want %q", tc.svc, tc.port, got, tc.want)
		}
	}
}

// sessionWithHosts builds a Session whose store holds the given (port, banner)
// pairs on a single host, so the enum selector sees concrete open services.
func sessionWithHosts(ports map[uint16]string) *Session {
	s := New(nil, nil, nil)
	h := &store.Host{IP: net.ParseIP("192.168.8.10")}
	for p, banner := range ports {
		h.SetPort(p, banner)
	}
	s.Store.UpsertHost(h)
	return s
}

func TestSelectEnumModulesPropagatesDiscoveredServices(t *testing.T) {
	s := sessionWithHosts(map[uint16]string{
		445:  "SMB",
		389:  "",
		80:   "nginx",
		2049: "",
		161:  "",
		3128: "squid", // unknown service, must not select an enum module
	})
	got := s.selectEnumModules()
	want := []string{"smb.enum", "ldap.enum", "nfs.enum", "snmp.enum", "web.dir"}
	if len(got) != len(want) {
		t.Fatalf("selectEnumModules = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("selectEnumModules[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestSelectEnumModulesDedupAcrossHosts(t *testing.T) {
	s := New(nil, nil, nil)
	for _, ip := range []string{"192.168.8.10", "192.168.8.11"} {
		h := &store.Host{IP: net.ParseIP(ip)}
		h.SetPort(445, "SMB")
		s.Store.UpsertHost(h)
	}
	got := s.selectEnumModules()
	if len(got) != 1 || got[0] != "smb.enum" {
		t.Fatalf("duplicate service across hosts should dedupe to [smb.enum], got %v", got)
	}
}

func TestSelectEnumModulesEmptyStore(t *testing.T) {
	if got := New(nil, nil, nil).selectEnumModules(); len(got) != 0 {
		t.Fatalf("empty store should select no enum modules, got %v", got)
	}
}

func TestWaitModuleReturnsImmediatelyWhenNotRunning(t *testing.T) {
	if err := waitModule(New(nil, nil, nil), "net.scan", time.Second); err != nil {
		t.Fatalf("waitModule on a not-running module should return nil, got %v", err)
	}
}

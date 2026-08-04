package dns

import (
	"net"
	"testing"
)

func TestRuleMatching(t *testing.T) {
	cases := []struct {
		pattern, name string
		want          bool
	}{
		{"bank.com", "bank.com", true},
		{"bank.com", "www.bank.com", false},
		{"*.bank.com", "bank.com", true},
		{"*.bank.com", "www.bank.com", true},
		{"*.bank.com", "login.bank.com", true},
		{"*.bank.com", "bank.com.evil.net", false},
		{"*.bank.com", "evilbank.com", false},
		{"*.bank.com", "sub.www.bank.com", true},
	}
	for _, c := range cases {
		if got := ruleMatches(c.pattern, c.name); got != c.want {
			t.Errorf("ruleMatches(%q, %q) = %v, want %v", c.pattern, c.name, got, c.want)
		}
	}
}

func TestAddRuleReplacesDuplicate(t *testing.T) {
	s := New("", nil, nil, nil)
	ip1 := net.ParseIP("10.0.0.1")
	ip2 := net.ParseIP("10.0.0.2")
	s.AddRule("bank.com", ip1)
	s.AddRule("bank.com", ip2)
	if got := len(s.Rules()); got != 1 {
		t.Fatalf("expected 1 rule, got %d", got)
	}
	if got, ok := s.match("bank.com"); !ok || !got.Equal(ip2) {
		t.Fatalf("match = %v, %v", got, ok)
	}
}

func TestServerMatchesWildcard(t *testing.T) {
	s := New("", nil, nil, nil)
	s.AddRule("*.bank.com", net.ParseIP("192.168.8.116"))
	if ip, ok := s.match("login.bank.com"); !ok || !ip.Equal(net.ParseIP("192.168.8.116")) {
		t.Fatalf("wildcard match failed: %v %v", ip, ok)
	}
	if _, ok := s.match("google.com"); ok {
		t.Fatal("should not match google.com")
	}
}

func TestSystemResolverFormat(t *testing.T) {
	// The resolver parser must not panic and returns nil when no nameserver.
	if systemResolver() == nil {
		t.Skip("no system nameserver configured; nothing to assert")
	}
}

func TestRuleNormalization(t *testing.T) {
	s := New("", nil, nil, nil)
	s.AddRule("*.Bank.COM", net.ParseIP("10.0.0.1"))
	if _, ok := s.match("www.bank.com"); !ok {
		t.Fatal("pattern should be normalized to lowercase")
	}
}

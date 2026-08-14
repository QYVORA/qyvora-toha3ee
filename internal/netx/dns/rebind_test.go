package dns

import (
	"log/slog"
	"net"
	"testing"

	"github.com/QYVORA/qyvora-toha3ee/internal/events"
	"github.com/QYVORA/qyvora-toha3ee/internal/store"
)

func newTestServer() *Server {
	return New("8.8.8.8:53", events.NewBus(), store.New(100), slog.New(slog.DiscardHandler))
}

func TestRebindAlternates(t *testing.T) {
	s := newTestServer()
	attacker := net.IPv4(10, 0, 0, 66)
	target := net.IPv4(192, 168, 1, 10)
	s.AddRebind("admin.corp.local", attacker, target)

	first, ok := s.rebindMatch("admin.corp.local")
	if !ok || !first.Equal(attacker) {
		t.Fatalf("first answer = %v (ok=%v), want %v", first, ok, attacker)
	}
	second, _ := s.rebindMatch("admin.corp.local")
	if !second.Equal(target) {
		t.Fatalf("second answer = %v, want %v", second, target)
	}
	third, _ := s.rebindMatch("admin.corp.local")
	if !third.Equal(attacker) {
		t.Fatalf("third answer = %v, want %v (alternation restored)", third, attacker)
	}
}

func TestRebindTarget(t *testing.T) {
	s := newTestServer()
	s.AddRebind("*.int", net.IPv4(10, 0, 0, 66), net.IPv4(10, 1, 1, 20))
	if got := s.rebindTarget("db.int"); !got.Equal(net.IPv4(10, 1, 1, 20)) {
		t.Fatalf("rebindTarget(db.int) = %v", got)
	}
	if got := s.rebindTarget("nonexistent.tld"); got != nil {
		t.Fatalf("rebindTarget(nonexistent) = %v, want nil", got)
	}
}

func TestRuleReplacesDuplicate(t *testing.T) {
	s := newTestServer()
	s.AddRule("bank.com", net.IPv4(1, 1, 1, 1))
	s.AddRule("bank.com", net.IPv4(2, 2, 2, 2))
	if len(s.rules) != 1 {
		t.Fatalf("rules = %d, want 1", len(s.rules))
	}
	if got, _ := s.rebindMatch("bank.com"); got != nil {
		t.Fatalf("bank.com should not be a rebind rule")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.rules[0].Target.Equal(net.IPv4(2, 2, 2, 2)) {
		t.Errorf("duplicate AddRule did not replace target")
	}
}

func TestRuleMatches(t *testing.T) {
	cases := []struct {
		pattern, name string
		want          bool
	}{
		{"bank.com", "bank.com", true},
		{"bank.com", "www.bank.com", false},
		{"*.bank.com", "www.bank.com", true},
		{"*.bank.com", "bank.com", true},
		{"*.bank.com", "evil.org", false},
		{"bank.com", "bank.com.evil.org", false},
	}
	for _, c := range cases {
		if got := ruleMatches(c.pattern, c.name); got != c.want {
			t.Errorf("ruleMatches(%q, %q) = %v, want %v", c.pattern, c.name, got, c.want)
		}
	}
}

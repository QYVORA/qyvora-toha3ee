package enum

import (
	"testing"
)

func TestSplitUsers(t *testing.T) {
	got := splitUsers("root, admin\nbob", "fallback")
	if len(got) != 3 {
		t.Fatalf("got %v", got)
	}
	if got[0] != "root" || got[1] != "admin" || got[2] != "bob" {
		t.Errorf("unexpected %v", got)
	}
	if out := splitUsers("", "a, b"); len(out) != 2 {
		t.Errorf("config fallback failed: %v", out)
	}
}

func TestHasPort(t *testing.T) {
	h := &HostRef{Ports: []uint16{22, 445}}
	if !hasPort(h, 445) {
		t.Error("expected 445 present")
	}
	if hasPort(h, 80) {
		t.Error("expected 80 absent")
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("short", 10); got != "short" {
		t.Errorf("got %q", got)
	}
	got := truncate("0123456789ABCDEF", 8)
	if got != "01234567..." {
		t.Errorf("got %q", got)
	}
}

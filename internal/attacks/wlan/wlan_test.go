package wlan

import (
	"testing"

	"github.com/qyvora/toha3ee/internal/attacks"
)

func TestModuleRegistration(t *testing.T) {
	expected := []string{"wlan.scan", "wlan.deauth", "wlan.handshake", "wlan.eviltwin"}
	for _, id := range expected {
		m, ok := attacks.Get(id)
		if !ok {
			t.Errorf("module %q not registered", id)
			continue
		}
		meta := m.Meta()
		if meta.ID != id {
			t.Errorf("module ID mismatch: got %q, want %q", meta.ID, id)
		}
		if meta.Category != "wireless" {
			t.Errorf("module %q category = %q, want %q", id, meta.Category, "wireless")
		}
		if meta.Description == "" {
			t.Errorf("module %q has empty description", id)
		}
		if len(meta.Targets) == 0 {
			t.Errorf("module %q has no targets", id)
		}
		if len(meta.Requires) == 0 {
			t.Errorf("module %q has no requires", id)
		}
	}
}

func TestWLANScanMeta(t *testing.T) {
	m, ok := attacks.Get("wlan.scan")
	if !ok {
		t.Fatal("wlan.scan not registered")
	}
	meta := m.Meta()
	if meta.Risk != attacks.RiskLow {
		t.Errorf("risk = %v, want low", meta.Risk)
	}
	if !meta.Passive {
		t.Error("wlan.scan should be passive")
	}
}

func TestWLANDeauthMeta(t *testing.T) {
	m, ok := attacks.Get("wlan.deauth")
	if !ok {
		t.Fatal("wlan.deauth not registered")
	}
	meta := m.Meta()
	if meta.Risk != attacks.RiskHigh {
		t.Errorf("risk = %v, want high", meta.Risk)
	}
	if meta.Passive {
		t.Error("wlan.deauth should not be passive")
	}
}

func TestWLANHandshakeMeta(t *testing.T) {
	m, ok := attacks.Get("wlan.handshake")
	if !ok {
		t.Fatal("wlan.handshake not registered")
	}
	meta := m.Meta()
	if meta.Risk != attacks.RiskHigh {
		t.Errorf("risk = %v, want high", meta.Risk)
	}
}

func TestWLANEvilTwinMeta(t *testing.T) {
	m, ok := attacks.Get("wlan.eviltwin")
	if !ok {
		t.Fatal("wlan.eviltwin not registered")
	}
	meta := m.Meta()
	if meta.Risk != attacks.RiskCritical {
		t.Errorf("risk = %v, want critical", meta.Risk)
	}
}

func TestWLANModuleLifecycle(t *testing.T) {
	for _, id := range []string{"wlan.scan", "wlan.deauth", "wlan.handshake", "wlan.eviltwin"} {
		m, ok := attacks.Get(id)
		if !ok {
			t.Errorf("module %q not registered", id)
			continue
		}
		if m.Meta().ID == "" {
			t.Errorf("module %q has empty ID", id)
		}
	}
}

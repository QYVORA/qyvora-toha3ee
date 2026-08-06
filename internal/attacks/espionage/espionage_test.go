package espionage

import (
	"testing"

	"github.com/qyvora/toha3ee/internal/attacks"
)

func TestModuleRegistration(t *testing.T) {
	expected := []string{"http.harvest", "http.proxy", "https.proxy", "phish.inject"}
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
		if meta.Category != "espionage" {
			t.Errorf("module %q category = %q, want %q", id, meta.Category, "espionage")
		}
		if meta.Description == "" {
			t.Errorf("module %q has empty description", id)
		}
	}
}

func TestHTTPHarvestMeta(t *testing.T) {
	m, ok := attacks.Get("http.harvest")
	if !ok {
		t.Fatal("http.harvest not registered")
	}
	meta := m.Meta()
	if meta.Risk != attacks.RiskMedium {
		t.Errorf("risk = %v, want medium", meta.Risk)
	}
	if len(meta.Requires) == 0 {
		t.Error("http.harvest should require cap.sniff")
	}
}

func TestHTTPProxyMeta(t *testing.T) {
	m, ok := attacks.Get("http.proxy")
	if !ok {
		t.Fatal("http.proxy not registered")
	}
	meta := m.Meta()
	if meta.Risk != attacks.RiskHigh {
		t.Errorf("risk = %v, want high", meta.Risk)
	}
}

func TestHTTPSProxyMeta(t *testing.T) {
	m, ok := attacks.Get("https.proxy")
	if !ok {
		t.Fatal("https.proxy not registered")
	}
	meta := m.Meta()
	if meta.Risk != attacks.RiskHigh {
		t.Errorf("risk = %v, want high", meta.Risk)
	}
}

func TestPhishInjectMeta(t *testing.T) {
	m, ok := attacks.Get("phish.inject")
	if !ok {
		t.Fatal("phish.inject not registered")
	}
	meta := m.Meta()
	if meta.Risk != attacks.RiskHigh {
		t.Errorf("risk = %v, want high", meta.Risk)
	}
}

func TestTemplateIDs(t *testing.T) {
	ids := templateIDs()
	if len(ids) == 0 {
		t.Fatal("no templates found")
	}
}

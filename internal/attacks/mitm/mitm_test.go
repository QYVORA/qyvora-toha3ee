package mitm

import (
	"testing"

	"github.com/QYVORA/qyvora-toha3ee/internal/attacks"
)

func TestModuleRegistration(t *testing.T) {
	expected := []string{"arp.spoof", "dns.spoof", "dhcp6.spoof", "llmnr.poison", "wpad.poison", "icmp.redirect"}
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
		if meta.Category != "mitm" {
			t.Errorf("module %q category = %q, want %q", id, meta.Category, "mitm")
		}
		if meta.Description == "" {
			t.Errorf("module %q has empty description", id)
		}
	}
}

func TestARPSpoofMeta(t *testing.T) {
	m, ok := attacks.Get("arp.spoof")
	if !ok {
		t.Fatal("arp.spoof not registered")
	}
	meta := m.Meta()
	if meta.Risk != attacks.RiskMedium {
		t.Errorf("risk = %v, want medium", meta.Risk)
	}
}

func TestDNSSpoofMeta(t *testing.T) {
	m, ok := attacks.Get("dns.spoof")
	if !ok {
		t.Fatal("dns.spoof not registered")
	}
	meta := m.Meta()
	if meta.Risk != attacks.RiskMedium {
		t.Errorf("risk = %v, want medium", meta.Risk)
	}
}

func TestDHCP6SpoofMeta(t *testing.T) {
	m, ok := attacks.Get("dhcp6.spoof")
	if !ok {
		t.Fatal("dhcp6.spoof not registered")
	}
	meta := m.Meta()
	if meta.Risk != attacks.RiskMedium {
		t.Errorf("risk = %v, want medium", meta.Risk)
	}
}

func TestLLMNRSpoofMeta(t *testing.T) {
	m, ok := attacks.Get("llmnr.poison")
	if !ok {
		t.Fatal("llmnr.poison not registered")
	}
	meta := m.Meta()
	if meta.Risk != attacks.RiskMedium {
		t.Errorf("risk = %v, want medium", meta.Risk)
	}
}

func TestWPADSpoofMeta(t *testing.T) {
	m, ok := attacks.Get("wpad.poison")
	if !ok {
		t.Fatal("wpad.poison not registered")
	}
	meta := m.Meta()
	if meta.Risk != attacks.RiskMedium {
		t.Errorf("risk = %v, want medium", meta.Risk)
	}
}

func TestICMPRedirectMeta(t *testing.T) {
	m, ok := attacks.Get("icmp.redirect")
	if !ok {
		t.Fatal("icmp.redirect not registered")
	}
	meta := m.Meta()
	if meta.Risk != attacks.RiskMedium {
		t.Errorf("risk = %v, want medium", meta.Risk)
	}
}

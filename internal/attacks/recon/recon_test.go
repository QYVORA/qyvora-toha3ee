package recon

import (
	"testing"

	"github.com/QYVORA/qyvora-toha3ee/internal/attacks"
)

func TestModuleRegistration(t *testing.T) {
	expected := []string{
		"net.scan", "service.synscan", "service.fingerprint", "web.dir", "service.tls",
		"net.ping", "net.traceroute", "net.osdetect", "service.tcpconnect",
		"service.udpscan", "service.finxmas", "service.ack",
		"service.protoscan", "service.idle",
	}
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
		if meta.Category != "recon" {
			t.Errorf("module %q category = %q, want %q", id, meta.Category, "recon")
		}
		if meta.Description == "" {
			t.Errorf("module %q has empty description", id)
		}
	}
}

func TestNetScanMeta(t *testing.T) {
	m, ok := attacks.Get("net.scan")
	if !ok {
		t.Fatal("net.scan not registered")
	}
	meta := m.Meta()
	if meta.Risk != attacks.RiskLow {
		t.Errorf("risk = %v, want low", meta.Risk)
	}
}

func TestServiceScanMeta(t *testing.T) {
	m, ok := attacks.Get("service.synscan")
	if !ok {
		t.Fatal("service.synscan not registered")
	}
	meta := m.Meta()
	if meta.Risk != attacks.RiskLow {
		t.Errorf("risk = %v, want low", meta.Risk)
	}
}

func TestServiceFingerprintMeta(t *testing.T) {
	m, ok := attacks.Get("service.fingerprint")
	if !ok {
		t.Fatal("service.fingerprint not registered")
	}
	meta := m.Meta()
	if meta.Risk != attacks.RiskLow {
		t.Errorf("risk = %v, want low", meta.Risk)
	}
}

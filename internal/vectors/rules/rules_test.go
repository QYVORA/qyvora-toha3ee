package rules

import (
	"testing"

	v "github.com/QYVORA/qyvora-toha3ee/internal/vectors"
)

func TestARPRulesRequireGatewayAndPoisonable(t *testing.T) {
	// No gateway -> no vectors.
	p := &v.Profile{Gateway: nil, Poisonable: true}
	vecs := arpRules(p)
	if len(vecs) != 0 {
		t.Fatalf("expected 0 vectors without gateway, got %d", len(vecs))
	}

	// Gateway but not poisonable -> no vectors.
	gw := &v.Host{IP: []byte{192, 168, 1, 1}}
	p = &v.Profile{Gateway: gw, Poisonable: false}
	vecs = arpRules(p)
	if len(vecs) != 0 {
		t.Fatalf("expected 0 vectors when not poisonable, got %d", len(vecs))
	}

	// Gateway + poisonable -> at least arp.spoof.
	p = &v.Profile{Gateway: gw, Poisonable: true}
	vecs = arpRules(p)
	found := false
	for _, v := range vecs {
		if v.ModuleID == "arp.spoof" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("arp.spoof not suggested when gateway + poisonable")
	}
}

func TestARPSpoofInternalNeedsTwoClients(t *testing.T) {
	gw := &v.Host{IP: []byte{192, 168, 1, 1}}
	client := &v.Host{IP: []byte{192, 168, 1, 10}, MAC: []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x0a}}

	// Only one client -> no internal.
	p := &v.Profile{Gateway: gw, Poisonable: true, Hosts: []*v.Host{client}}
	vecs := arpRules(p)
	for _, v := range vecs {
		if v.ModuleID == "arp.spoof.internal" {
			t.Fatal("arp.spoof.internal suggested with only 1 client")
		}
	}

	// Two clients -> internal suggested.
	client2 := &v.Host{IP: []byte{192, 168, 1, 20}, MAC: []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x14}}
	p.Hosts = []*v.Host{client, client2}
	vecs = arpRules(p)
	found := false
	for _, v := range vecs {
		if v.ModuleID == "arp.spoof.internal" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("arp.spoof.internal not suggested with 2 clients")
	}
}

func TestHTTPHarvestNeedsPlainHTTP(t *testing.T) {
	gw := &v.Host{IP: []byte{192, 168, 1, 1}}
	p := &v.Profile{Gateway: gw, Poisonable: true, SeesPlainHTTP: false}
	vecs := arpRules(p)
	for _, v := range vecs {
		if v.ModuleID == "http.harvest" {
			t.Fatal("http.harvest suggested without SeesPlainHTTP")
		}
	}

	p.SeesPlainHTTP = true
	vecs = arpRules(p)
	found := false
	for _, v := range vecs {
		if v.ModuleID == "http.harvest" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("http.harvest not suggested with SeesPlainHTTP")
	}
}

func TestServiceRulesSuggestScanWhenNoHosts(t *testing.T) {
	p := &v.Profile{}
	vecs := serviceRules(p)
	if len(vecs) != 1 || vecs[0].ModuleID != "service.synscan" {
		t.Fatalf("expected service.synscan for empty profile, got %v", vecs)
	}
}

func TestHasWebPort(t *testing.T) {
	if !hasWeb(map[uint16]string{80: "http"}) {
		t.Fatal("port 80 should be web")
	}
	if !hasWeb(map[uint16]string{443: "https"}) {
		t.Fatal("port 443 should be web")
	}
	if hasWeb(map[uint16]string{22: "ssh"}) {
		t.Fatal("port 22 should not be web")
	}
}

func TestHasSMBPort(t *testing.T) {
	if !hasSMB(map[uint16]string{445: "smb"}) {
		t.Fatal("port 445 should be SMB")
	}
	if hasSMB(map[uint16]string{80: "http"}) {
		t.Fatal("port 80 should not be SMB")
	}
}

func TestLikelyRouter(t *testing.T) {
	for _, vendor := range []string{"TP-Link", "Netgear", "D-Link", "Cisco", "MikroTik"} {
		h := &v.Host{Vendor: vendor}
		if !likelyRouter(h) {
			t.Errorf("vendor %q should be recognized as router", vendor)
		}
	}
	h := &v.Host{Vendor: "Intel Corp."}
	if likelyRouter(h) {
		t.Error("Intel Corp. should not be recognized as router")
	}
}

func TestWlanRulesNeedMonitorCapable(t *testing.T) {
	p := &v.Profile{MonitorCapable: false}
	vecs := wlanRules(p)
	if len(vecs) != 0 {
		t.Fatal("wlan rules should return empty without monitor capability")
	}

	p.MonitorCapable = true
	p.HasAP = false
	vecs = wlanRules(p)
	found := false
	for _, v := range vecs {
		if v.ModuleID == "wlan.scan" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("wlan.scan not suggested with monitor capable but no AP")
	}
}

func TestContainsFold(t *testing.T) {
	if !containsFold("TP-LINK Archer", "tp-link") {
		t.Fatal("containsFold should match case-insensitively")
	}
	if containsFold("Intel Corp.", "tp-link") {
		t.Fatal("containsFold should not match unrelated strings")
	}
}

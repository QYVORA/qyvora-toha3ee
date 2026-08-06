package vectors_test

import (
	"net"
	"testing"

	"github.com/qyvora/toha3ee/internal/vectors"
	_ "github.com/qyvora/toha3ee/internal/vectors/rules" // register rules
)

func testProfile() *vectors.Profile {
	gw := &vectors.Host{IP: net.ParseIP("192.168.8.1"), MAC: mustMAC("aa:bb:cc:00:00:01")}
	return &vectors.Profile{
		Gateway: gw,
		Hosts: []*vectors.Host{
			gw,
			{IP: net.ParseIP("192.168.8.107"), MAC: mustMAC("aa:bb:cc:00:00:02"), Vendor: "Apple", Ports: map[uint16]string{80: "http", 443: "https"}},
			{IP: net.ParseIP("192.168.8.108"), MAC: mustMAC("aa:bb:cc:00:00:03"), Vendor: "Intel"},
		},
		Poisonable:    true,
		SeesPlainHTTP: true,
		SeesLLMNR:     true,
		SeesSMB:       true,
		SeesDoH:       false,
	}
}

func mustMAC(s string) net.HardwareAddr {
	m, _ := net.ParseMAC(s)
	return m
}

func metaResolver(id string) (vectors.MetaInfo, bool) {
	meta := map[string]vectors.MetaInfo{
		"arp.spoof":           {Category: "mitm", Risk: "medium", Requires: []string{"cap.ip_forward", "cap.raw_socket"}},
		"arp.spoof.internal":  {Category: "mitm", Risk: "medium", Requires: []string{"cap.raw_socket"}},
		"http.harvest":        {Category: "http", Risk: "low", Requires: nil, Passive: true},
		"dns.spoof":           {Category: "mitm", Risk: "medium", Requires: []string{"cap.ip_forward", "cap.raw_socket"}},
		"http.proxy":          {Category: "http", Risk: "high", Requires: []string{"cap.ip_forward", "cap.raw_socket"}},
		"https.proxy":         {Category: "http", Risk: "high", Requires: []string{"cap.ip_forward", "cap.raw_socket"}},
		"phish.inject":        {Category: "http", Risk: "high", Requires: []string{"cap.ip_forward"}},
		"llmnr.poison":        {Category: "auth", Risk: "medium", Requires: []string{"cap.raw_socket"}},
		"ntlm.relay":          {Category: "auth", Risk: "critical", Requires: []string{"cap.raw_socket"}},
		"smb.signing":         {Category: "auth", Risk: "info", Requires: nil, Passive: true},
		"wlan.scan":           {Category: "wireless", Risk: "low", Requires: []string{"cap.monitor_iface"}},
		"wlan.handshake":      {Category: "wireless", Risk: "high", Requires: []string{"cap.monitor_iface"}},
		"wlan.deauth":         {Category: "wireless", Risk: "high", Requires: []string{"cap.monitor_iface"}},
		"wlan.eviltwin":       {Category: "wireless", Risk: "critical", Requires: []string{"cap.monitor_iface"}},
		"dhcp6.spoof":         {Category: "mitm", Risk: "high", Requires: []string{"cap.ip_forward", "cap.raw_socket"}},
		"icmp.redirect":       {Category: "mitm", Risk: "medium", Requires: []string{"cap.raw_socket"}},
		"wpad.poison":         {Category: "mitm", Risk: "medium", Requires: []string{"cap.raw_socket"}},
		"service.synscan":     {Category: "service", Risk: "low", Requires: []string{"cap.raw_socket"}},
		"service.fingerprint": {Category: "service", Risk: "low", Requires: nil},
		"default.creds":       {Category: "service", Risk: "medium", Requires: nil},
	}
	m, ok := meta[id]
	return m, ok
}

func TestAnalyzeRanksByConfidence(t *testing.T) {
	eng := vectors.NewEngine(metaResolver)
	vecs := eng.Analyze(testProfile())
	if len(vecs) == 0 {
		t.Fatal("no vectors produced")
	}
	for i := 1; i < len(vecs); i++ {
		if vecs[i-1].Confidence < vecs[i].Confidence {
			t.Fatalf("not sorted: %v before %v", vecs[i-1], vecs[i])
		}
	}
	// Top should be arp.spoof (0.97).
	if vecs[0].ModuleID != "arp.spoof" {
		t.Fatalf("top vector = %s (%v)", vecs[0].ModuleID, vecs[0].Confidence)
	}
}

func TestMetaAttached(t *testing.T) {
	eng := vectors.NewEngine(metaResolver)
	vecs := eng.Analyze(testProfile())
	found := false
	for _, v := range vecs {
		if v.ModuleID == "arp.spoof" {
			found = true
			if v.Risk != "medium" {
				t.Fatalf("risk = %q", v.Risk)
			}
			if len(v.Requires) != 2 {
				t.Fatalf("requires = %v", v.Requires)
			}
		}
	}
	if !found {
		t.Fatal("arp.spoof vector missing")
	}
}

func TestDedupByModuleTarget(t *testing.T) {
	eng := vectors.NewEngine(metaResolver)
	vecs := eng.Analyze(testProfile())
	count := 0
	for _, v := range vecs {
		if v.ModuleID == "dns.spoof" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 dns.spoof vector, got %d", count)
	}
}

func TestSatisfiable(t *testing.T) {
	eng := vectors.NewEngine(metaResolver)
	p := testProfile()
	p.MonitorCapable = true

	ok := eng.Satisfiable(p, vectors.Vector{ModuleID: "arp.spoof", Requires: []string{"cap.ip_forward", "cap.raw_socket"}})
	if !ok {
		t.Fatal("ip_forward+raw_socket should be satisfiable")
	}
	ok = eng.Satisfiable(p, vectors.Vector{ModuleID: "wlan.handshake", Requires: []string{"cap.monitor_iface"}})
	if !ok {
		t.Fatal("wlan.handshake should be satisfiable with monitor capable")
	}
	p.MonitorCapable = false
	ok = eng.Satisfiable(p, vectors.Vector{ModuleID: "wlan.handshake", Requires: []string{"cap.monitor_iface"}})
	if ok {
		t.Fatal("wlan.handshake should not be satisfiable without monitor iface")
	}
	ok = eng.Satisfiable(p, vectors.Vector{Requires: []string{"cap.ca_trust"}})
	if ok {
		t.Fatal("cap.ca_trust should never be auto-satisfiable")
	}
}

func TestNoGatewayNoArpVectors(t *testing.T) {
	p := &vectors.Profile{Poisonable: true}
	eng := vectors.NewEngine(metaResolver)
	for _, v := range eng.Analyze(p) {
		if v.ModuleID == "arp.spoof" {
			t.Fatal("arp.spoof suggested without gateway")
		}
	}
}

func TestWirelessVectorsNeedMonitor(t *testing.T) {
	p := testProfile()
	p.MonitorCapable = true
	p.HasAP = true
	p.HasClients = true
	eng := vectors.NewEngine(metaResolver)
	vecs := eng.Analyze(p)
	ids := map[string]bool{}
	for _, v := range vecs {
		ids[v.ModuleID] = true
	}
	if !ids["wlan.deauth"] || !ids["wlan.handshake"] || !ids["wlan.eviltwin"] {
		t.Fatalf("wireless vectors missing: %v", ids)
	}
}

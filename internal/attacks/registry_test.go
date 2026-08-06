package attacks_test

import (
	"testing"

	"github.com/qyvora/toha3ee/internal/attacks"

	_ "github.com/qyvora/toha3ee/internal/attacks/auth"
	_ "github.com/qyvora/toha3ee/internal/attacks/espionage"
	_ "github.com/qyvora/toha3ee/internal/attacks/mitm"
	_ "github.com/qyvora/toha3ee/internal/attacks/post"
	_ "github.com/qyvora/toha3ee/internal/attacks/recon"
	_ "github.com/qyvora/toha3ee/internal/attacks/switch"
	_ "github.com/qyvora/toha3ee/internal/attacks/wlan"
	_ "github.com/qyvora/toha3ee/internal/vectors/rules"
)

// TestRegistryCompleteness pins the full module catalogue the framework must
// ship. Any missing or renamed module fails the build surface.
func TestRegistryCompleteness(t *testing.T) {
	want := []string{
		// mitm
		"arp.spoof", "dns.spoof", "dns.rebind", "dhcp6.spoof", "dhcp.starve",
		"dhcp.rogue", "icmp.redirect", "ipv6.ra", "ipv6.ndp", "llmnr.poison",
		"wpad.poison",
		// espionage
		"http.harvest", "http.proxy", "https.proxy", "ssl.strip", "phish.inject",
		// auth
		"default.creds", "ntlm.relay", "smb.signing", "smb.kerberoast",
		// recon
		"net.scan", "service.synscan", "service.fingerprint", "cve.suggest",
		// post
		"report.generate", "session.replay", "pcap.export",
		// switch
		"switch.flood", "switch.portsteal", "switch.vlanhop", "switch.cdp",
		"switch.stp",
		// wireless
		"wlan.scan", "wlan.deauth", "wlan.handshake", "wlan.eviltwin",
		"wlan.pmkid", "wlan.beaconflood", "wlan.karma",
	}
	got := attacks.ListIDs()
	have := map[string]bool{}
	for _, id := range got {
		have[id] = true
	}
	for _, id := range want {
		if !have[id] {
			t.Errorf("expected module %q to be registered (have %v)", id, got)
		}
	}
}

// TestModuleContract ensures every registered module satisfies the lifecycle
// and produces sane metadata.
func TestModuleContract(t *testing.T) {
	for _, m := range attacks.List() {
		meta := m.Meta()
		if meta.ID == "" {
			t.Errorf("module registered with empty ID")
			continue
		}
		if meta.Description == "" {
			t.Errorf("module %s has no description", meta.ID)
		}
		if meta.Risk < attacks.RiskInfo || meta.Risk > attacks.RiskCritical {
			t.Errorf("module %s has invalid risk %v", meta.ID, meta.Risk)
		}
		// Every category is non-empty and the ID is dotted.
		if meta.Category == "" {
			t.Errorf("module %s has no category", meta.ID)
		}
		dot := false
		for _, r := range meta.ID {
			if r == '.' {
				dot = true
				break
			}
		}
		if !dot {
			t.Errorf("module %s ID is not dotted", meta.ID)
		}
	}
}

// TestNoDuplicateCategories guards against accidental category typos that
// would fragment the UI grouping.
func TestNoDuplicateCategories(t *testing.T) {
	cats := attacks.Categories()
	seen := map[string]bool{}
	for _, c := range cats {
		if seen[c] {
			t.Errorf("duplicate category %q", c)
		}
		seen[c] = true
	}
	// A category must hold at least one module.
	for _, m := range attacks.List() {
		if m.Meta().Category == "" {
			t.Errorf("module %s has empty category", m.Meta().ID)
		}
	}
}

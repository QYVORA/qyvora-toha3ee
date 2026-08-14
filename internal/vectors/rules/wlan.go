package rules

import (
	v "github.com/QYVORA/qyvora-toha3ee/internal/vectors"
)

// wlanRules suggests wireless attacks when a monitor-capable interface is
// present.
func wlanRules(p *v.Profile) []v.Vector {
	var out []v.Vector
	// Every wireless attack needs monitor mode; without a capable interface
	// the whole family is unsuggestable.
	if !p.MonitorCapable {
		return out
	}

	if !p.HasAP {
		// First step: find access points with a passive scan. No AP is known
		// yet, so nothing attack-shaped can be suggested; return the scan
		// immediately rather than piling on later-stage vectors.
		out = append(out, v.Vector{
			ModuleID:   "wlan.scan",
			Target:     "monitor",
			Confidence: 0.95,
			Risk:       "low",
			Impact:     "passive scan of 802.11 beacons to enumerate APs and clients",
		})
		return out
	}

	out = append(out, v.Vector{
		ModuleID:   "wlan.handshake",
		Target:     "ap",
		Confidence: 0.66,
		Risk:       "high",
		Impact:     "capture WPA/WPA2 handshakes for offline cracking",
	})

	out = append(out, v.Vector{
		ModuleID:   "wlan.eviltwin",
		Target:     "ap",
		Confidence: 0.60,
		Risk:       "critical",
		Impact:     "rogue AP impersonating a trusted SSID with a captive-phishing portal",
	})

	// Deauthentication needs real clients on the AP to kick off; with none
	// observed there is nothing to disconnect.
	if p.HasClients {
		out = append(out, v.Vector{
			ModuleID:   "wlan.deauth",
			Target:     "client",
			Confidence: 0.75,
			Risk:       "high",
			Impact:     "deauthentication flood forcing clients off the AP",
		})
	}
	return out
}

// init registers the rule family with the engine during package init.
func init() {
	v.RegisterRule(wlanRules)
}

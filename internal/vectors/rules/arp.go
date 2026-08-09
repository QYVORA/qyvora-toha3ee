// Package rules holds the vector rule families. Every rule is a plain
// function from *vectors.Profile to []vectors.Vector and self-registers with
// vectors.RegisterRule during init(), so the engine stays dependency-free.
package rules

import (
	v "github.com/qyvora/toha3ee/internal/vectors"
)

// arpRules suggests L2 MITM and passive harvesting attacks.
func arpRules(p *v.Profile) []v.Vector {
	var out []v.Vector
	// ARP attacks all depend on a known gateway to impersonate; without one
	// there is nothing to spoof toward.
	if p.Gateway == nil {
		return out
	}
	// If recon proved the segment rejects forged ARP responses, MITM via ARP
	// cannot work; skip the whole family.
	if !p.Poisonable {
		return out
	}

	// Classic full-duplex ARP MITM against a single victim host.
	out = append(out, v.Vector{
		ModuleID:   "arp.spoof",
		Target:     p.Gateway.IP.String(),
		Confidence: 0.97,
		Risk:       "medium",
		Impact:     "full-duplex MITM: intercept and relay traffic between the gateway and a victim host",
	})

	// Internal host-to-host spoofing when at least two client hosts exist.
	// The two-host floor matters: with a single client there is no second
	// party whose traffic could be redirected.
	clientCount := 0
	for _, h := range p.Hosts {
		// Count only hosts with a MAC: an ARP-spoofable target must be
		// reachable at L2, and gateway is excluded as the impersonation target.
		if h.IP != nil && !h.IP.Equal(p.Gateway.IP) && h.MAC != nil {
			clientCount++
		}
	}
	if clientCount >= 2 {
		out = append(out, v.Vector{
			ModuleID:   "arp.spoof.internal",
			Target:     "host-to-host",
			Confidence: 0.85,
			Risk:       "medium",
			Impact:     "ARP MITM between two internal hosts without touching the gateway",
		})
	}

	// Plaintext HTTP on the segment makes passive credential harvesting
	// possible without any injection at all.
	if p.SeesPlainHTTP {
		out = append(out, v.Vector{
			ModuleID:   "http.harvest",
			Target:     p.Gateway.IP.String(),
			Confidence: 0.92,
			Risk:       "low",
			Impact:     "passively harvest HTTP credentials and sessions observed on the wire",
		})
	}
	return out
}

// init registers the rule family with the engine during package init.
func init() {
	v.RegisterRule(arpRules)
}

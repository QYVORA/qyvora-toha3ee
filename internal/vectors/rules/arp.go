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
	if p.Gateway == nil {
		return out
	}
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
	clientCount := 0
	for _, h := range p.Hosts {
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

func init() {
	v.RegisterRule(arpRules)
}

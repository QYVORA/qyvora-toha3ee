package rules

import (
	v "github.com/qyvora/toha3ee/internal/vectors"
)

// dhcpRules suggests DHCP/DHCPv6/NDP and ICMP-redirect based attacks.
func dhcpRules(p *v.Profile) []v.Vector {
	var out []v.Vector
	if p.Gateway == nil || !p.Poisonable {
		return out
	}

	out = append(out, v.Vector{
		ModuleID:   "dhcp6.spoof",
		Target:     p.Gateway.IP.String(),
		Confidence: 0.60,
		Risk:       "high",
		Impact:     "advertise a rogue DHCPv6 server (mitm6-style) to hijack IPv6 DNS for the segment",
	})

	out = append(out, v.Vector{
		ModuleID:   "icmp.redirect",
		Target:     p.Gateway.IP.String(),
		Confidence: 0.55,
		Risk:       "medium",
		Impact:     "inject ICMP redirects steering victim traffic through the attacker",
	})

	if p.SeesPlainHTTP {
		out = append(out, v.Vector{
			ModuleID:   "wpad.poison",
			Target:     p.Gateway.IP.String(),
			Confidence: 0.50,
			Risk:       "medium",
			Impact:     "serve a rogue WPAD proxy configuration to browsers on the segment",
		})
	}
	return out
}

func init() {
	v.RegisterRule(dhcpRules)
}

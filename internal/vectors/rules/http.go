package rules

import (
	v "github.com/QYVORA/qyvora-toha3ee/internal/vectors"
)

// httpRules suggests DNS, HTTP(S) interception and phishing attacks.
func httpRules(p *v.Profile) []v.Vector {
	var out []v.Vector
	// DNS/proxy attacks reroute traffic through the attacker, which requires
	// both a known gateway and a segment that accepts forged responses.
	if p.Gateway == nil || !p.Poisonable {
		return out
	}

	out = append(out, v.Vector{
		ModuleID:   "dns.spoof",
		Target:     p.Gateway.IP.String(),
		Confidence: 0.80,
		Risk:       "medium",
		Impact:     "DNS responses spoofed for targeted domains; all other queries forwarded upstream",
	})

	// The HTTP-specific tools only make sense where plaintext HTTP actually
	// flows; offering them on a fully-TLS network would mislead the user.
	if p.SeesPlainHTTP {
		out = append(out, v.Vector{
			ModuleID:   "http.proxy",
			Target:     p.Gateway.IP.String(),
			Confidence: 0.88,
			Risk:       "high",
			Impact:     "inline MITM proxy that can inject JS, swap forms and harvest credentials",
		})
		out = append(out, v.Vector{
			ModuleID:   "phish.inject",
			Target:     p.Gateway.IP.String(),
			Confidence: 0.72,
			Risk:       "high",
			Impact:     "rewrite login forms on real sites to the embedded phishing templates",
		})
	}

	// HTTPS interception is only honest when the framework CA is trusted on
	// the victim device; surface that limitation directly.
	out = append(out, v.Vector{
		ModuleID:   "https.proxy",
		Target:     p.Gateway.IP.String(),
		Confidence: 0.55,
		Risk:       "high",
		Impact:     "HTTPS MITM requires the framework CA to be trusted on the victim device (cert-pinned apps and Android 7+/iOS user-CA limits apply)",
	})

	// DoH detection changes the outlook on DNS spoofing: clients that tunnel
	// DNS over HTTPS bypass a spoofed DNS answer entirely. Emit a low-value,
	// informational vector so the user understands the limitation.
	if p.SeesDoH {
		out = append(out, v.Vector{
			ModuleID:   "dns.spoof",
			Target:     "doh-bypass-warning",
			Confidence: 0.05,
			Risk:       "info",
			Impact:     "DNS-over-HTTPS detected (port 853): DNS spoofing will be bypassed for clients using DoH",
		})
	}
	return out
}

// init registers the rule family with the engine during package init.
func init() {
	v.RegisterRule(httpRules)
}

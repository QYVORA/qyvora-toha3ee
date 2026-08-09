package rules

import (
	v "github.com/qyvora/toha3ee/internal/vectors"
)

// smbRules suggests LLMNR/NBNS/mDNS poisoning and NTLM relay attacks.
func smbRules(p *v.Profile) []v.Vector {
	var out []v.Vector

	// Any of the legacy name-resolution protocols on the wire means
	// poisoning can harvest NTLM hashes; none of them seen means there is
	// nothing to respond to.
	poisonable := p.SeesLLMNR || p.SeesNBNS || p.SeesMDNS
	if poisonable {
		out = append(out, v.Vector{
			ModuleID:   "llmnr.poison",
			Target:     "multicast-names",
			Confidence: 0.74,
			Risk:       "medium",
			Impact:     "respond to LLMNR/NBT-NS/mDNS name resolution and capture NTLMv2 challenges",
		})
	}

	// SMB traffic is required for both relaying auth and for passively
	// judging the signing policy, so both suggestions gate on it.
	if p.SeesSMB {
		out = append(out, v.Vector{
			ModuleID:   "ntlm.relay",
			Target:     "smb-clients",
			Confidence: 0.50,
			Risk:       "critical",
			Impact:     "capture NTLM authentication material and relay it to target HTTP/SMB endpoints",
		})
		out = append(out, v.Vector{
			ModuleID:   "smb.signing",
			Target:     "smb-clients",
			Confidence: 0.40,
			Risk:       "info",
			Impact:     "passively check whether SMB signing is enforced on the segment",
		})
	}
	return out
}

// init registers the rule family with the engine during package init.
func init() {
	v.RegisterRule(smbRules)
}

package rules

import (
	v "github.com/qyvora/toha3ee/internal/vectors"
)

// smbRules suggests LLMNR/NBNS/mDNS poisoning and NTLM relay attacks.
func smbRules(p *v.Profile) []v.Vector {
	var out []v.Vector

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

func init() {
	v.RegisterRule(smbRules)
}

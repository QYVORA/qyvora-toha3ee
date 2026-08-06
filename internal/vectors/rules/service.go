package rules

import (
	"strings"

	v "github.com/qyvora/toha3ee/internal/vectors"
)

// serviceRules suggests scanning, fingerprinting and default-credential
// checks against discovered services.
func serviceRules(p *v.Profile) []v.Vector {
	var out []v.Vector

	if len(p.Hosts) == 0 {
		out = append(out, v.Vector{
			ModuleID:   "service.synscan",
			Target:     "subnet",
			Confidence: 0.85,
			Risk:       "low",
			Impact:     "sweep the subnet for open TCP ports before anything else",
		})
		return out
	}

	scannedAny := false
	for _, h := range p.Hosts {
		if len(h.Ports) == 0 {
			continue
		}
		scannedAny = true
		out = append(out, v.Vector{
			ModuleID:   "service.fingerprint",
			Target:     h.IP.String(),
			Confidence: 0.90,
			Risk:       "low",
			Impact:     "grab banners and fingerprint services on " + h.IP.String(),
		})
		if hasWeb(h.Ports) && likelyRouter(h) {
			out = append(out, v.Vector{
				ModuleID:   "default.creds",
				Target:     h.IP.String(),
				Confidence: 0.60,
				Risk:       "medium",
				Impact:     "test bundled default credentials against the device's web login",
			})
		}
		if hasSMB(h.Ports) {
			out = append(out, v.Vector{
				ModuleID:   "smb.signing",
				Target:     h.IP.String(),
				Confidence: 0.45,
				Risk:       "info",
				Impact:     "check SMB signing policy on " + h.IP.String(),
			})
		}
	}
	if !scannedAny {
		out = append(out, v.Vector{
			ModuleID:   "service.synscan",
			Target:     "subnet",
			Confidence: 0.80,
			Risk:       "low",
			Impact:     "hosts discovered but no ports yet; run a SYN scan",
		})
	}
	return out
}

func hasWeb(ports map[uint16]string) bool {
	for p := range ports {
		if p == 80 || p == 443 || p == 8080 || p == 8443 {
			return true
		}
	}
	return false
}

func hasSMB(ports map[uint16]string) bool {
	_, ok := ports[445]
	return ok
}

// likelyRouter guesses from the vendor or hostname whether a device is a
// router/IoT appliance with a default-credential web login.
func likelyRouter(h *v.Host) bool {
	vendor := h.Vendor
	name := h.Name
	for _, needle := range []string{"TP-Link", "Netgear", "D-Link", "Asus", "ASUSTek", "Huawei", "ZTE", "Sercomm", "Sagemcom", "Ubiquiti", "MikroTik", "Cisco", "Arcadyan", "PCS"} {
		if containsFold(vendor, needle) || containsFold(name, needle) {
			return true
		}
	}
	return false
}

func containsFold(haystack, needle string) bool {
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}

func init() {
	v.RegisterRule(serviceRules)
}

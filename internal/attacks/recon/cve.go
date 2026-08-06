package recon

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/qyvora/toha3ee/internal/attacks"
	"github.com/qyvora/toha3ee/internal/store"
)

func init() {
	attacks.Register(&CVESuggest{})
}

// CVE is a single suggested vulnerability.
type CVE struct {
	ID       string
	Severity string
	Service  string
	Host     string
	Reason   string
}

// CVESuggest cross-references the store's service banners and OS guesses
// against a small embedded rule table and reports candidate CVEs. It is an
// advisory module: it never touches the wire.
type CVESuggest struct{}

func (*CVESuggest) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "cve.suggest",
		Category:    "recon",
		Risk:        attacks.RiskInfo,
		Targets:     []string{"host"},
		Passive:     true,
		Description: "map captured service banners and OS guesses to known CVE candidates from an embedded rule table",
		Limitations: "the embedded table covers common services only; versions must match banners exactly; always verify against a CVE database",
	}
}

// Preflight requires some service banners to exist.
func (*CVESuggest) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	if len(ctx.Store.Hosts()) == 0 {
		rep.AddFixable("hosts", "no hosts in the store; run net.scan + service.synscan + service.fingerprint first")
		return rep, nil
	}
	banners := 0
	for _, h := range ctx.Store.Hosts() {
		banners += len(h.Ports)
	}
	if banners == 0 {
		rep.AddFixable("banners", "no service banners captured; run service.fingerprint first")
	} else {
		rep.AddOK("banners", fmt.Sprintf("%d banner(s) from %d host(s)", banners, len(ctx.Store.Hosts())))
	}
	return rep, nil
}

// Run evaluates every host banner against the rule table.
func (*CVESuggest) Run(ctx *attacks.AttackCtx, opts map[string]string) error {
	var out []CVE
	for _, h := range ctx.Store.Hosts() {
		out = append(out, suggestForHost(h)...)
	}
	ctx.SetState("cve.suggest", out)
	if len(out) == 0 {
		ctx.Printf("[*] cve.suggest: no CVEs matched the captured banners.\n")
		return nil
	}
	for _, c := range out {
		ctx.Printf("[!] cve.suggest: %-12s %s on %s (%s): %s\n", c.Severity, c.ID, c.Host, c.Service, c.Reason)
	}
	return nil
}

// Verify reports the number of suggested CVEs.
func (*CVESuggest) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	v, ok := ctx.GetState("cve.suggest")
	if !ok {
		return nil, fmt.Errorf("cve.suggest has not run")
	}
	cves := v.([]CVE)
	imp := &attacks.Impact{Summary: fmt.Sprintf("suggested %d CVE candidate(s)", len(cves))}
	imp.Add("cve_candidates", fmt.Sprintf("%d", len(cves)))
	sev := map[string]int{}
	for _, c := range cves {
		sev[c.Severity]++
	}
	for _, k := range []string{"critical", "high", "medium"} {
		if n := sev[k]; n > 0 {
			imp.Add(k, fmt.Sprintf("%d", n))
		}
	}
	return imp, nil
}

// Cleanup is a no-op.
func (*CVESuggest) Cleanup(ctx *attacks.AttackCtx) error { return nil }

func suggestForHost(h *store.Host) []CVE {
	var out []CVE
	ports := h.OpenPorts()
	for _, p := range ports {
		banner := h.PortBanner(p)
		if banner == "" {
			continue
		}
		matched := matchBanner(banner, p)
		if matched == nil {
			continue
		}
		out = append(out, CVE{
			ID:       matched.id,
			Severity: matched.severity,
			Service:  fmt.Sprintf("%s/%d", matched.service, p),
			Host:     h.IP.String(),
			Reason:   matched.reason,
		})
	}
	if h.OSGuess != "" {
		if c := matchOS(h.OSGuess); c != nil {
			out = append(out, CVE{
				ID:       c.id,
				Severity: c.severity,
				Service:  "os",
				Host:     h.IP.String(),
				Reason:   c.reason,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return sevRank(out[i].Severity) > sevRank(out[j].Severity) })
	return out
}

type cveRule struct {
	id, severity, service, reason string
	re                            *regexp.Regexp
}

var rules = []cveRule{
	{id: "CVE-2023-48795", severity: "high", service: "ssh", re: regexp.MustCompile(`(?i)OpenSSH_[89]\.[0-4]`), reason: "Terrapin prefix-injection: OpenSSH < 9.6 affected by channel-prefix truncation"},
	{id: "CVE-2016-6210", severity: "high", service: "ssh", re: regexp.MustCompile(`(?i)OpenSSH_[67]\.\d`), reason: "user enumeration via timing on password auth"},
	{id: "CVE-2021-41773", severity: "critical", service: "apache", re: regexp.MustCompile(`(?i)Apache/2\.4\.49`), reason: "path traversal + RCE on Apache 2.4.49"},
	{id: "CVE-2021-42013", severity: "critical", service: "apache", re: regexp.MustCompile(`(?i)Apache/2\.4\.5[01]`), reason: "path traversal + RCE bypass on Apache 2.4.50"},
	{id: "CVE-2022-0778", severity: "high", service: "apache", re: regexp.MustCompile(`(?i)Apache/2\.4\.4[0-9]`), reason: "OpenSSL BN_mod_sqrt infinite loop DoS"},
	{id: "CVE-2024-23897", severity: "critical", service: "jenkins", re: regexp.MustCompile(`(?i)Jenkins\s*/?\s*([01]\.([0-4]\d|5[0-4])\.\d+)`), reason: "CLI arbitrary file read (Jenkins < 2.442/LTS 2.426.2)"},
	{id: "CVE-2023-44487", severity: "high", service: "http", re: regexp.MustCompile(`(?i)(nginx|httpd|caddy|node)`), reason: "HTTP/2 rapid-reset DoS affects most HTTP/2 servers"},
	{id: "CVE-2021-23017", severity: "medium", service: "nginx", re: regexp.MustCompile(`(?i)nginx/1\.(2[01]|1[89]\.\d)`), reason: "DNS resolver off-by-one stack write in nginx"},
	{id: "CVE-2017-7494", severity: "critical", service: "samba", re: regexp.MustCompile(`(?i)Samba\s+4\.[0-5]\.\d`), reason: "EternalRed SMB RCE (CVE-2017-7494) on Samba < 4.6.4"},
	{id: "CVE-2023-22527", severity: "critical", service: "confluence", re: regexp.MustCompile(`(?i)Confluence\s+8\.[0-5]`), reason: "template injection RCE on Confluence 8.5.x"},
	{id: "CVE-2021-34473", severity: "critical", service: "exchange", re: regexp.MustCompile(`(?i)Microsoft\s+Exchange\s+Server\s+2019\s+CU\d`), reason: "ProxyLogon SSRF/RCE chain on on-prem Exchange"},
	{id: "CVE-2023-23397", severity: "critical", service: "exchange", re: regexp.MustCompile(`(?i)Microsoft\s+Exchange\s+Server\s+(2013|2016|2019)`), reason: "NTLM relay via malicious meeting invite"},
	{id: "CVE-2018-13379", severity: "high", service: "fortinet", re: regexp.MustCompile(`(?i)FortiOS|FortiGate`), reason: "SSL-VPN path traversal leaking sessions"},
	{id: "CVE-2023-27350", severity: "critical", service: "printers", re: regexp.MustCompile(`(?i)HP|brother|lexmark`), reason: "printer RCE on several embedded web UIs"},
	{id: "CVE-2019-11510", severity: "critical", service: "pulse", re: regexp.MustCompile(`(?i)Pulse\s+Secure|PulseConnectSecure`), reason: "SSL-VPN arbitrary file read"},
}

var osRules = []cveRule{
	{id: "CVE-2020-1472", severity: "critical", service: "os", re: regexp.MustCompile(`(?i)windows\s+server\s+20(08|12|16|19)`), reason: "Zerologon: unauthenticated DC takeover on vulnerable Windows"},
	{id: "CVE-2021-42278", severity: "critical", service: "os", re: regexp.MustCompile(`(?i)windows\s+server\s+2019`), reason: "noPac: AD user/MachineAccount confusion to DC compromise"},
}

// matchBanner returns the first rule matching the banner text.
func matchBanner(banner string, port uint16) *cveRule {
	for i := range rules {
		if rules[i].re.MatchString(banner) {
			return &rules[i]
		}
	}
	// Fall back to port-only heuristics for banners without a version.
	switch port {
	case 3389:
		if strings.Contains(strings.ToLower(banner), "rdp") || banner == "" {
			// No version available; only flag if banner hints at Windows.
			if strings.Contains(strings.ToLower(banner), "microsoft") || strings.Contains(strings.ToLower(banner), "windows") {
				return &cveRule{id: "CVE-2019-0708", severity: "critical", service: "rdp", reason: "BlueKeep RDP RCE on unpatched Windows (verify patch level)"}
			}
		}
	case 8443:
		return &cveRule{id: "CVE-2020-3452", severity: "high", service: "vpn", reason: "Cisco ASA/FTD path traversal on /+CSCOE+/ endpoint (verify product)"}
	}
	return nil
}

func matchOS(os string) *cveRule {
	for i := range osRules {
		if osRules[i].re.MatchString(os) {
			return &osRules[i]
		}
	}
	return nil
}

func sevRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	}
	return 1
}

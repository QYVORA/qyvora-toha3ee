package recon

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/QYVORA/qyvora-toha3ee/internal/attacks"
	"github.com/QYVORA/qyvora-toha3ee/internal/events"
	"github.com/QYVORA/qyvora-toha3ee/internal/store"
)

// init registers the CVE suggestion module.
func init() {
	attacks.Register(&CVESuggest{})
}

// CVE is a single suggested vulnerability.
type CVE struct {
	ID       string // e.g. "CVE-2021-41773"
	Severity string // critical/high/medium, either from the rule table or CVSS
	Service  string // service (or port) the finding applies to, or "os"
	Host     string // the affected host's IP
	Reason   string // human-readable explanation of the match
}

// CVESuggest cross-references the store's service banners and OS guesses
// against a small embedded rule table and reports candidate CVEs. It is an
// advisory module: it never touches the wire.
type CVESuggest struct{}

// Meta returns the module descriptor used for registry, help and REPL
// completion.
func (*CVESuggest) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "cve.suggest",
		Category:    "recon",
		Risk:        attacks.RiskInfo,
		Targets:     []string{"host"},
		Passive:     true, // matches local data only; never probes the target
		Description: "map captured service banners to known CVEs from an embedded table, or look up CVE IDs / keywords live via the NVD and cve.org APIs",
		Limitations: "embedded mode matches the local rule table only; live mode needs outbound HTTPS to services.nvd.nist.gov / cveawg.mitre.org and is rate-limited",
	}
}

// Preflight requires some service banners to exist.
func (*CVESuggest) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	if len(ctx.Store.Hosts()) == 0 {
		rep.AddFixable("hosts", "no hosts in the store; run net.scan + service.synscan + service.fingerprint first")
		return rep, nil
	}
	// Count the total number of captured banners across all hosts; without any
	// banners there is nothing for the embedded rules to match against.
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

// Run evaluates every host banner against the rule table, or queries the CVE
// APIs live when mode=live.
func (*CVESuggest) Run(ctx *attacks.AttackCtx, opts map[string]string) error {
	mode := ctx.Conf.Get("cve.suggest", "mode")
	if m, ok := opts["mode"]; ok && m != "" {
		mode = m
	}
	if mode == "live" {
		return cveRunLive(ctx)
	}
	// Embedded mode: match every captured banner and OS guess offline.
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

// cveRunLive queries the CVE databases for the configured lookup: a CVE ID
// goes to the cve.org API, a keyword to the NVD keyword search.
func cveRunLive(ctx *attacks.AttackCtx) error {
	lookup := ctx.Conf.Get("cve.suggest", "lookup")
	if lookup == "" {
		return fmt.Errorf("cve.suggest: set cve.suggest.lookup to a CVE ID or keyword (and mode=live)")
	}
	timeout := ctx.Conf.GetDuration("cve.suggest", "timeout", 20*time.Second)
	limit := ctx.Conf.GetInt("cve.suggest", "limit", 8)

	var out []CVE
	// Disambiguate the lookup: a "CVE-" prefix routes to the single-record
	// cve.org endpoint, anything else to the NVD keyword search.
	if strings.HasPrefix(strings.ToUpper(lookup), "CVE-") {
		c, err := cveByID(lookup, timeout)
		if err != nil {
			return fmt.Errorf("cve.suggest: %w", err)
		}
		if c != nil {
			out = append(out, *c)
		}
	} else {
		got, err := cveByKeyword(lookup, limit, timeout)
		if err != nil {
			return fmt.Errorf("cve.suggest: %w", err)
		}
		out = got
	}
	ctx.SetState("cve.suggest", out)
	for _, c := range out {
		ctx.Emit(events.TopicLog, fmt.Sprintf("cve.suggest: %s %s (%s): %s", c.ID, c.Severity, c.Service, c.Reason), nil)
		ctx.Printf("[!] cve.suggest: %-12s %s %s: %s\n", c.Severity, c.ID, c.Service, c.Reason)
	}
	if len(out) == 0 {
		ctx.Printf("[*] cve.suggest: no live CVE results for %q.\n", lookup)
	}
	return nil
}

// cveByKeyword searches the NVD keyword endpoint.
func cveByKeyword(keyword string, limit int, timeout time.Duration) ([]CVE, error) {
	// NVD 2.0 keyword search: query the REST API and cap the page size with
	// resultsPerPage so a vague keyword does not return thousands of records.
	u := "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=" +
		url.QueryEscape(keyword) + "&resultsPerPage=" + url.QueryEscape(fmt.Sprint(limit))
	body, err := httpGetCVE(u, timeout)
	if err != nil {
		return nil, err
	}
	return parseNVD(body)
}

// nvdRecord mirrors the fields of an NVD 2.0 CVE record we care about.
type nvdRecord struct {
	Vulnerabilities []struct {
		CVE struct {
			ID           string `json:"id"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			// CVSS metrics are versioned; we try V3.1, then V3.0, then V2 to
			// find any available base severity.
			Metrics struct {
				CvssMetricV31 []struct {
					CvssData struct {
						BaseSeverity string `json:"baseSeverity"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
				CvssMetricV30 []struct {
					CvssData struct {
						BaseSeverity string `json:"baseSeverity"`
					} `json:"cvssData"`
				} `json:"cvssMetricV30"`
				CvssMetricV2 []struct {
					BaseSeverity string `json:"baseSeverity"`
				} `json:"cvssMetricV2"`
			} `json:"metrics"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

// parseNVD decodes an NVD 2.0 keyword-search response into CVE records.
func parseNVD(body []byte) ([]CVE, error) {
	var resp nvdRecord
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	var out []CVE
	for _, v := range resp.Vulnerabilities {
		// Prefer the newest CVSS vector's severity, falling back through older
		// versions until one is found.
		sev := ""
		if len(v.CVE.Metrics.CvssMetricV31) > 0 {
			sev = v.CVE.Metrics.CvssMetricV31[0].CvssData.BaseSeverity
		}
		if sev == "" && len(v.CVE.Metrics.CvssMetricV30) > 0 {
			sev = v.CVE.Metrics.CvssMetricV30[0].CvssData.BaseSeverity
		}
		if sev == "" && len(v.CVE.Metrics.CvssMetricV2) > 0 {
			sev = v.CVE.Metrics.CvssMetricV2[0].BaseSeverity
		}
		desc := firstEnglish(v.CVE.Descriptions)
		// Cap descriptions so the reason text stays readable on one line.
		if len(desc) > 140 {
			desc = desc[:137] + "..."
		}
		out = append(out, CVE{ID: v.CVE.ID, Severity: sev, Service: "nvd", Reason: desc})
	}
	return out, nil
}

// cveByID looks a single CVE up via the cve.org API.
func cveByID(id string, timeout time.Duration) (*CVE, error) {
	// The cve.org API keys records by uppercase CVE id in the URL path.
	body, err := httpGetCVE("https://cveawg.mitre.org/api/cve/"+strings.ToUpper(id), timeout)
	if err != nil {
		return nil, err
	}
	return parseCVEOrg(body, strings.ToUpper(id))
}

// cveorgRecord mirrors the fields of a cve.org API record we care about.
type cveorgRecord struct {
	CveID      string `json:"cveId"`
	Containers struct {
		CNA struct {
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics []struct {
				// Multiple CVSS vectors may be present; pick the first with a
				// severity, in V3.1 -> V3.0 -> V2 order.
				CvssV31 struct {
					BaseSeverity string `json:"baseSeverity"`
				} `json:"cvssV3_1"`
				CvssV30 struct {
					BaseSeverity string `json:"baseSeverity"`
				} `json:"cvssV3_0"`
				CvssV2 struct {
					BaseSeverity string `json:"baseSeverity"`
				} `json:"cvssV2_0"`
			} `json:"metrics"`
		} `json:"cna"`
	} `json:"containers"`
}

// parseCVEOrg decodes a cve.org API record into a CVE.
func parseCVEOrg(body []byte, id string) (*CVE, error) {
	var resp cveorgRecord
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	sev := ""
	for _, m := range resp.Containers.CNA.Metrics {
		// Take the first metric entry that exposes a severity, breaking out of
		// the loop so we do not overwrite a newer vector with an older one.
		if m.CvssV31.BaseSeverity != "" {
			sev = m.CvssV31.BaseSeverity
			break
		}
		if m.CvssV30.BaseSeverity != "" {
			sev = m.CvssV30.BaseSeverity
			break
		}
		if m.CvssV2.BaseSeverity != "" {
			sev = m.CvssV2.BaseSeverity
			break
		}
	}
	desc := ""
	for _, d := range resp.Containers.CNA.Descriptions {
		// Prefer the English description for the reason text.
		if d.Lang == "en" {
			desc = d.Value
			break
		}
	}
	if len(desc) > 140 {
		desc = desc[:137] + "..."
	}
	// Trust the record's own id, falling back to the one we requested.
	cid := resp.CveID
	if cid == "" {
		cid = id
	}
	return &CVE{ID: cid, Severity: sev, Service: "cve.org", Reason: desc}, nil
}

// httpGetCVE performs a short HTTPS GET for CVE database queries.
func httpGetCVE(u string, timeout time.Duration) ([]byte, error) {
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, err
	}
	// Identify the client; some CVE APIs rate-limit or reject unidentifiable
	// agents.
	req.Header.Set("User-Agent", "toha3ee/1.0 (authorized assessment)")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CVE API returned HTTP %d", resp.StatusCode)
	}
	// Cap the response at 4 MiB to bound memory on oversized result sets.
	return io.ReadAll(io.LimitReader(resp.Body, 4<<20))
}

// firstEnglish returns the first description that is English (or has no
// declared language) from an NVD description list.
func firstEnglish(ds []struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}) string {
	for _, d := range ds {
		if d.Lang == "en" || d.Lang == "" {
			return d.Value
		}
	}
	return ""
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
	// Bucket the suggestions by severity so the impact report reads like a
	// triage list.
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
func (*CVESuggest) Cleanup(_ *attacks.AttackCtx) error { return nil }

// suggestForHost runs every open port's banner and the OS guess through the
// rule tables, returning the matched CVEs sorted by severity.
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
	// Also match the OS fingerprint if a service-level rule did not fire.
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
	// Present the most dangerous findings first.
	sort.Slice(out, func(i, j int) bool { return sevRank(out[i].Severity) > sevRank(out[j].Severity) })
	return out
}

// cveRule is one banner/OS match rule: a regex to match against the captured
// text plus the CVE metadata and a human-readable reason.
type cveRule struct {
	id, severity, service, reason string
	re                            *regexp.Regexp
}

// rules is the embedded banner-signature table. Each entry ties a small,
// version-specific regex to a known CVE; the regexes are intentionally narrow
// so we only flag a CVE when the banner is specific enough to be confident.
var rules = []cveRule{
	{id: "CVE-2023-48795", severity: "high", service: "ssh", re: regexp.MustCompile(`(?i)OpenSSH_[89]\.[0-4]`), reason: "Terrapin prefix-injection: OpenSSH < 9.6 affected by channel-prefix truncation"},
	{id: "CVE-2016-6210", severity: "high", service: "ssh", re: regexp.MustCompile(`(?i)OpenSSH_[67]\.\d`), reason: "user enumeration via timing on password auth"},
	{id: "CVE-2021-41773", severity: "critical", service: "apache", re: regexp.MustCompile(`(?i)Apache/2\.4\.49`), reason: "path traversal + RCE on Apache 2.4.49"},
	{id: "CVE-2021-42013", severity: "critical", service: "apache", re: regexp.MustCompile(`(?i)Apache/2\.4\.5[01]`), reason: "path traversal + RCE bypass on Apache 2.4.50"},
	{id: "CVE-2022-0778", severity: "high", service: "apache", re: regexp.MustCompile(`(?i)Apache/2\.4\.4[0-9]`), reason: "OpenSSL BN_mod_sqrt infinite loop DoS"},
	{id: "CVE-2024-23897", severity: "critical", service: "jenkins", re: regexp.MustCompile(`(?i)Jenkins\s*/?\s*([01]\.([0-4]\d|5[0-4])\.\d+)`), reason: "CLI arbitrary file read (Jenkins < 2.442/LTS 2.426.2)"},
	{id: "CVE-2023-44487", severity: "high", service: "http", re: regexp.MustCompile(`(?i)(nginx/[1-9]\.|httpd/2\.[4-5]\.|caddy/v2\.|node/v[18]\.)`), reason: "HTTP/2 rapid-reset DoS affects most HTTP/2 servers"},
	{id: "CVE-2021-23017", severity: "medium", service: "nginx", re: regexp.MustCompile(`(?i)nginx/1\.(2[01]|1[89]\.\d)`), reason: "DNS resolver off-by-one stack write in nginx"},
	{id: "CVE-2017-7494", severity: "critical", service: "samba", re: regexp.MustCompile(`(?i)Samba\s+4\.[0-5]\.\d`), reason: "EternalRed SMB RCE (CVE-2017-7494) on Samba < 4.6.4"},
	{id: "CVE-2023-22527", severity: "critical", service: "confluence", re: regexp.MustCompile(`(?i)Confluence\s+8\.[0-5]`), reason: "template injection RCE on Confluence 8.5.x"},
	{id: "CVE-2021-34473", severity: "critical", service: "exchange", re: regexp.MustCompile(`(?i)Microsoft\s+Exchange\s+Server\s+2019\s+CU\d`), reason: "ProxyLogon SSRF/RCE chain on on-prem Exchange"},
	{id: "CVE-2023-23397", severity: "critical", service: "exchange", re: regexp.MustCompile(`(?i)Microsoft\s+Exchange\s+Server\s+(2013|2016|2019)`), reason: "NTLM relay via malicious meeting invite"},
	{id: "CVE-2018-13379", severity: "high", service: "fortinet", re: regexp.MustCompile(`(?i)FortiOS|FortiGate`), reason: "SSL-VPN path traversal leaking sessions"},
	{id: "CVE-2023-27350", severity: "critical", service: "printers", re: regexp.MustCompile(`(?i)(HP\s+LaserJet\s+Pro|MFP\s+M[0-9]|Brother\s+HL-L|Brother\s+MFC-L|Lexmark\s+MS[0-9]|Lexmark\s+MX[0-9])`), reason: "printer RCE on several embedded web UIs"},
	{id: "CVE-2019-11510", severity: "critical", service: "pulse", re: regexp.MustCompile(`(?i)Pulse\s+Secure|PulseConnectSecure`), reason: "SSL-VPN arbitrary file read"},
}

// osRules maps OS fingerprints to OS-level CVEs.
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
		if strings.Contains(strings.ToLower(banner), "cisco") || strings.Contains(strings.ToLower(banner), "asa") || strings.Contains(strings.ToLower(banner), "ftd") {
			return &cveRule{id: "CVE-2020-3452", severity: "high", service: "vpn", reason: "Cisco ASA/FTD path traversal on /+CSCOE+/ endpoint (verify product)"}
		}
	}
	return nil
}

// matchOS returns the first OS rule matching the fingerprint text.
func matchOS(os string) *cveRule {
	for i := range osRules {
		if osRules[i].re.MatchString(os) {
			return &osRules[i]
		}
	}
	return nil
}

// sevRank maps a severity string to a numeric rank for sorting; unknown
// severities sort lowest.
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

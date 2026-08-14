package osint

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/QYVORA/qyvora-toha3ee/internal/attacks"
	"github.com/QYVORA/qyvora-toha3ee/internal/events"
)

// CTLogs enumerates subdomains of a domain from public certificate
// transparency logs (crt.sh). TLS certificates are logged by every CA, so the
// query surfaces hidden hosts and internal names the org never published.
type CTLogs struct{}

// Meta implements attacks.Module.
func (*CTLogs) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "osint.ct",
		Category:    "osint",
		Risk:        attacks.RiskInfo,
		Targets:     []string{"domain"},
		Passive:     true,
		Description: "enumerate subdomains from certificate transparency logs (crt.sh)",
		Limitations: "only names present in public certificates appear; wildcard certs may hide some hosts; depends on crt.sh availability",
	}
}

// Preflight needs a target domain.
func (*CTLogs) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	if _, err := target(ctx, "osint.ct", "domain"); err != nil {
		rep.AddFixable("domain", "set osint.ct.domain, e.g. 'set osint.ct.domain example.com'")
	} else {
		rep.AddOK("domain", ctx.Conf.Get("osint.ct", "domain"))
	}
	return rep, nil
}

// certEntry is one crt.sh JSON record. The "output=json" variant of the crt.sh
// query returns an array of such objects; issuer_name is carried along in case
// later triage wants to correlate certificate chains, though only name_value
// feeds the subdomain extraction.
type certEntry struct {
	NameValue string `json:"name_value"`
	Issuer    string `json:"issuer_name"`
}

// Run fetches and dedupes the certificate names for the domain.
func (*CTLogs) Run(ctx *attacks.AttackCtx, opts map[string]string) error {
	domain, err := target(ctx, "osint.ct", "domain")
	if err != nil {
		return err
	}
	// Normalize: lower-case, strip surrounding whitespace and any trailing dot
	// so "Example.COM." behaves like "example.com".
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	timeout := ctx.Conf.GetDuration("osint.ct", "timeout", 20*time.Second)

	// crt.sh accepts "%.domain" to match any subdomain: the query searches the
	// common name / SAN fields of all logged certs. The JSON output format
	// avoids scraping the HTML result table.
	body, err := httpGet(fmt.Sprintf("https://crt.sh/?q=%s&output=json", "%."+domain), timeout)
	if err != nil {
		return fmt.Errorf("osint.ct: crt.sh: %w", err)
	}
	var entries []certEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return fmt.Errorf("osint.ct: parse crt.sh response: %w", err)
	}

	// A single cert can carry several names (SANs joined by newlines), so the
	// extraction splits on newlines and dedupes across all entries.
	seen := map[string]bool{}
	var names []string
	for _, e := range entries {
		for _, n := range strings.Split(e.NameValue, "\n") {
			// Trim "*.domain" wildcards — a wildcard cert says nothing about a
			// concrete host, and we want bare names for the final report.
			n = strings.ToLower(strings.TrimSpace(strings.Trim(n, "*.")))
			if n == "" || seen[n] {
				continue
			}
			// Reject names outside the target's zone (unrelated certs that
			// happened to share the % wildcard match) but accept the apex.
			if n != domain && !strings.HasSuffix(n, "."+domain) {
				continue
			}
			seen[n] = true
			names = append(names, n)
		}
	}
	// Deterministic ordering for stable reports and diffs across runs.
	sort.Strings(names)

	for _, n := range names {
		// Stream each name onto the log topic as it is confirmed.
		ctx.Emit(events.TopicLog, fmt.Sprintf("osint.ct: subdomain %s", n), nil)
	}
	ctx.SetState("osint.ct", names)
	ctx.Printf("[*] osint.ct complete: %d unique name(s) in CT logs for %s.\n", len(names), domain)
	return nil
}

// Verify reports the discovered subdomains.
func (*CTLogs) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	v, ok := ctx.GetState("osint.ct")
	if !ok {
		return nil, fmt.Errorf("osint.ct not run")
	}
	names, _ := v.([]string)
	imp := &attacks.Impact{Summary: fmt.Sprintf("found %d subdomain(s) via certificate transparency", len(names))}
	imp.Add("subdomains", strconv.Itoa(len(names)))
	// Cap the individual names in the report at 50 to keep impact output
	// readable; the full list is already persisted in state.
	for i, n := range names {
		if i >= 50 {
			break
		}
		imp.Add("name", n)
	}
	return imp, nil
}

// Cleanup is a no-op.
func (*CTLogs) Cleanup(ctx *attacks.AttackCtx) error { return nil }

var _ attacks.Module = (*CTLogs)(nil)

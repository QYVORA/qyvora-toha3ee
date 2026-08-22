package osint

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/QYVORA/qyvora-toha3ee/internal/attacks"
	"github.com/QYVORA/qyvora-toha3ee/internal/events"
)

// ASNEnum maps a target's IP estate via BGP/ASN lookups (RIPEstat): from a
// domain or IP it finds the owning ASN and every announced prefix, and from an
// ASN it lists all announced prefixes. It touches only RIPE's public database.
type ASNEnum struct{}

// Meta implements attacks.Module.
func (*ASNEnum) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "osint.asn",
		Category:    "osint",
		Risk:        attacks.RiskInfo,
		Targets:     []string{"domain", "ip", "asn"},
		Description: "map the org's entire IP estate via ASN/BGP lookups (RIPEstat ip-to-asn + announced prefixes)",
		Limitations: "relies on the public RIPEstat API; results reflect current BGP announcements and may lag de-registrations",
	}
}

// ripenetResponse mirrors the envelope returned by RIPEstat's JSON endpoints:
// the "data" object wraps the per-prefix results. The ASN value is a string
// (e.g. "AS3333") even though the field is named asn, so it needs trimming.
type ripenetResponse struct {
	Data struct {
		Prefixes []struct {
			Prefix string `json:"prefix"`
			ASN    string `json:"asn"`
		} `json:"prefixes"`
	} `json:"data"`
}

// asnResult is one resolved ASN plus the list of CIDR prefixes it announces;
// Count mirrors len(Prefixes) for convenient aggregation later.
type asnResult struct {
	ASN      string
	Prefixes []string
	Count    int
}

// Preflight needs a target.
func (*ASNEnum) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	t, err := target(ctx, "osint.asn", "target")
	if err != nil {
		rep.AddFixable("target", err.Error())
		return rep, nil
	}
	rep.AddOK("target", t)
	return rep, nil
}

// Run resolves the target to an ASN and lists its announced prefixes.
func (*ASNEnum) Run(ctx *attacks.AttackCtx, opts map[string]string) error {
	// Pull the configured target, but let an on-the-fly --target override win.
	t := ctx.Conf.Get("osint.asn", "target")
	if o, ok := opts["target"]; ok && o != "" {
		t = o
	}
	// The per-module timeout bounds every external HTTP call so a slow RIPE
	// response cannot stall the whole engagement run.
	timeout := ctx.Conf.GetDuration("osint.asn", "timeout", 15*time.Second)
	asns, err := resolveASNs(t, timeout)
	if err != nil {
		return fmt.Errorf("osint.asn: %w", err)
	}
	var out []asnResult
	for _, asn := range asns {
		prefixes, err := announcedPrefixes(asn, timeout)
		if err != nil {
			// A single failed prefix lookup should not abort the whole run;
			// skip that ASN and keep enumerating the rest.
			continue
		}
		out = append(out, asnResult{ASN: asn, Prefixes: prefixes, Count: len(prefixes)})
		for _, p := range prefixes {
			// Emit every announced prefix as a finding so downstream phases
			// can pivot into each CIDR block.
			emit(ctx, "finding", fmt.Sprintf("osint.asn: %s announces %s", asn, p))
		}
	}
	// Persist the estate for Verify and hand back a console summary.
	ctx.SetState("osint.asn", out)
	ctx.Printf("[*] osint.asn complete: %d ASN(s), %d prefix(es) mapped.\n", len(out), totalPrefixes(out))
	return nil
}

// resolveASNs accepts a bare ASN, an IP or a domain and returns the list of
// ASNs that own/announce it, deduplicated and stripped of the "AS" prefix.
func resolveASNs(target string, timeout time.Duration) ([]string, error) {
	// seen guards against the same ASN appearing twice (e.g. when several IPs
	// of one domain all belong to the same autonomous system).
	seen := map[string]bool{}
	var out []string
	// add normalizes an ASN to its bare numeric form and records it once.
	add := func(asn string) {
		asn = strings.TrimPrefix(strings.ToUpper(asn), "AS")
		if asn != "" && !seen[asn] {
			seen[asn] = true
			out = append(out, asn)
		}
	}

	// A literal ASN: the user typed "AS3333" or a bare number, so there is no
	// need to ask RIPE anything yet — just seed the result and fall through to
	// prefix enumeration.
	if len(target) > 2 && (strings.EqualFold(target[:2], "AS") || isAllDigits(target)) {
		add(target)
		if len(out) > 0 {
			return out, nil
		}
	}
	// An IP: resolve it straight through RIPEstat's ip-to-asn lookup.
	if ip := net.ParseIP(target); ip != nil {
		if ips, err := ipToASN(ip, timeout); err == nil {
			for _, a := range ips {
				add(a)
			}
		}
		// Even if the lookup failed, an IP target maps to at most one AS; stop
		// here rather than attempting a DNS resolution of the IP string.
		return out, nil
	}
	// A domain: resolve every A/AAAA address, then map each to its owning ASN.
	ips, err := net.LookupHost(target)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("cannot resolve %q", target)
	}
	for _, ip := range ips {
		if asns, err := ipToASN(net.ParseIP(ip), timeout); err == nil {
			for _, a := range asns {
				add(a)
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no ASN found for %q", target)
	}
	return out, nil
}

// isAllDigits reports whether s is a non-empty string of digits only, used to
// detect a bare ASN number ("3333") as opposed to an AS-prefixed one.
func isAllDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return len(s) > 0
}

// ipToASN queries the RIPEstat ip-to-asn dataset for the given IP and returns
// every ASN that announces it. The URL's "resource" parameter is the IP itself
// (optionally with an "as=" prefix to pin the ASN for path queries, unused
// here); the free dataset needs no API key.
func ipToASN(ip net.IP, timeout time.Duration) ([]string, error) {
	raw, err := httpGet("https://stat.ripe.net/data/ip-to-asn/data.json?resource="+ip.String(), timeout)
	if err != nil {
		return nil, err
	}
	var resp ripenetResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, err
	}
	var out []string
	for _, p := range resp.Data.Prefixes {
		if p.ASN != "" {
			// RIPE returns ASNs prefixed with "AS"; normalize to bare numbers.
			out = append(out, strings.TrimPrefix(p.ASN, "AS"))
		}
	}
	return out, nil
}

// announcedPrefixes lists every CIDR prefix an ASN currently announces to the
// internet, via RIPEstat's announced-prefixes dataset keyed on "resource=AS<nn>".
// This is the authoritative view of the org's public IP estate.
func announcedPrefixes(asn string, timeout time.Duration) ([]string, error) {
	raw, err := httpGet("https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS"+asn, timeout)
	if err != nil {
		return nil, err
	}
	// The response reuses the same "data.prefixes[]" envelope, but only the
	// prefix string is of interest here, so it is unmarshaled inline.
	var resp struct {
		Data struct {
			Prefixes []struct {
				Prefix string `json:"prefix"`
			} `json:"prefixes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, err
	}
	var out []string
	for _, p := range resp.Data.Prefixes {
		if p.Prefix != "" {
			out = append(out, p.Prefix)
		}
	}
	return out, nil
}

// totalPrefixes sums the per-ASN prefix counts for console/impact summaries.
func totalPrefixes(res []asnResult) int {
	n := 0
	for _, r := range res {
		n += r.Count
	}
	return n
}

// Verify reports the mapped estate.
func (*ASNEnum) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	v, ok := ctx.GetState("osint.asn")
	if !ok {
		return nil, fmt.Errorf("osint.asn not run")
	}
	res, _ := v.([]asnResult)
	imp := &attacks.Impact{Summary: fmt.Sprintf("mapped %d ASN(s) / %d prefix(es)", len(res), totalPrefixes(res))}
	for _, r := range res {
		imp.Add("asn", r.ASN+" prefixes="+strconv.Itoa(r.Count))
	}
	return imp, nil
}

// Cleanup is a no-op.
func (*ASNEnum) Cleanup(_ *attacks.AttackCtx) error { return nil }

// emit pushes a message onto the shared log topic. topic is currently unused
// beyond documentation, but keeping it lets callers express intent and allows
// a future routed emission without changing call sites.
func emit(ctx *attacks.AttackCtx, _, msg string) {
	ctx.Emit(events.TopicLog, msg, nil)
}

// Compile-time assertion that ASNEnum satisfies the attacks.Module interface.
var _ attacks.Module = (*ASNEnum)(nil)

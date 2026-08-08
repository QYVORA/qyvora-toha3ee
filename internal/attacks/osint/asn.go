package osint

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/qyvora/toha3ee/internal/attacks"
	"github.com/qyvora/toha3ee/internal/events"
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

type ripenetResponse struct {
	Data struct {
		Prefixes []struct {
			Prefix string `json:"prefix"`
			ASN    string `json:"asn"`
		} `json:"prefixes"`
	} `json:"data"`
}

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
	t := ctx.Conf.Get("osint.asn", "target")
	if o, ok := opts["target"]; ok && o != "" {
		t = o
	}
	timeout := ctx.Conf.GetDuration("osint.asn", "timeout", 15*time.Second)
	asns, err := resolveASNs(t, timeout)
	if err != nil {
		return fmt.Errorf("osint.asn: %w", err)
	}
	var out []asnResult
	for _, asn := range asns {
		prefixes, err := announcedPrefixes(asn, timeout)
		if err != nil {
			continue
		}
		out = append(out, asnResult{ASN: asn, Prefixes: prefixes, Count: len(prefixes)})
		for _, p := range prefixes {
			emit(ctx, "finding", fmt.Sprintf("osint.asn: %s announces %s", asn, p))
		}
	}
	ctx.SetState("osint.asn", out)
	ctx.Printf("[*] osint.asn complete: %d ASN(s), %d prefix(es) mapped.\n", len(out), totalPrefixes(out))
	return nil
}

func resolveASNs(target string, timeout time.Duration) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	add := func(asn string) {
		asn = strings.TrimPrefix(strings.ToUpper(asn), "AS")
		if asn != "" && !seen[asn] {
			seen[asn] = true
			out = append(out, asn)
		}
	}

	// A literal ASN.
	if len(target) > 2 && (strings.EqualFold(target[:2], "AS") || isAllDigits(target)) {
		add(target)
		if len(out) > 0 {
			return out, nil
		}
	}
	// An IP.
	if ip := net.ParseIP(target); ip != nil {
		if ips, err := ipToASN(ip, timeout); err == nil {
			for _, a := range ips {
				add(a)
			}
		}
		return out, nil
	}
	// A domain.
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

func isAllDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return len(s) > 0
}

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
			out = append(out, strings.TrimPrefix(p.ASN, "AS"))
		}
	}
	return out, nil
}

func announcedPrefixes(asn string, timeout time.Duration) ([]string, error) {
	raw, err := httpGet("https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS"+asn, timeout)
	if err != nil {
		return nil, err
	}
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
func (*ASNEnum) Cleanup(ctx *attacks.AttackCtx) error { return nil }

func emit(ctx *attacks.AttackCtx, topic, msg string) {
	ctx.Emit(events.TopicLog, msg, nil)
}

var _ attacks.Module = (*ASNEnum)(nil)

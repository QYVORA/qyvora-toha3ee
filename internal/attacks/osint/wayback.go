package osint

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/qyvora/toha3ee/internal/attacks"
)

// WaybackEnum lists every URL the Internet Archive has captured for a domain
// and its subdomains, exposing historical pages, endpoints and parameters that
// have long since been removed from the live site.
type WaybackEnum struct{}

// Meta implements attacks.Module.
func (*WaybackEnum) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "osint.wayback",
		Category:    "osint",
		Risk:        attacks.RiskInfo,
		Targets:     []string{"domain"},
		Description: "recover historical URLs and subdomains from the Wayback Machine CDX API",
		Limitations: "only shows what the archive has crawled; limit caps rows per query",
	}
}

type waybackResult struct {
	Target string
	Count  int
	URLs   []string
}

// Preflight needs a domain.
func (*WaybackEnum) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	t, err := target(ctx, "osint.wayback", "target")
	if err != nil {
		rep.AddFixable("target", err.Error())
		return rep, nil
	}
	rep.AddOK("target", t)
	return rep, nil
}

// Run queries the CDX API for archived URLs.
func (*WaybackEnum) Run(ctx *attacks.AttackCtx, opts map[string]string) error {
	t := ctx.Conf.Get("osint.wayback", "target")
	if o, ok := opts["target"]; ok && o != "" {
		t = o
	}
	timeout := ctx.Conf.GetDuration("osint.wayback", "timeout", 30*time.Second)
	limit := ctx.Conf.Get("osint.wayback", "limit")
	if limit == "" {
		limit = "2000"
	}
	params := url.Values{}
	params.Set("url", "*.`"+t+"`/*")
	params.Set("output", "json")
	params.Set("fl", "original")
	params.Set("collapse", "urlkey")
	params.Set("filter", "statuscode:200")
	params.Set("limit", limit)
	endpoint := "https://web.archive.org/cdx/search/cdx?" + params.Encode()

	raw, err := httpGet(endpoint, timeout)
	if err != nil {
		return fmt.Errorf("osint.wayback: %w", err)
	}
	var rows [][]string
	if err := json.Unmarshal(raw, &rows); err != nil {
		return fmt.Errorf("osint.wayback: %w", err)
	}
	seen := map[string]bool{}
	var urls []string
	for _, r := range rows {
		if len(r) == 0 {
			continue
		}
		u := r[0]
		if seen[u] {
			continue
		}
		seen[u] = true
		urls = append(urls, u)
		emit(ctx, "finding", "osint.wayback: archived "+u)
	}
	ctx.SetState("osint.wayback", waybackResult{Target: t, Count: len(urls), URLs: urls})
	ctx.Printf("[*] osint.wayback: %d unique URL(s) archived for %s.\n", len(urls), t)
	return nil
}

// Verify reports the URL count and interesting matches.
func (*WaybackEnum) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	v, ok := ctx.GetState("osint.wayback")
	if !ok {
		return nil, fmt.Errorf("osint.wayback not run")
	}
	res, _ := v.(waybackResult)
	imp := &attacks.Impact{Summary: fmt.Sprintf("%d archived URL(s) for %s", res.Count, res.Target)}
	for _, u := range res.URLs {
		lu := strings.ToLower(u)
		if strings.Contains(lu, "admin") || strings.Contains(lu, "api") || strings.Contains(lu, ".env") ||
			strings.Contains(lu, "backup") || strings.Contains(lu, "config") || strings.Contains(lu, "phpmyadmin") ||
			strings.Contains(lu, "swagger") || strings.Contains(lu, "login") {
			imp.Add("interesting", u)
		}
	}
	return imp, nil
}

// Cleanup is a no-op.
func (*WaybackEnum) Cleanup(ctx *attacks.AttackCtx) error { return nil }

var _ attacks.Module = (*WaybackEnum)(nil)

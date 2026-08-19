package osint

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"time"

	"github.com/QYVORA/qyvora-toha3ee/internal/attacks"
)

// Dork runs search-engine queries to surface indexable results that expose
// infrastructure, documents or internal references. It uses DuckDuckGo's
// server-rendered HTML endpoint, so no browser or JS execution is required.
type Dork struct{}

// Meta implements attacks.Module.
func (*Dork) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "osint.dork",
		Category:    "osint",
		Risk:        attacks.RiskInfo,
		Targets:     []string{"query"},
		Description: "run a search-engine dork and collect result URLs (DuckDuckGo HTML endpoint)",
		Limitations: "results are limited to what the engine indexes; aggressive querying may trigger rate limiting",
	}
}

// resultLink matches the anchor tags of DuckDuckGo's HTML results page. Each
// result is an <a> element carrying the "result__a" CSS class; the capture
// group extracts the (percent-encoded) href that points at the hit URL.
var resultLink = regexp.MustCompile(`<a[^>]+class="result__a"[^>]+href="([^"]+)"`)

// dorkResult bundles a dork query with its matched URLs for state/reporting.
type dorkResult struct {
	Query   string
	Count   int
	Results []string
}

// Preflight needs a query.
func (*Dork) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	q, err := target(ctx, "osint.dork", "query")
	if err != nil {
		rep.AddFixable("query", err.Error())
		return rep, nil
	}
	rep.AddOK("query", q)
	return rep, nil
}

// Run executes the dork and records result URLs.
func (*Dork) Run(ctx *attacks.AttackCtx, opts map[string]string) error {
	// Pull the configured query, but let an on-the-fly --query override win.
	q := ctx.Conf.Get("osint.dork", "query")
	if o, ok := opts["query"]; ok && o != "" {
		q = o
	}
	timeout := ctx.Conf.GetDuration("osint.dork", "timeout", 20*time.Second)
	results, err := ddgResults(q, timeout)
	if err != nil {
		return fmt.Errorf("osint.dork: %w", err)
	}
	ctx.SetState("osint.dork", dorkResult{Query: q, Count: len(results), Results: results})
	for _, r := range results {
		emit(ctx, "finding", "osint.dork: "+r)
	}
	ctx.Printf("[*] osint.dork: %d result(s) for %q.\n", len(results), q)
	return nil
}

// ddgResults fetches the DDG HTML result page and extracts result links. The
// HTML endpoint (html.duckduckgo.com) is used instead of the JSON API because
// it requires no key and mirrors a plain browser request; the search terms are
// sent URL-encoded in the "q" query parameter.
func ddgResults(query string, timeout time.Duration) ([]string, error) {
	client := &http.Client{Timeout: timeout}
	u := "https://html.duckduckgo.com/html/?q=" + url.QueryEscape(query)
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, err
	}
	// A realistic desktop Chrome UA avoids trivial bot-filtering that would
	// otherwise return a CAPTCHA page instead of results.
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		// Non-200 (including DDG's anti-bot 202) means no usable results.
		return nil, fmt.Errorf("search engine returned HTTP %d", resp.StatusCode)
	}
	// Cap the read at 4 MiB — a results page is a few hundred KB at most.
	body, err := readAllLimit(resp.Body, 4<<20)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, m := range resultLink.FindAllStringSubmatch(string(body), -1) {
		if len(m) > 1 {
			// DDG percent-encodes result hrefs (a redirect wrapper); decode
			// them back to the real target URL before reporting.
			if unesc, err := url.QueryUnescape(m[1]); err == nil {
				out = append(out, unesc)
			}
		}
	}
	return dedup(out), nil
}

// dedup collapses repeated URLs while preserving first-seen order.
func dedup(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// Verify reports the result count.
func (*Dork) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	v, ok := ctx.GetState("osint.dork")
	if !ok {
		return nil, fmt.Errorf("osint.dork not run")
	}
	r, _ := v.(dorkResult)
	imp := &attacks.Impact{Summary: fmt.Sprintf("%d result(s) for %q", r.Count, r.Query)}
	for _, u := range r.Results {
		imp.Add("url", u)
	}
	return imp, nil
}

// Cleanup is a no-op.
func (*Dork) Cleanup(ctx *attacks.AttackCtx) error { return nil }

var _ attacks.Module = (*Dork)(nil)

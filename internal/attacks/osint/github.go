package osint

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/qyvora/toha3ee/internal/attacks"
)

// GitHubDork searches GitHub code for leaked secrets and internal references
// to an org. It reports the repository, file path and a sanitized snippet so
// findings can be triaged without re-exposing secrets.
type GitHubDork struct{}

// Meta implements attacks.Module.
func (*GitHubDork) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "osint.github",
		Category:    "osint",
		Risk:        attacks.RiskInfo,
		Targets:     []string{"org", "domain", "keyword"},
		Description: "GitHub code-search for leaked secrets and internal references (token required)",
		Limitations: "GitHub code search requires an authenticated token; results are capped at 100 per query",
	}
}

// ghItem is one code-search hit: which repository and file matched, a link to
// the blob, and a (sanitized) snippet of the matching fragment. The Source
// field is populated from the "text_matches" array returned by the API.
type ghItem struct {
	Repo    string `json:"repository"`
	Path    string `json:"path"`
	HTMLURL string `json:"html_url"`
	Source  string `json:"text_matches"`
}

// ghResult groups the items found by one named dork query.
type ghResult struct {
	Query string
	Count int
	Items []ghItem
}

// ghQueries is the fixed set of GitHub code-search dorks. Each query is later
// suffixed with the org target so only code mentioning the org is surfaced.
// The "name" is used as the finding label; "q" is the GitHub search syntax
// (OR-ed terms, filename: filters) as documented by the code-search API.
var ghQueries = []struct {
	name string
	q    string
}{
	{"password", "password"},
	{"aws_key", "aws_access_key_id OR AWS_SECRET_ACCESS_KEY"},
	{"env_file", "filename:.env"},
	{"api_key", "api_key OR apikey OR api-key"},
	{"private_key", "PRIVATE KEY"},
	{"internal", "internal OR intranet OR vpn"},
}

// Preflight needs a token and a target.
func (*GitHubDork) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	if ctx.Conf.Get("osint.github", "token") == "" {
		rep.AddBlocked("token", "GitHub code search requires authentication; set osint.github.token")
	} else {
		rep.AddOK("token", "GitHub token set")
	}
	t, err := target(ctx, "osint.github", "target")
	if err != nil {
		rep.AddFixable("target", err.Error())
		return rep, nil
	}
	rep.AddOK("target", t)
	return rep, nil
}

// Run executes the dork queries.
func (*GitHubDork) Run(ctx *attacks.AttackCtx, opts map[string]string) error {
	// Code search is only available to authenticated users, so a token is
	// mandatory here rather than a per-query enhancement.
	token := ctx.Conf.Get("osint.github", "token")
	if token == "" {
		return fmt.Errorf("osint.github: set osint.github.token first")
	}
	t := ctx.Conf.Get("osint.github", "target")
	if o, ok := opts["target"]; ok && o != "" {
		t = o
	}
	timeout := ctx.Conf.GetDuration("osint.github", "timeout", 20*time.Second)

	var all []ghResult
	total := 0
	for _, dq := range ghQueries {
		// Combine the dork with the org target: "password <org>".
		q := dq.q + " " + t
		items, err := ghSearch(token, q, timeout)
		if err != nil {
			// One failed query (e.g. rate limit, bad syntax) must not sink the
			// rest; log and move to the next dork.
			ctx.Printf("[!] osint.github: query %q failed: %v\n", q, err)
			continue
		}
		all = append(all, ghResult{Query: dq.name, Count: len(items), Items: items})
		total += len(items)
		for _, it := range items {
			emit(ctx, "finding", fmt.Sprintf("osint.github: %s leaked in %s/%s", dq.name, it.Repo, it.Path))
		}
	}
	ctx.SetState("osint.github", all)
	ctx.Printf("[*] osint.github: %d code match(es) across %d query type(s).\n", total, len(all))
	return nil
}

// ghSearch runs one code-search query against the GitHub API. The endpoint is
// the search/code JSON API; "q" carries the URL-encoded query and "per_page=50"
// is the maximum page size, so a single request returns up to 50 matches.
func ghSearch(token, query string, timeout time.Duration) ([]ghItem, error) {
	client := newAuthClient(token, timeout)
	raw, err := client.get("https://api.github.com/search/code?q=" + urlQuery(query) + "&per_page=50")
	if err != nil {
		return nil, err
	}
	// Unmarshal only the fields code search actually returns: the item's path,
	// html_url, repository.full_name and the text_matches fragment list.
	var resp struct {
		Items []struct {
			Name       string `json:"name"`
			Path       string `json:"path"`
			HTMLURL    string `json:"html_url"`
			Repository struct {
				FullName string `json:"full_name"`
			} `json:"repository"`
			Matches []struct {
				Fragment string `json:"fragment"`
			} `json:"text_matches"`
		} `json:"items"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, err
	}
	var out []ghItem
	for _, it := range resp.Items {
		item := ghItem{Repo: it.Repository.FullName, Path: it.Path, HTMLURL: it.HTMLURL}
		// text_matches are only present with the text-match media type (which
		// the shared client requests); use the first fragment as the snippet.
		if len(it.Matches) > 0 {
			item.Source = sanitize(it.Matches[0].Fragment)
		}
		out = append(out, item)
	}
	return out, nil
}

// sanitize truncates a secret snippet so findings are reportable but the raw
// secret is not echoed back into the terminal.
func sanitize(s string) string {
	if len(s) > 120 {
		return s[:117] + "..."
	}
	return s
}

// Verify reports the repositories involved.
func (*GitHubDork) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	v, ok := ctx.GetState("osint.github")
	if !ok {
		return nil, fmt.Errorf("osint.github not run")
	}
	res, _ := v.([]ghResult)
	imp := &attacks.Impact{Summary: fmt.Sprintf("%d GitHub code-search match(es)", totalItems(res))}
	for _, r := range res {
		if r.Count > 0 {
			imp.Add("query", fmt.Sprintf("%s: %d", r.Query, r.Count))
		}
	}
	return imp, nil
}

// totalItems sums the item counts across all query results for the summary.
func totalItems(res []ghResult) int {
	n := 0
	for _, r := range res {
		n += r.Count
	}
	return n
}

// Cleanup is a no-op.
func (*GitHubDork) Cleanup(ctx *attacks.AttackCtx) error { return nil }

var _ attacks.Module = (*GitHubDork)(nil)

package osint

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/qyvora/toha3ee/internal/attacks"
)

// Harvest extracts email addresses belonging to a target domain from search
// engine indexes. It compiles the addresses into a wordlist usable by later
// credential modules, so every name found is later testable against the org's
// own services.
type Harvest struct{}

// Meta implements attacks.Module.
func (*Harvest) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "osint.harvest",
		Category:    "osint",
		Risk:        attacks.RiskInfo,
		Targets:     []string{"domain"},
		Description: "harvest employee email addresses for a domain from search-engine indexes",
		Limitations: "returns only addresses that are publicly indexed; rate limits may truncate results",
	}
}

var emailRe = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)

type harvestResult struct {
	Domain  string
	Emails  []string
	Count   int
}

var harvestQueries = []func(string) string{
	func(d string) string { return "@" + d },
	func(d string) string { return "email @" + d + " site:" + d },
	func(d string) string { return "contact " + d },
	func(d string) string { return "staff " + d + " -site:" + d },
}

// Preflight needs a domain.
func (*Harvest) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	t, err := target(ctx, "osint.harvest", "domain")
	if err != nil {
		rep.AddFixable("domain", err.Error())
		return rep, nil
	}
	rep.AddOK("domain", t)
	return rep, nil
}

// Run queries the search index and extracts matching addresses.
func (*Harvest) Run(ctx *attacks.AttackCtx, opts map[string]string) error {
	d := ctx.Conf.Get("osint.harvest", "domain")
	if o, ok := opts["domain"]; ok && o != "" {
		d = o
	}
	timeout := ctx.Conf.GetDuration("osint.harvest", "timeout", 25*time.Second)
	seen := map[string]bool{}
	var emails []string
	for _, makeQ := range harvestQueries {
		q := makeQ(d)
		results, err := ddgResults(q, timeout)
		if err != nil {
			continue
		}
		for _, r := range results {
			for _, m := range emailRe.FindAllString(r, -1) {
				addr := strings.ToLower(m)
				if !strings.HasSuffix(addr, "@"+strings.ToLower(d)) {
					continue
				}
				if !seen[addr] {
					seen[addr] = true
					emails = append(emails, addr)
				}
			}
		}
	}
	ctx.SetState("osint.harvest", harvestResult{Domain: d, Emails: emails, Count: len(emails)})
	for _, e := range emails {
		emit(ctx, "finding", "osint.harvest: "+e)
	}
	ctx.Printf("[*] osint.harvest: %d address(es) for %s.\n", len(emails), d)
	return nil
}

// Verify reports the harvested addresses.
func (*Harvest) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	v, ok := ctx.GetState("osint.harvest")
	if !ok {
		return nil, fmt.Errorf("osint.harvest not run")
	}
	r, _ := v.(harvestResult)
	imp := &attacks.Impact{Summary: fmt.Sprintf("%d email address(es) for %s", r.Count, r.Domain)}
	for _, e := range r.Emails {
		imp.Add("email", e)
	}
	return imp, nil
}

// Cleanup is a no-op.
func (*Harvest) Cleanup(ctx *attacks.AttackCtx) error { return nil }

var _ attacks.Module = (*Harvest)(nil)

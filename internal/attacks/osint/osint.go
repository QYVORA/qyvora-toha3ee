// Package osint implements passive reconnaissance modules that make no direct
// contact with the target's infrastructure: DNS record enumeration, WHOIS/RDAP
// lookups and certificate-transparency subdomain discovery. They query public
// databases and resolvers only, so a target sees nothing but ordinary third-
// party traffic. Every module is read-only and safe to run under authorization
// in an engagement's passive phase.
package osint

import (
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/QYVORA/qyvora-toha3ee/internal/attacks"
	"github.com/QYVORA/qyvora-toha3ee/internal/stealth"
)

func init() {
	// Register every passive OSINT module so the framework can discover them
	// by ID (osint.asn, osint.ct, ...) without a central list to maintain.
	attacks.Register(&DNSEnum{})
	attacks.Register(&WHOIS{})
	attacks.Register(&CTLogs{})
	attacks.Register(&ASNEnum{})
	attacks.Register(&Shodan{})
	attacks.Register(&BucketEnum{})
	attacks.Register(&WaybackEnum{})
	attacks.Register(&GitHubDork{})
	attacks.Register(&HIBP{})
	attacks.Register(&Metadata{})
	attacks.Register(&Dork{})
	attacks.Register(&Harvest{})
}

// httpGet fetches a URL with a short timeout and a realistic browser agent so
// passive lookups are not fingerprinted as tool traffic. It enforces HTTP 200
// and caps the response body at 8 MiB — the public APIs queried here never
// legitimately exceed that, and the cap protects against runaway downloads.
func httpGet(url string, timeout time.Duration) ([]byte, error) {
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	// The shared stealth profile supplies a plausible browser UA, keeping
	// third-party OSINT endpoints (RIPE, crt.sh, HIBP, ...) from blocking us.
	req.Header.Set("User-Agent", stealth.Default.UserAgent())
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	// Any non-200 (rate-limit 429, auth 401/403, server 5xx) is surfaced as an
	// error rather than being parsed as an empty result set.
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned HTTP %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	return body, nil
}

// target returns the configured query target for a module namespace. It is the
// common preflight helper: a missing value yields a fixable, self-explanatory
// error that names the exact config key to set.
func target(ctx *attacks.AttackCtx, ns, key string) (string, error) {
	t := ctx.Conf.Get(ns, key)
	if t == "" {
		return "", fmt.Errorf("%s: set %s.%s first (e.g. 'set %s.%s example.com')", ns, ns, key, ns, key)
	}
	return t, nil
}

// readAllLimit reads up to n bytes from a reader, used to bound response-body
// reads on endpoints that have no Content-Length guarantee.
func readAllLimit(r io.Reader, n int64) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, n))
}

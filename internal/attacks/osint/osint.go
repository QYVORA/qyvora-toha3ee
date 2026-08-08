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
	"net"
	"net/http"
	"time"

	"github.com/qyvora/toha3ee/internal/attacks"
	"github.com/qyvora/toha3ee/internal/stealth"
)

func init() {
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
// passive lookups are not fingerprinted as tool traffic.
func httpGet(url string, timeout time.Duration) ([]byte, error) {
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", stealth.Default.UserAgent())
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned HTTP %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	return body, nil
}

// target returns the configured query target for a module namespace.
func target(ctx *attacks.AttackCtx, ns, key string) (string, error) {
	t := ctx.Conf.Get(ns, key)
	if t == "" {
		return "", fmt.Errorf("%s: set %s.%s first (e.g. 'set %s.%s example.com')", ns, ns, key, ns, key)
	}
	return t, nil
}

// isIP reports whether s parses as an IP address.
func isIP(s string) bool {
	return net.ParseIP(s) != nil
}

// readAllLimit reads up to n bytes from a reader.
func readAllLimit(r io.Reader, n int64) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, n))
}

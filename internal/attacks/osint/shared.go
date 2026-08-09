package osint

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// sha1Hex returns the uppercase-agnostic lowercase hex SHA-1 digest of s. It is
// used by the HIBP Pwned Passwords flow, which hashes candidate passwords with
// SHA-1 before splitting them for the k-anonymity range query.
func sha1Hex(s string) string {
	h := sha1.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

// authClient is an HTTP client that presents a bearer token, used for APIs that
// require authentication (GitHub, HIBP breach lookups).
type authClient struct {
	http  *http.Client
	token string
	agent string
}

// newAuthClient builds an authClient with the given token and a per-request
// timeout; the agent field is left empty so the get method applies its default.
func newAuthClient(token string, timeout time.Duration) *authClient {
	return &authClient{http: &http.Client{Timeout: timeout}, token: token}
}

// get performs an authenticated GET and returns the response body. The header
// setup is GitHub-specific: the token goes in "Authorization: token <t>" and
// the text-match media type asks GitHub to include match fragments in replies.
func (c *authClient) get(u string) ([]byte, error) {
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, err
	}
	// A per-client agent can be set, but default to a tool identifier so the
	// API sees something honest yet generic.
	req.Header.Set("User-Agent", c.agent)
	if c.agent == "" {
		req.Header.Set("User-Agent", "toha3ee/1.0")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "token "+c.token)
	}
	// text-match media type: code search only returns the fragment snippets we
	// rely on when this Accept header is present.
	req.Header.Set("Accept", "application/vnd.github.text-match+json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// Non-200 (401 bad token, 403 rate limit) is reported with the URL so
		// the failure is attributable to the exact endpoint hit.
		return nil, fmt.Errorf("GET %s returned HTTP %d", u, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 8<<20))
}

// urlQuery percent-encodes a string for safe inclusion as a query parameter.
func urlQuery(s string) string {
	return url.QueryEscape(s)
}

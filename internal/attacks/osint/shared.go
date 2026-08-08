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

func sha1Hex(s string) string {
	h := sha1.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

// authClient is an HTTP client that presents a bearer token, used for APIs that
// require authentication (GitHub, HIBP breach lookups).
type authClient struct {
	http    *http.Client
	token   string
	agent   string
}

func newAuthClient(token string, timeout time.Duration) *authClient {
	return &authClient{http: &http.Client{Timeout: timeout}, token: token}
}

// get performs an authenticated GET and returns the response body.
func (c *authClient) get(u string) ([]byte, error) {
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.agent)
	if c.agent == "" {
		req.Header.Set("User-Agent", "toha3ee/1.0")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "token "+c.token)
	}
	req.Header.Set("Accept", "application/vnd.github.text-match+json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s returned HTTP %d", u, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 8<<20))
}

func urlQuery(s string) string {
	return url.QueryEscape(s)
}

package selfupdate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

// Release is the subset of the GitHub Releases API payload the updater needs.
type Release struct {
	TagName    string  `json:"tag_name"`
	Draft      bool    `json:"draft"`
	Prerelease bool    `json:"prerelease"`
	Assets     []Asset `json:"assets"`
}

// Asset is a single downloadable release artifact.
type Asset struct {
	Name               string `json:"name"`
	Size               int64  `json:"size"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

// allowlistedHosts are the only hosts a release download may touch. The
// browser_download_url points at github.com and redirects to GitHub's object
// storage; anything else is refused before a connection is made.
var allowlistedHosts = map[string]bool{
	"github.com":                           true,
	"api.github.com":                       true,
	"objects.githubusercontent.com":        true,
	"release-assets.githubusercontent.com": true,
}

// newHTTPClient returns a client that refuses redirects leaving the official
// hosts, so a compromised redirect target cannot feed us bytes.
func newHTTPClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("too many redirects")
			}
			if !officialURL(req.URL) {
				return fmt.Errorf("refusing redirect to non-official host %q", req.URL.Host)
			}
			return nil
		},
	}
}

// apiToken returns an optional GitHub token for higher API rate limits. It is
// never logged and never attached to asset downloads.
func apiToken() string {
	if t := os.Getenv("GITHUB_TOKEN"); t != "" {
		return t
	}
	return os.Getenv("GH_TOKEN")
}

func (c Config) apiBase() string {
	if c.APIBaseURL != "" {
		return c.APIBaseURL
	}
	return apiBaseDefault
}

// fetchLatestRelease queries the official repository's latest published
// release. Network-level failures become KindNetwork, HTTP-level failures
// KindAPI or KindRateLimited; both leave any installed binary untouched.
func fetchLatestRelease(ctx context.Context, cfg Config) (*Release, error) {
	endpoint := fmt.Sprintf("%s/repos/%s/%s/releases/latest", cfg.apiBase(), cfg.Owner, cfg.Repo)
	parsed, err := url.Parse(endpoint)
	if err != nil || !officialURL(parsed) {
		return nil, &UpdateError{Kind: KindAPI, tool: cfg.ToolName, reason: "configured release endpoint is not HTTPS"}
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, &UpdateError{Kind: KindAPI, tool: cfg.ToolName, reason: "cannot build release request"}
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if tok := apiToken(); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}

	resp, err := newHTTPClient().Do(req)
	if err != nil {
		return nil, &UpdateError{Kind: KindNetwork, tool: cfg.ToolName, reason: "the official release service could not be reached", err: err}
	}
	defer resp.Body.Close() //nolint:errcheck // read-only stream

	switch resp.StatusCode {
	case http.StatusOK:
		// fall through to decoding
	case http.StatusNotFound:
		return nil, &UpdateError{Kind: KindAPI, tool: cfg.ToolName, reason: fmt.Sprintf("no releases are published under %s/%s yet", cfg.Owner, cfg.Repo)}
	case http.StatusForbidden, http.StatusTooManyRequests:
		return nil, &UpdateError{Kind: KindRateLimited, tool: cfg.ToolName, reason: "GitHub API rate limit reached; set GITHUB_TOKEN to raise it and retry later"}
	default:
		return nil, &UpdateError{Kind: KindAPI, tool: cfg.ToolName, reason: fmt.Sprintf("the official release service returned HTTP %d", resp.StatusCode)}
	}

	var release Release
	dec := json.NewDecoder(io.LimitReader(resp.Body, maxChecksumSize))
	if err := dec.Decode(&release); err != nil {
		return nil, &UpdateError{Kind: KindAPI, tool: cfg.ToolName, reason: "the official release service returned malformed metadata", err: err}
	}
	if release.TagName == "" {
		return nil, &UpdateError{Kind: KindAPI, tool: cfg.ToolName, reason: "the official release service returned no tag name"}
	}
	return &release, nil
}

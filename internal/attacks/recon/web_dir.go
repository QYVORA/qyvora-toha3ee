package recon

import (
	"bufio"
	"embed"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/QYVORA/qyvora-toha3ee/internal/attacks"
	"github.com/QYVORA/qyvora-toha3ee/internal/events"
	"github.com/QYVORA/qyvora-toha3ee/internal/netx/ports"
	"github.com/QYVORA/qyvora-toha3ee/internal/stealth"
)

//go:embed wordlists/*.txt
var wordlistFS embed.FS

// WebDir is a directory/file brute-forcer against discovered HTTP(S) services.
// It is deliberately light: the default wordlist is small and every request is
// paced through the stealth profile so the scan stays hard to fingerprint.
type WebDir struct{}

// Meta implements attacks.Module.
func (*WebDir) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "web.dir",
		Category:    "recon",
		Risk:        attacks.RiskLow,
		Targets:     []string{"service"},
		Description: "brute-force common web directories and files on discovered HTTP/HTTPS services",
		Limitations: "detection relies on status codes only (200/30x/401/403); servers returning 200 for missing paths cause false positives",
	}
}

// Preflight needs discovered hosts.
func (*WebDir) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	if len(ctx.Store.Hosts()) == 0 {
		rep.AddFixable("targets", "no hosts discovered; run net.scan first")
	} else {
		rep.AddOK("targets", fmt.Sprintf("%d host(s) available", len(ctx.Store.Hosts())))
	}
	// Validate a custom wordlist path up front; the default falls back to the
	// embedded common list.
	wordlist := ctx.Conf.Get("web.dir", "wordlist")
	if wordlist != "" && wordlist != "common" {
		if _, err := os.Open(wordlist); err != nil {
			rep.AddBlocked("wordlist", fmt.Sprintf("cannot read %s: %v", wordlist, err))
		} else {
			rep.AddOK("wordlist", wordlist)
		}
	} else {
		rep.AddOK("wordlist", "embedded common wordlist")
	}
	return rep, nil
}

// dirFinding is one interesting path discovered on a web service.
type dirFinding struct {
	Host string
	Port uint16
	Path string
	Code int
}

// Run walks the wordlist against every discovered HTTP/HTTPS service.
func (*WebDir) Run(ctx *attacks.AttackCtx, opts map[string]string) error {
	st := stealth.FromConfig(ctx.Conf, "web.dir")

	wordlist := ctx.Conf.Get("web.dir", "wordlist")
	if w, ok := opts["wordlist"]; ok && w != "" {
		wordlist = w
	}
	entries, err := loadWordlist(wordlist)
	if err != nil {
		return fmt.Errorf("web.dir: %w", err)
	}
	exts := splitList(ctx.Conf.Get("web.dir", "extensions"))
	timeout := ctx.Conf.GetDuration("web.dir", "timeout", 2*time.Second)
	// Redirects are not followed so a 30x is reported as-is rather than
	// chased to its landing page.
	client := &http.Client{Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	var findings []dirFinding
	total := 0
	for _, h := range ctx.Store.Hosts() {
		if len(h.OpenPorts()) == 0 {
			continue
		}
		for _, p := range h.OpenPorts() {
			svc := ports.GuessService(p)
			if svc != "http" && svc != "http-proxy" && svc != "https" && svc != "https-alt" {
				continue
			}
			scheme := "http"
			if p == 443 || p == 8443 {
				scheme = "https"
			}
			base := fmt.Sprintf("%s://%s", scheme, net.JoinHostPort(h.IP.String(), strconv.Itoa(int(p))))
			for _, e := range entries {
				for _, path := range expandExtensions(e, exts) {
					select {
					case <-ctx.Done:
						return nil
					default:
					}
					st.JitterSleep()
					url := base + "/" + path
					resp, err := client.Get(url)
					if err != nil {
						continue
					}
					// Read up to 8KB of the body to check for catch-all pages.
					body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
					_ = resp.Body.Close()
					total++
					bodyLen := len(body)
					// Interesting = exists (200), redirect, or protected
					// (401/403). A soft 404 would return 404 or a catch-all.
					if resp.StatusCode == 200 || (resp.StatusCode >= 301 && resp.StatusCode <= 308) || resp.StatusCode == 401 || resp.StatusCode == 403 {
						// A 200 with an empty body is likely a catch-all/soft-404.
						if resp.StatusCode == 200 && bodyLen == 0 {
							continue
						}
						findings = append(findings, dirFinding{Host: h.IP.String(), Port: p, Path: path, Code: resp.StatusCode})
						ctx.Emit(events.TopicLog, fmt.Sprintf("web.dir: %s:%d/%s [%d] (body %d bytes)", h.IP, p, path, resp.StatusCode, bodyLen), nil)
					}
				}
			}
		}
	}
	ctx.SetState("web.dir", findings)
	ctx.Printf("[*] web.dir complete: %d request(s), %d interesting path(s).\n", total, len(findings))
	return nil
}

// loadWordlist reads a wordlist one entry per line: the embedded common list
// for the default name, or an external file otherwise. Blank lines are
// skipped.
func loadWordlist(wordlist string) ([]string, error) {
	if wordlist == "" || wordlist == "common" {
		data, err := wordlistFS.ReadFile("wordlists/common.txt")
		if err != nil {
			return nil, fmt.Errorf("embedded wordlist: %w", err)
		}
		var out []string
		sc := bufio.NewScanner(strings.NewReader(string(data)))
		for sc.Scan() {
			if e := strings.TrimSpace(sc.Text()); e != "" {
				out = append(out, e)
			}
		}
		return out, nil
	}
	f, err := os.Open(wordlist)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if e := strings.TrimSpace(sc.Text()); e != "" {
			out = append(out, e)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// expandExtensions yields e itself plus e+ext for each configured extension
// when e has no extension of its own.
func expandExtensions(e string, exts []string) []string {
	out := []string{e}
	if len(exts) == 0 || strings.Contains(e, ".") {
		return out
	}
	for _, x := range exts {
		out = append(out, e+x)
	}
	return out
}

// splitList splits a comma-separated config value into trimmed, non-empty
// tokens.
func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// Verify reports the discovered paths.
func (*WebDir) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	v, ok := ctx.GetState("web.dir")
	if !ok {
		return nil, fmt.Errorf("web.dir not run")
	}
	findings, _ := v.([]dirFinding)
	imp := &attacks.Impact{Summary: fmt.Sprintf("found %d interesting web path(s)", len(findings))}
	imp.Add("requests", "see session log")
	imp.Add("findings", strconv.Itoa(len(findings)))
	for _, f := range findings {
		imp.Add("found", fmt.Sprintf("%s:%d/%s [%d]", f.Host, f.Port, f.Path, f.Code))
	}
	return imp, nil
}

// Cleanup is a no-op.
func (*WebDir) Cleanup(_ *attacks.AttackCtx) error {
	return nil
}

var _ attacks.Module = (*WebDir)(nil)

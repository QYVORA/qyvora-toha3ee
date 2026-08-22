// Package web holds web-application assessment modules.
package web

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/QYVORA/qyvora-toha3ee/internal/attacks"
	"github.com/QYVORA/qyvora-toha3ee/internal/netx/ports"
	"github.com/QYVORA/qyvora-toha3ee/internal/stealth"
)

func init() {
	attacks.Register(&Misconfig{})
}

// securityHeaders is the baseline set a hardened site should send.
var securityHeaders = []struct {
	name    string
	present string
}{
	{"Strict-Transport-Security", "HSTS (Strict-Transport-Security) missing"},
	{"Content-Security-Policy", "CSP (Content-Security-Policy) missing"},
	{"X-Content-Type-Options", "X-Content-Type-Options missing (MIME sniffing possible)"},
	{"X-Frame-Options", "X-Frame-Options missing (clickjacking risk)"},
	{"Referrer-Policy", "Referrer-Policy missing"},
}

// Misconfig checks web servers for common security misconfigurations:
// missing hardening headers, verbose version disclosure, directory listing and
// stack-trace leaks.
type Misconfig struct{}

// Meta implements attacks.Module.
func (*Misconfig) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "web.misconfig",
		Category:    "web",
		Risk:        attacks.RiskInfo,
		Targets:     []string{"service"},
		Description: "assess web servers for missing security headers, version disclosure, directory listing and verbose error pages",
		Limitations: "each check is a single HEAD/GET request; header-based checks can be defeated by edge caches",
	}
}

type misconfigFinding struct {
	Host    string
	Port    uint16
	Check   string
	Detail  string
	Finding bool
}

// Preflight needs discovered HTTP(S) services.
func (*Misconfig) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	n := 0
	for _, h := range ctx.Store.Hosts() {
		for _, p := range h.OpenPorts() {
			svc := ports.GuessService(p)
			if svc == "http" || svc == "http-proxy" || svc == "https" || svc == "https-alt" {
				n++
			}
		}
	}
	if n == 0 {
		rep.AddFixable("targets", "no HTTP(S) services discovered; run service.synscan/service.tcpconnect first")
	} else {
		rep.AddOK("targets", fmt.Sprintf("%d HTTP(S) service(s) discovered", n))
	}
	return rep, nil
}

// Run probes each discovered HTTP(S) service.
func (*Misconfig) Run(ctx *attacks.AttackCtx, _ map[string]string) error {
	st := stealth.FromConfig(ctx.Conf, "web.misconfig")
	timeout := ctx.Conf.GetDuration("web.misconfig", "timeout", 3*time.Second)
	client := &http.Client{Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	var findings []misconfigFinding
	checked := 0
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
			st.JitterSleep()
			resp, body, err := fetch(client, base)
			if err != nil {
				continue
			}
			checked++
			findings = append(findings, checkHeaders(h.IP.String(), p, resp)...)
			findings = append(findings, checkServer(h.IP.String(), p, resp)...)
			findings = append(findings, checkDirectoryListing(h.IP.String(), p, resp, body, base)...)
			findings = append(findings, checkVerboseError(client, st, h.IP.String(), p, base)...)
			_ = resp.Body.Close()
		}
	}
	ctx.SetState("web.misconfig", findings)
	nBad := 0
	for _, f := range findings {
		if f.Finding {
			nBad++
		}
	}
	ctx.Printf("[*] web.misconfig complete: %d service(s) checked, %d issue(s).\n", checked, nBad)
	return nil
}

func fetch(client *http.Client, base string) (*http.Response, []byte, error) {
	req, err := http.NewRequest("GET", base, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", "toha3ee")
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp, body, nil
}

func checkHeaders(host string, port uint16, resp *http.Response) []misconfigFinding {
	var out []misconfigFinding
	for _, h := range securityHeaders {
		if resp.Header.Get(h.name) == "" {
			out = append(out, misconfigFinding{Host: host, Port: port, Check: "header", Detail: h.present, Finding: true})
		}
	}
	return out
}

func checkServer(host string, port uint16, resp *http.Response) []misconfigFinding {
	var out []misconfigFinding
	server := resp.Header.Get("Server")
	via := resp.Header.Get("Via")
	if strings.TrimSpace(server) != "" {
		// Any version token ("nginx/1.24.0") is disclosure.
		if strings.ContainsAny(server, "/0123456789") {
			out = append(out, misconfigFinding{Host: host, Port: port, Check: "banner", Detail: "Server discloses version: " + server, Finding: true})
		}
	}
	if strings.TrimSpace(via) != "" {
		out = append(out, misconfigFinding{Host: host, Port: port, Check: "banner", Detail: "Via proxy banner: " + via, Finding: true})
	}
	return out
}

func checkDirectoryListing(host string, port uint16, resp *http.Response, body []byte, base string) []misconfigFinding {
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		return nil
	}
	low := strings.ToLower(string(body))
	if strings.Contains(low, "index of /") || strings.Contains(low, "directory listing") {
		return []misconfigFinding{{Host: host, Port: port, Check: "listing", Detail: "directory listing enabled at " + base, Finding: true}}
	}
	return nil
}

func checkVerboseError(client *http.Client, st *stealth.Config, host string, port uint16, base string) []misconfigFinding {
	st.JitterSleep()
	req, err := http.NewRequest("GET", base+"/%00", nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "toha3ee")
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	low := strings.ToLower(string(body))
	var leak string
	switch {
	case strings.Contains(low, "traceback"):
		leak = "Python traceback leaked"
	case strings.Contains(low, "stack trace"):
		leak = "stack trace leaked"
	case strings.Contains(low, "server error in '"):
		leak = "classic ASP error page"
	case strings.Contains(low, "java.lang"):
		leak = "Java exception leaked"
	case strings.Contains(low, "at ") && strings.Contains(low, ".cs("):
		leak = ".NET stack leaked"
	}
	if leak != "" {
		return []misconfigFinding{{Host: host, Port: port, Check: "verbose_error", Detail: leak + " at " + base, Finding: true}}
	}
	return nil
}

// Verify reports the issues found.
func (*Misconfig) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	v, ok := ctx.GetState("web.misconfig")
	if !ok {
		return nil, fmt.Errorf("web.misconfig not run")
	}
	findings, _ := v.([]misconfigFinding)
	nBad := 0
	for _, f := range findings {
		if f.Finding {
			nBad++
		}
	}
	imp := &attacks.Impact{Summary: fmt.Sprintf("found %d web misconfiguration issue(s)", nBad)}
	imp.Add("issues", strconv.Itoa(nBad))
	for _, f := range findings {
		imp.Add(f.Check, fmt.Sprintf("%s:%d %s", f.Host, f.Port, f.Detail))
	}
	return imp, nil
}

// Cleanup is a no-op.
func (*Misconfig) Cleanup(_ *attacks.AttackCtx) error { return nil }

var _ attacks.Module = (*Misconfig)(nil)

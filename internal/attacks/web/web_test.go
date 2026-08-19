package web

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/QYVORA/qyvora-toha3ee/internal/attacks"
	"github.com/QYVORA/qyvora-toha3ee/internal/config"
	"github.com/QYVORA/qyvora-toha3ee/internal/events"
	"github.com/QYVORA/qyvora-toha3ee/internal/safety"
	"github.com/QYVORA/qyvora-toha3ee/internal/stealth"
	"github.com/QYVORA/qyvora-toha3ee/internal/store"
)

// testCtx builds an AttackCtx with an empty store, so Preflight reports that
// no HTTP(S) targets have been discovered.
func testCtx() (*attacks.AttackCtx, chan struct{}) {
	done := make(chan struct{})
	return &attacks.AttackCtx{
		ID:      "test",
		Bus:     events.NewBus(),
		Conf:    config.Default(),
		Store:   store.New(128),
		Safety:  safety.NewManager(events.NewBus(), slog.New(slog.NewTextHandler(io.Discard, nil))),
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		Out:     io.Discard,
		Done:    done,
		State:   &sync.Map{},
		Targets: nil,
	}, done
}

func get(t *testing.T, srv *httptest.Server, path string) (*http.Response, []byte) {
	t.Helper()
	client := srv.Client()
	resp, err := client.Get(srv.URL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp, body
}

func TestCheckHeadersFlagsMissingSecurityHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.24.0")
	}))
	defer srv.Close()
	resp, _ := get(t, srv, "/")
	findings := checkHeaders("10.0.0.1", 80, resp)
	if len(findings) != len(securityHeaders) {
		t.Fatalf("got %d header findings, want %d", len(findings), len(securityHeaders))
	}
	seen := map[string]bool{}
	for _, f := range findings {
		if f.Check != "header" || !f.Finding {
			t.Errorf("unexpected finding %+v", f)
		}
		seen[f.Detail] = true
	}
	if !seen["HSTS (Strict-Transport-Security) missing"] {
		t.Error("HSTS finding missing")
	}
	if !seen["CSP (Content-Security-Policy) missing"] {
		t.Error("CSP finding missing")
	}
}

func TestCheckHeadersPresentHeadersNotFlagged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
	}))
	defer srv.Close()
	resp, _ := get(t, srv, "/")
	if findings := checkHeaders("10.0.0.1", 80, resp); len(findings) != 0 {
		t.Errorf("expected no findings, got %+v", findings)
	}
}

func TestCheckServerVersionDisclosure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.24.0")
		w.Header().Set("Via", "1.1 varnish")
	}))
	defer srv.Close()
	resp, _ := get(t, srv, "/")
	findings := checkServer("10.0.0.1", 80, resp)
	if len(findings) != 2 {
		t.Fatalf("got %d banner findings, want 2: %+v", len(findings), findings)
	}
	if !strings.Contains(findings[0].Detail, "nginx/1.24.0") {
		t.Errorf("server banner not flagged: %+v", findings[0])
	}
}

func TestCheckServerBareProductNameNotVersion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
	}))
	defer srv.Close()
	resp, _ := get(t, srv, "/")
	if findings := checkServer("10.0.0.1", 80, resp); len(findings) != 0 {
		t.Errorf("bare product name without version should not be flagged: %+v", findings)
	}
}

func TestCheckDirectoryListing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<h1>Index of /var/www</h1><ul><li>secret.tgz</li></ul>")
	}))
	defer srv.Close()
	resp, body := get(t, srv, "/")
	findings := checkDirectoryListing("10.0.0.1", 80, resp, body, srv.URL)
	if len(findings) != 1 || findings[0].Check != "listing" {
		t.Fatalf("directory listing not flagged: %+v", findings)
	}
	if !strings.Contains(findings[0].Detail, srv.URL) {
		t.Errorf("listing detail missing path: %+v", findings[0])
	}
}

func TestCheckDirectoryListingNonHTMLIgnored(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "Index of / (Apache/2.4.41 (Ubuntu) Server at 10.0.0.1)")
	}))
	defer srv.Close()
	resp, body := get(t, srv, "/")
	if findings := checkDirectoryListing("10.0.0.1", 80, resp, body, srv.URL); len(findings) != 0 {
		t.Errorf("non-HTML response should not be flagged: %+v", findings)
	}
}

func TestCheckVerboseErrorStackTrace(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "<pre>Exception in thread \"main\" java.lang.NullPointerException\n        at com.example.App.run(App.java:42)</pre>")
	}))
	defer srv.Close()
	ctx, _ := testCtx()
	st := stealth.FromConfig(ctx.Conf, "web.misconfig")
	findings := checkVerboseError(srv.Client(), st, "10.0.0.1", 80, srv.URL)
	if len(findings) != 1 {
		t.Fatalf("verbose error not flagged: %+v", findings)
	}
	if !strings.Contains(findings[0].Detail, "Java exception") {
		t.Errorf("wrong leak detail: %+v", findings[0])
	}
}

func TestCheckVerboseErrorCleanPage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "<html><body>404 Not Found</body></html>")
	}))
	defer srv.Close()
	ctx, _ := testCtx()
	st := stealth.FromConfig(ctx.Conf, "web.misconfig")
	if findings := checkVerboseError(srv.Client(), st, "10.0.0.1", 80, srv.URL); len(findings) != 0 {
		t.Errorf("clean 404 should not be flagged: %+v", findings)
	}
}

func TestPreflightReportsNoTargets(t *testing.T) {
	ctx, _ := testCtx()
	rep, err := (&Misconfig{}).Preflight(ctx)
	if err != nil {
		t.Fatalf("Preflight: %v", err)
	}
	var fixable bool
	for _, c := range rep.Checks {
		if c.Name == "targets" && c.Status == safety.StatusFixable {
			fixable = true
		}
	}
	if !fixable {
		t.Errorf("expected a fixable 'targets' finding, got %+v", rep.Checks)
	}
}

func TestMetaMatchesModuleContract(t *testing.T) {
	m := (&Misconfig{}).Meta()
	if m.ID != "web.misconfig" || m.Category != "web" || m.Risk != attacks.RiskInfo {
		t.Errorf("unexpected meta %+v", m)
	}
}

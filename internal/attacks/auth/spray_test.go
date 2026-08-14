package auth

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/QYVORA/qyvora-toha3ee/internal/store"
)

func TestPasswordSprayFindsValid(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if ok && user == "jdoe" && pass == "Spring2026" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="portal"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	addr := srv.Listener.Addr().(*net.TCPAddr)

	db := store.New(100)
	db.UpsertHost(hostWithPort("127.0.0.1", uint16(addr.Port)))
	ctx, _ := testCtx(db)
	ctx.Conf.Settings["auth.spray"] = map[string]string{
		"ports":    strconv.Itoa(addr.Port),
		"password": "Spring2026",
		"users":    "alice,bob,jdoe",
	}

	m := &PasswordSpray{}
	if err := m.Run(ctx, nil); err != nil {
		t.Fatalf("run: %v", err)
	}
	creds := db.CredsBySource("auth.spray")
	if len(creds) != 1 {
		t.Fatalf("expected 1 cred, got %d", len(creds))
	}
	if creds[0].Username != "jdoe" || creds[0].Password != "Spring2026" {
		t.Fatalf("wrong cred: %+v", creds[0])
	}
}

func TestSprayUsersFallback(t *testing.T) {
	db := store.New(100)
	ctx, _ := testCtx(db)
	users, err := sprayUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) < 3 {
		t.Errorf("expected default user fallback, got %v", users)
	}
}

func TestReadLines(t *testing.T) {
	f := t.TempDir() + "/users.txt"
	if err := writeLines(f, []string{"root", "", "admin", "  bob  "}); err != nil {
		t.Fatal(err)
	}
	lines, err := readLines(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 3 {
		t.Fatalf("got %v", lines)
	}
	if lines[2] != "bob" {
		t.Errorf("lines not trimmed: %v", lines)
	}
}

func writeLines(path string, lines []string) error {
	var b strings.Builder
	for _, l := range lines {
		b.WriteString(l + "\n")
	}
	return os.WriteFile(path, []byte(b.String()), 0o600)
}

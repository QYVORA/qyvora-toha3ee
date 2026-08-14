package session

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func sampleReport() *Report {
	return &Report{
		Generated: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		Running:   []string{"arp.spoof"},
		Hosts: []reportHost{
			{IP: "192.168.1.10", MAC: "aa:bb:cc:dd:ee:ff", Vendor: "Acme", Ports: map[uint16]string{80: "http"}},
		},
		Creds: []reportCred{
			{ID: 1, Service: "http", Username: "alice", Password: "s3cret", Host: "192.168.1.10", VictimIP: "192.168.1.10", Source: "http.harvest"},
		},
		Sessions: []reportSession{
			{ID: 7, VictimIP: "192.168.1.10", Host: "mail", Cookies: map[string]string{"sid": "abc"}, Auth: "Bearer x"},
		},
		Events: []reportEvent{
			{Time: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), Topic: "scan.started", Msg: "begin"},
		},
	}
}

func TestRenderJSONKeepsPlaintextCredentials(t *testing.T) {
	data, err := sampleReport().RenderJSON()
	if err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}
	if !strings.Contains(string(data), `"s3cret"`) {
		t.Error("JSON report must keep plaintext credentials (machine format)")
	}
}

func TestRenderTerminalRedactsPasswords(t *testing.T) {
	out := sampleReport().RenderTerminal()
	if strings.Contains(out, "s3cret") {
		t.Error("terminal report leaked a plaintext password")
	}
	if !strings.Contains(out, "<redacted>") {
		t.Error("terminal report should mark redacted credentials")
	}
	if !strings.Contains(out, "192.168.1.10") {
		t.Error("terminal report missing host data")
	}
}

func TestRenderMarkdownRedactsPasswords(t *testing.T) {
	out := sampleReport().RenderMarkdown()
	if strings.Contains(out, "s3cret") {
		t.Error("markdown report leaked a plaintext password")
	}
	if !strings.Contains(out, "| 1 | http | alice | 192.168.1.10 | http.harvest |") {
		t.Error("markdown credentials table missing expected row")
	}
}

func TestLoadReportRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	if err := writeReport(path, sampleReport()); err != nil {
		t.Fatalf("writeReport: %v", err)
	}
	rep, err := LoadReport(path)
	if err != nil {
		t.Fatalf("LoadReport: %v", err)
	}
	if len(rep.Creds) != 1 || rep.Creds[0].Username != "alice" {
		t.Errorf("round-trip creds = %+v", rep.Creds)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("report file mode = %v, want 0600", info.Mode().Perm())
	}
}

func TestLoadReportMissing(t *testing.T) {
	if _, err := LoadReport(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Error("LoadReport of a missing file should error")
	}
}

// TestRunArgsAcceptsCapletSuffix verifies "on <file>.caplet" resolves to the
// caplet runner exactly like the legacy ".cap" spelling.
func TestRunArgsAcceptsCapletSuffix(t *testing.T) {
	s, _ := newTestSession(t)
	for _, id := range []string{"missing.caplet", "missing.cap"} {
		err := s.runArgs([]string{id})
		if err == nil {
			t.Errorf("runArgs(%q) should error on a missing caplet", id)
		}
		if !strings.Contains(err.Error(), "not found") {
			t.Errorf("runArgs(%q) = %v, want a caplet-not-found error", id, err)
		}
	}
}

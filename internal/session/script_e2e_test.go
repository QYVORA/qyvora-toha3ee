package session

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestScriptPipelineEndToEnd drives the real script engine through the
// Session-backed Runner: parse a ".toha3ee" file, mutate config, interpolate
// live session properties, write a report and read it back. It never touches
// the network, so it runs anywhere.
func TestScriptPipelineEndToEnd(t *testing.T) {
	s, buf := newTestSession(t)
	dir := t.TempDir()
	reportPath := filepath.Join(dir, "report.json")

	script := `# full pipeline (offline)
set net.scan.timeout -> "3s"
echo -> "framework $(version) iface $(iface.name)"
_hosts -> [$(net.hosts)]
echo -> "hosts=$(_hosts.size) running=$(running.count)"
report '` + reportPath + `'
`

	if err := s.RunScript(writeScript(t, script)); err != nil {
		t.Fatalf("RunScript: %v\noutput:\n%s", err, buf.String())
	}

	// echo lines must have hit the console with interpolated values.
	out := buf.String()
	if !strings.Contains(out, "framework "+Version) {
		t.Errorf("version not interpolated, output:\n%s", out)
	}
	if !strings.Contains(out, "hosts=") || !strings.Contains(out, "running=0") {
		t.Errorf("live counters not interpolated, output:\n%s", out)
	}

	// The report command inside the script must have produced a readable file.
	rep, err := LoadReport(reportPath)
	if err != nil {
		t.Fatalf("LoadReport after script: %v", err)
	}
	if !rep.Generated.IsZero() {
		t.Logf("report generated at %s", rep.Generated)
	}

	// Config writes from the script must be visible on the session.
	if got := s.Conf.Get("net.scan", "timeout"); got != "3s" {
		t.Errorf("script set net.scan.timeout = %q, want 3s", got)
	}
}

// TestScriptPipelineConfigRoundTrip exercises set/get through the runner and
// verifies a script cannot run an unknown module.
func TestScriptPipelineConfigRoundTrip(t *testing.T) {
	s, buf := newTestSession(t)
	script := `set arp.spoof.targets -> "10.0.0.5,10.0.0.6"
echo -> "targets=$(config.arp.spoof.targets)"
`
	if err := s.RunScript(writeScript(t, script)); err != nil {
		t.Fatalf("RunScript: %v\noutput:\n%s", err, buf.String())
	}
	if !strings.Contains(buf.String(), "targets=10.0.0.5,10.0.0.6") {
		t.Errorf("config interpolation failed, output:\n%s", buf.String())
	}
}

// TestScriptPipelineUnknownModuleFails ensures a script typo surfaces as an
// error instead of being silently ignored.
func TestScriptPipelineUnknownModuleFails(t *testing.T) {
	s, _ := newTestSession(t)
	script := "on net.nosuchmodule\n"
	err := s.RunScript(writeScript(t, script))
	if err == nil {
		t.Fatal("expected an error for an unknown module")
	}
	if !strings.Contains(err.Error(), "nosuchmodule") {
		t.Errorf("error should name the module, got %v", err)
	}
}

func writeScript(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "e2e.toha3ee")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

package selfupdate

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// fakeHub is a local stand-in for the official QYVORA GitHub Releases API. It
// serves exactly the endpoints the updater is allowed to contact and records
// every request so tests can assert that no unnecessary downloads occur.
type fakeHub struct {
	srv        *httptest.Server
	mu         sync.Mutex
	requests   []string
	latestJSON []byte
	files      map[string][]byte // asset name -> served bytes
	statusCode int               // override for the /releases/latest endpoint
}

func newFakeHub(t *testing.T) *fakeHub {
	t.Helper()
	h := &fakeHub{files: map[string][]byte{}, statusCode: http.StatusOK}
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/QYVORA/qyvora-test/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		h.record(r.URL.Path)
		if h.statusCode != http.StatusOK {
			w.WriteHeader(h.statusCode)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(h.latestJSON)
	})
	mux.HandleFunc("/download/", func(w http.ResponseWriter, r *http.Request) {
		h.record(r.URL.Path)
		name := strings.TrimPrefix(r.URL.Path, "/download/")
		data, ok := h.files[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(data)
	})
	mux.HandleFunc("/redirect/", func(w http.ResponseWriter, r *http.Request) {
		h.record(r.URL.Path)
		http.Redirect(w, r, "https://evil.example.com/payload", http.StatusFound)
	})
	h.srv = httptest.NewServer(mux)
	t.Cleanup(h.srv.Close)
	return h
}

func (h *fakeHub) record(path string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.requests = append(h.requests, path)
}

func (h *fakeHub) hits(prefix string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, p := range h.requests {
		if strings.HasPrefix(p, prefix) {
			n++
		}
	}
	return n
}

// publish installs a release with one raw-binary asset per supported
// platform plus a SHA256SUMS manifest, mimicking the real pipelines.
func (h *fakeHub) publish(tag string, payloadFor func(goos, goarch string) []byte) {
	names := make([]string, 0, 6)
	for _, goos := range []string{"linux", "darwin", "windows"} {
		for _, goarch := range []string{"amd64", "arm64"} {
			name := fmt.Sprintf("tool-%s-%s", goos, goarch)
			if goos == "windows" {
				name += ".exe"
			}
			h.files[name] = payloadFor(goos, goarch)
			names = append(names, name)
		}
	}

	var manifest strings.Builder
	payload := h.files[names[0]]
	sum := sha256.Sum256(payload)
	_ = sum
	for _, name := range names {
		s := sha256.Sum256(h.files[name])
		fmt.Fprintf(&manifest, "%s  %s\n", hex.EncodeToString(s[:]), name)
	}
	h.files["SHA256SUMS"] = []byte(manifest.String())

	type asset struct {
		Name               string `json:"name"`
		Size               int64  `json:"size"`
		BrowserDownloadURL string `json:"browser_download_url"`
	}
	var assets = make([]asset, 0, len(names)+1)
	for _, name := range append(names, "SHA256SUMS") {
		assets = append(assets, asset{
			Name:               name,
			Size:               int64(len(h.files[name])),
			BrowserDownloadURL: h.srv.URL + "/download/" + name,
		})
	}
	body, _ := json.Marshal(map[string]any{
		"tag_name":   tag,
		"draft":      false,
		"prerelease": false,
		"assets":     assets,
	})
	h.latestJSON = body
}

// testConfig wires a Config to the fake hub with the running platform mapped
// deterministically and a fake executable inside dir.
func testConfig(h *fakeHub, currentVersion, exePath string) Config {
	return Config{
		Owner:          "QYVORA",
		Repo:           "qyvora-test",
		ToolName:       "testtool",
		CurrentVersion: func() string { return currentVersion },
		ArtifactName: func(goos, goarch string) string {
			name := fmt.Sprintf("tool-%s-%s", goos, goarch)
			if goos == "windows" {
				name += ".exe"
			}
			return name
		},
		ChecksumAsset:  func(string) string { return "SHA256SUMS" },
		ArchiveFor:     func(string, string) (ArchiveKind, string) { return ArchiveNone, "" },
		APIBaseURL:     h.srv.URL,
		ExecutablePath: func() (string, error) { return exePath, nil },
	}
}

// TestRunArchivedArtifactInstallsEntry exercises the TOHA3EE-style flow: the
// release asset is a tar.gz whose payload must be extracted before install.
func TestRunArchivedArtifactInstallsEntry(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("archive fixture builds a tar.gz; windows pipeline uses zip")
	}
	h := newFakeHub(t)

	dir := t.TempDir()
	bin := filepath.Join(dir, "tool")
	payload := []byte("archived-binary-payload")
	if err := os.WriteFile(bin, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	_ = tw.WriteHeader(&tar.Header{Name: "tool", Mode: 0o755, Size: int64(len(payload))})
	_, _ = tw.Write(payload)
	_ = tw.Close()
	_ = gz.Close()

	artifact := fmt.Sprintf("tool-%s-%s.tar.gz", runtime.GOOS, runtime.GOARCH)
	sum := sha256.Sum256(buf.Bytes())
	h.files[artifact] = buf.Bytes()
	h.files["SHA256SUMS"] = []byte(fmt.Sprintf("%s  %s\n", hex.EncodeToString(sum[:]), artifact))

	type asset struct {
		Name               string `json:"name"`
		Size               int64  `json:"size"`
		BrowserDownloadURL string `json:"browser_download_url"`
	}
	body, _ := json.Marshal(map[string]any{
		"tag_name": "v2.0.0",
		"assets":   []asset{{Name: artifact, Size: int64(buf.Len()), BrowserDownloadURL: h.srv.URL + "/download/" + artifact}, {Name: "SHA256SUMS", Size: int64(len(h.files["SHA256SUMS"])), BrowserDownloadURL: h.srv.URL + "/download/SHA256SUMS"}},
	})
	h.latestJSON = body

	cfg := testConfig(h, "v1.0.0", bin)
	cfg.ArtifactName = func(goos, goarch string) string {
		return fmt.Sprintf("tool-%s-%s.tar.gz", goos, goarch)
	}
	cfg.ArchiveFor = func(_, _ string) (ArchiveKind, string) {
		return ArchiveTarGz, "tool"
	}

	out := &bytes.Buffer{}
	res, err := Run(context.Background(), cfg, Options{Out: out})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Status != StatusUpdated {
		t.Fatalf("status = %d", res.Status)
	}
	got, rerr := os.ReadFile(bin)
	if rerr != nil || string(got) != string(payload) {
		t.Fatalf("installed binary = %q (err %v), want %q", got, rerr, payload)
	}
	if left := leftoverTemps(dir); len(left) != 0 {
		t.Fatalf("temps left behind: %v", left)
	}
}

func writeInstalledBinary(t *testing.T, content string, mode fs.FileMode) (dir, path string) {
	t.Helper()
	dir = t.TempDir()
	path = filepath.Join(dir, "tool")
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return dir, path
}

func leftoverTemps(dir string) []string {
	entries, _ := os.ReadDir(dir)
	var found []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".testtool-") || strings.HasPrefix(e.Name(), ".qyvora-update-probe-") {
			found = append(found, e.Name())
		}
	}
	return found
}

func TestRunAlreadyUpToDateSkipsDownload(t *testing.T) {
	h := newFakeHub(t)
	h.publish("v1.2.0", func(g, a string) []byte { return []byte("payload-" + g + "-" + a) })

	dir, bin := writeInstalledBinary(t, "old-bytes", 0o755)
	cfg := testConfig(h, "v1.2.0", bin)

	res, err := Run(context.Background(), cfg, Options{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Status != StatusCurrent {
		t.Fatalf("status = %d, want StatusCurrent", res.Status)
	}
	if got, _ := os.ReadFile(bin); string(got) != "old-bytes" {
		t.Fatalf("binary was modified: %q", got)
	}
	if n := h.hits("/download/"); n != 0 {
		t.Fatalf("up-to-date check downloaded %d artifacts, want 0", n)
	}
	if left := leftoverTemps(dir); len(left) != 0 {
		t.Fatalf("temp files left behind: %v", left)
	}
}

func TestRunNewVersionInstallsVerifiedArtifact(t *testing.T) {
	h := newFakeHub(t)
	h.publish("v1.3.0", func(g, a string) []byte { return []byte("NEW-" + g + "-" + a) })

	wantMode := fs.FileMode(0o755)
	dir, bin := writeInstalledBinary(t, "old", wantMode)
	cfg := testConfig(h, "1.2.0", bin) // bare number must compare fine

	out := &bytes.Buffer{}
	res, err := Run(context.Background(), cfg, Options{Out: out})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Status != StatusUpdated || res.Latest != "v1.3.0" || res.Path != bin {
		t.Fatalf("unexpected result: %+v", res)
	}

	got, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	want := "NEW-" + runtime.GOOS + "-" + runtime.GOARCH
	if string(got) != want {
		t.Fatalf("installed %q, want %q", got, want)
	}
	info, _ := os.Stat(bin)
	if info.Mode().Perm() != wantMode {
		t.Fatalf("mode = %v, want preserved %v", info.Mode().Perm(), wantMode)
	}
	for _, phrase := range []string{
		"Checking for updates...", "Latest version: v1.3.0",
		"Update available:", "Downloading testtool v1.3.0...",
		"✓ Download complete", "✓ Artifact verified", "✓ Binary installed",
		"testtool has been updated to v1.3.0.",
	} {
		if !strings.Contains(out.String(), phrase) {
			t.Errorf("output missing canonical phrase %q; output:\n%s", phrase, out.String())
		}
	}
	if left := leftoverTemps(dir); len(left) != 0 {
		t.Fatalf("temp files left behind: %v", left)
	}
	if res.Artifact != fmt.Sprintf("tool-%s-%s", runtime.GOOS, runtime.GOARCH) &&
		res.Artifact != fmt.Sprintf("tool-%s-%s.exe", runtime.GOOS, runtime.GOARCH) {
		t.Fatalf("selected wrong artifact %q", res.Artifact)
	}
}

func TestRunDowngradeRefused(t *testing.T) {
	h := newFakeHub(t)
	h.publish("v1.3.0", func(_, _ string) []byte { return []byte("x") })

	_, bin := writeInstalledBinary(t, "newer-build", 0o755)
	cfg := testConfig(h, "v1.4.0", bin)

	res, err := Run(context.Background(), cfg, Options{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Status != StatusNewerInstalled {
		t.Fatalf("status = %d, want StatusNewerInstalled", res.Status)
	}
	if got, _ := os.ReadFile(bin); string(got) != "newer-build" {
		t.Fatal("downgrade overwrote the newer installed binary")
	}
	if n := h.hits("/download/"); n != 0 {
		t.Fatalf("refused downgrade still downloaded %d files", n)
	}
}

func TestRunChecksumMismatchAbortsCleanly(t *testing.T) {
	h := newFakeHub(t)
	h.publish("v1.3.0", func(_, _ string) []byte { return []byte("payload") })
	// Corrupt the manifest so verification must fail: valid entries, wrong
	// digests.
	var bogus strings.Builder
	for _, goos := range []string{"linux", "darwin", "windows"} {
		for _, goarch := range []string{"amd64", "arm64"} {
			name := fmt.Sprintf("tool-%s-%s", goos, goarch)
			if goos == "windows" {
				name += ".exe"
			}
			fmt.Fprintf(&bogus, "%s  %s\n", strings.Repeat("00", 32), name)
		}
	}
	h.files["SHA256SUMS"] = []byte(bogus.String())

	dir, bin := writeInstalledBinary(t, "original", 0o755)
	cfg := testConfig(h, "v1.2.0", bin)

	_, err := Run(context.Background(), cfg, Options{})
	var ue *UpdateError
	if err == nil {
		t.Fatal("expected checksum failure")
	}
	if !asUpdateError(err, &ue) || ue.Kind != KindChecksumMismatch {
		t.Fatalf("got %v (%T), want KindChecksumMismatch", err, err)
	}
	if got, _ := os.ReadFile(bin); string(got) != "original" {
		t.Fatal("failed verification still replaced the binary")
	}
	if left := leftoverTemps(dir); len(left) != 0 {
		t.Fatalf("dangerous temp files left behind after failure: %v", left)
	}
}

func TestRunNetworkFailureLeavesBinaryUntouched(t *testing.T) {
	h := newFakeHub(t)
	h.publish("v1.3.0", func(_, _ string) []byte { return []byte("x") })
	url := h.srv.URL
	h.srv.Close() // simulate total connectivity loss

	dir, bin := writeInstalledBinary(t, "keep-me", 0o755)
	cfg := testConfig(h, "v1.2.0", bin)
	cfg.APIBaseURL = url

	_, err := Run(context.Background(), cfg, Options{})
	var ue *UpdateError
	if err == nil || !asUpdateError(err, &ue) || ue.Kind != KindNetwork {
		t.Fatalf("got %v, want KindNetwork", err)
	}
	if got, _ := os.ReadFile(bin); string(got) != "keep-me" {
		t.Fatal("network failure modified the installed binary")
	}
	if left := leftoverTemps(dir); len(left) != 0 {
		t.Fatalf("temps left behind: %v", left)
	}
}

func TestRunMissingManifestFailsClosed(t *testing.T) {
	h := newFakeHub(t)
	h.publish("v1.3.0", func(_, _ string) []byte { return []byte("x") })
	delete(h.files, "SHA256SUMS")

	dir, bin := writeInstalledBinary(t, "original", 0o755)
	cfg := testConfig(h, "v1.2.0", bin)

	_, err := Run(context.Background(), cfg, Options{})
	var ue *UpdateError
	if err == nil || !asUpdateError(err, &ue) {
		t.Fatalf("got %v, want UpdateError", err)
	}
	if ue.Kind != KindVerificationUnavailable && ue.Kind != KindPlatform && ue.Kind != KindAPI {
		t.Fatalf("unexpected kind %q", ue.Kind)
	}
	if got, _ := os.ReadFile(bin); string(got) != "original" {
		t.Fatal("unverifiable release replaced the binary")
	}
	if left := leftoverTemps(dir); len(left) != 0 {
		t.Fatalf("temps left behind: %v", left)
	}
}

func TestRunUnsupportedPlatformReportsCleanly(t *testing.T) {
	h := newFakeHub(t)
	h.publish("v1.3.0", func(_, _ string) []byte { return []byte("x") })

	_, bin := writeInstalledBinary(t, "old", 0o755)
	cfg := testConfig(h, "v1.2.0", bin)
	cfg.ArtifactName = func(string, string) string { return "" }

	_, err := Run(context.Background(), cfg, Options{})
	var ue *UpdateError
	if err == nil || !asUpdateError(err, &ue) || ue.Kind != KindPlatform {
		t.Fatalf("got %v, want KindPlatform", err)
	}
	want := fmt.Sprintf("No release exists for %s/%s.", runtime.GOOS, runtime.GOARCH)
	if ue.Error() != want {
		t.Fatalf("message %q, want %q", ue.Error(), want)
	}
	if n := h.hits("/download/"); n != 0 {
		t.Fatal("unsupported platform triggered downloads")
	}
}

func TestRunDevBuildRefusedWithoutNetwork(t *testing.T) {
	h := newFakeHub(t)
	h.publish("v1.3.0", func(_, _ string) []byte { return []byte("x") })

	_, bin := writeInstalledBinary(t, "old", 0o755)
	cfg := testConfig(h, "dev", bin)

	_, err := Run(context.Background(), cfg, Options{})
	var ue *UpdateError
	if err == nil || !asUpdateError(err, &ue) || ue.Kind != KindDevBuild {
		t.Fatalf("got %v, want KindDevBuild", err)
	}
	if len(h.requests) != 0 {
		t.Fatal("dev build contacted the network")
	}
}

func TestRunPermissionFailureIsClean(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses permission failures")
	}
	if runtime.GOOS == "windows" {
		t.Skip("chmod-based permission model does not apply on windows")
	}
	h := newFakeHub(t)
	h.publish("v1.3.0", func(_, _ string) []byte { return []byte("payload") })

	dir, bin := writeInstalledBinary(t, "old", 0o755)
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	cfg := testConfig(h, "v1.2.0", bin)
	_, err := Run(context.Background(), cfg, Options{})
	var ue *UpdateError
	if err == nil || !asUpdateError(err, &ue) || ue.Kind != KindPermission {
		t.Fatalf("got %v, want KindPermission", err)
	}
	if ue.Path() != bin {
		t.Fatalf("error path = %q, want %q", ue.Path(), bin)
	}
	if got, _ := os.ReadFile(bin); string(got) != "old" {
		t.Fatal("permission failure modified the binary")
	}
}

func TestAPIStatusMapping(t *testing.T) {
	tests := []struct {
		status int
		want   Kind
	}{
		{http.StatusNotFound, KindAPI},
		{http.StatusForbidden, KindRateLimited},
		{http.StatusInternalServerError, KindAPI},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("HTTP %d", tt.status), func(t *testing.T) {
			h := newFakeHub(t)
			h.statusCode = tt.status
			_, bin := writeInstalledBinary(t, "old", 0o755)
			cfg := testConfig(h, "v1.2.0", bin)

			_, err := CheckForUpdates(context.Background(), cfg)
			var ue *UpdateError
			if err == nil || !asUpdateError(err, &ue) || ue.Kind != tt.want {
				t.Fatalf("got %v, want %s", err, tt.want)
			}
			if got, _ := os.ReadFile(bin); string(got) != "old" {
				t.Fatal("binary modified on API failure")
			}
		})
	}
}

func TestRedirectToNonOfficialHostRefused(t *testing.T) {
	h := newFakeHub(t)
	// Publish normally, then point the artifact URL at our redirector.
	h.publish("v1.3.0", func(_, _ string) []byte { return []byte("evil") })
	artifact := fmt.Sprintf("tool-%s-%s", runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "windows" {
		artifact += ".exe"
	}
	var release map[string]any
	if err := json.Unmarshal(h.latestJSON, &release); err != nil {
		t.Fatal(err)
	}
	for _, a := range release["assets"].([]any) {
		m := a.(map[string]any)
		if m["name"] == artifact {
			m["browser_download_url"] = h.srv.URL + "/redirect/" + artifact
		}
	}
	h.latestJSON, _ = json.Marshal(release)

	_, bin := writeInstalledBinary(t, "original", 0o755)
	cfg := testConfig(h, "v1.2.0", bin)

	_, err := Run(context.Background(), cfg, Options{})
	if err == nil {
		t.Fatal("expected redirect refusal")
	}
	if got, _ := os.ReadFile(bin); string(got) != "original" {
		t.Fatal("redirected download replaced the binary")
	}
	if left := leftoverTemps(filepath.Dir(bin)); len(left) != 0 {
		t.Fatalf("temps left behind: %v", left)
	}
}

func TestReplaceBinaryAtomicity(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "tool")
	staged := filepath.Join(dir, ".staged")

	// Successful replace preserves mode and lands verified bytes.
	_ = os.WriteFile(target, []byte("old"), 0o755)
	newBytes := []byte("brand-new")
	sum := sha256.Sum256(newBytes)
	_ = os.WriteFile(staged, newBytes, 0o600)
	if err := replaceBinary(Config{}, target, staged, hex.EncodeToString(sum[:])); err != nil {
		t.Fatalf("replaceBinary: %v", err)
	}
	if got, _ := os.ReadFile(target); string(got) != "brand-new" {
		t.Fatalf("target = %q", got)
	}
	if info, _ := os.Stat(target); info.Mode().Perm() != 0o755 {
		t.Fatalf("mode not preserved: %v", info.Mode().Perm())
	}

	// Tampered staged bytes abort before the swap.
	_ = os.WriteFile(target, []byte("previous-good"), 0o750)
	_ = os.WriteFile(staged, []byte("tampered"), 0o600)
	err := replaceBinary(Config{}, target, staged, strings.Repeat("11", 32))
	var ue *UpdateError
	if err == nil || !asUpdateError(err, &ue) || ue.Kind != KindChecksumMismatch {
		t.Fatalf("got %v, want KindChecksumMismatch", err)
	}
	if got, _ := os.ReadFile(target); string(got) != "previous-good" {
		t.Fatal("tampered staged file destroyed the previous binary")
	}
}

func TestCheckForUpdatesStatuses(t *testing.T) {
	h := newFakeHub(t)
	h.publish("v1.3.0", func(_, _ string) []byte { return []byte("x") })

	tests := []struct {
		current string
		want    Status
	}{
		{"v1.2.0", StatusUpdated},
		{"v1.3.0", StatusCurrent},
		{"v1.4.0", StatusNewerInstalled},
	}
	for _, tt := range tests {
		_, bin := writeInstalledBinary(t, "x", 0o755)
		cfg := testConfig(h, tt.current, bin)
		res, err := CheckForUpdates(context.Background(), cfg)
		if err != nil {
			t.Fatalf("current=%s: %v", tt.current, err)
		}
		if res.Status != tt.want {
			t.Fatalf("current=%s: status=%d want %d", tt.current, res.Status, tt.want)
		}
	}
}

func asUpdateError(err error, target **UpdateError) bool {
	ue, ok := err.(*UpdateError)
	if ok {
		*target = ue
	}
	return ok
}

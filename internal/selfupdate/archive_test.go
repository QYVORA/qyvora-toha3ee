package selfupdate

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func buildTarGz(t *testing.T, entries map[string]string) string {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, content := range entries {
		hdr := &tar.Header{Name: name, Mode: 0o755, Size: int64(len(content))}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "a.tar.gz")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestExtractTarGzExactEntry(t *testing.T) {
	payload := "toha3ee-binary-bytes"
	archive := buildTarGz(t, map[string]string{
		"toha3ee":          payload,
		"assets/toha3.png": "icon",
	})
	dest := filepath.Join(t.TempDir(), "out")

	if err := extractEntry(archive, "toha3ee", dest, ArchiveTarGz); err != nil {
		t.Fatalf("extractEntry: %v", err)
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != payload {
		t.Fatalf("got %q, want %q", got, payload)
	}
	if info, err := os.Stat(dest); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("dest mode = %v (err %v), want 0600", info.Mode(), err)
	}
}

func TestExtractTarGzDotPrefixEntry(t *testing.T) {
	archive := buildTarGz(t, map[string]string{"./toha3ee": "payload"})
	dest := filepath.Join(t.TempDir(), "out")
	if err := extractEntry(archive, "toha3ee", dest, ArchiveTarGz); err != nil {
		t.Fatalf("extractEntry with ./ prefix: %v", err)
	}
}

func TestExtractTarGzRefusesTraversalAndMissing(t *testing.T) {
	dir := t.TempDir()
	archive := buildTarGz(t, map[string]string{
		"../escaped":  "evil",
		"sub/toha3ee": "decoy",
		"other":       "x",
	})

	outside := filepath.Join(dir, "escaped")
	err := extractEntry(archive, "../escaped", outside, ArchiveTarGz)
	if err == nil {
		t.Fatal("expected traversal entry to be refused")
	}
	if _, statErr := os.Stat(outside); !os.IsNotExist(statErr) {
		t.Fatalf("traversal target must not exist, got err=%v", statErr)
	}
	// A nested decoy must never satisfy an exact-name request.
	decoy := filepath.Join(dir, "decoy-out")
	if err := extractEntry(archive, "toha3ee", decoy, ArchiveTarGz); err == nil {
		got, _ := os.ReadFile(decoy)
		t.Fatalf("nested entry must not match; extracted %q", got)
	}
	if err := extractEntry(archive, "nope", filepath.Join(dir, "out"), ArchiveTarGz); err == nil {
		t.Fatal("expected missing-entry error")
	}
}

func buildZip(t *testing.T, entries map[string]string) string {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "a.zip")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestExtractZipExactEntry(t *testing.T) {
	archive := buildZip(t, map[string]string{
		"toha3ee.exe": "win-binary",
		"toha3ee.ico": "icon",
	})
	dest := filepath.Join(t.TempDir(), "out.exe")
	if err := extractEntry(archive, "toha3ee.exe", dest, ArchiveZip); err != nil {
		t.Fatalf("extractEntry: %v", err)
	}
	got, _ := os.ReadFile(dest)
	if string(got) != "win-binary" {
		t.Fatalf("got %q", got)
	}
}

func TestExtractNotAnArchiveFailsClosed(t *testing.T) {
	junk := filepath.Join(t.TempDir(), "junk.bin")
	_ = os.WriteFile(junk, []byte("not an archive at all "+strings.Repeat("x", 64)), 0o600)

	if err := extractEntry(junk, "bin", filepath.Join(t.TempDir(), "out"), ArchiveTarGz); err == nil {
		t.Error("tar.gz: expected error for junk input")
	}
	if err := extractEntry(junk, "bin", filepath.Join(t.TempDir(), "out2"), ArchiveZip); err == nil {
		t.Error("zip: expected error for junk input")
	}
	if err := extractEntry(junk, "bin", filepath.Join(t.TempDir(), "out3"), ArchiveNone); err == nil {
		t.Error("ArchiveNone must refuse extraction")
	}
}

package main

import (
	"strings"
	"testing"

	"github.com/QYVORA/qyvora-toha3ee/internal/selfupdate"
)

// TestReleaseArtifactName pins the release asset naming contract for toha3ee.
//
// The same names are produced in three places that can drift apart: the
// release workflow (.github/workflows/release.yml), install.sh, and this
// updater. When they disagree the updater requests an asset that no release
// has ever published and the user is told to reinstall by hand.
//
// Canonical: toha3ee_<version>_<linux|macos|windows>_<arch>.tar.gz (zip on
// windows), where <version> is the tag with its leading "v" stripped. toha3ee
// links libpcap through cgo, so it has no Android build and no case here.
//
// The cases that have actually been wrong in this ecosystem:
//
//   - macOS assets are published as "macos", but Go reports GOOS "darwin".
//   - The version is part of the asset name. GoReleaser strips the "v".
func TestReleaseArtifactName(t *testing.T) {
	cfg := releaseConfig()
	if cfg.ArtifactName == nil {
		t.Fatal("ArtifactName is nil; the updater cannot resolve a release asset")
	}

	tests := []struct {
		version, goos, goarch, want string
	}{
		{"v0.1.0", "linux", "amd64", "toha3ee_0.1.0_linux_amd64.tar.gz"},
		{"v0.1.0", "linux", "arm64", "toha3ee_0.1.0_linux_arm64.tar.gz"},
		{"v0.1.0", "darwin", "amd64", "toha3ee_0.1.0_macos_amd64.tar.gz"},
		{"v0.1.0", "darwin", "arm64", "toha3ee_0.1.0_macos_arm64.tar.gz"},
		{"v0.1.0", "windows", "amd64", "toha3ee_0.1.0_windows_amd64.zip"},
		{"v0.1.0", "windows", "arm64", "toha3ee_0.1.0_windows_arm64.zip"},
		{"0.1.0", "linux", "amd64", "toha3ee_0.1.0_linux_amd64.tar.gz"},
	}

	for _, tt := range tests {
		if got := cfg.ArtifactName(tt.version, tt.goos, tt.goarch); got != tt.want {
			t.Errorf("ArtifactName(%q, %q, %q) = %q, want %q",
				tt.version, tt.goos, tt.goarch, got, tt.want)
		}
	}
}

// TestReleaseArchiveEntryMatchesAsset guards the failure mode of an update
// that downloads and verifies the archive correctly but installs the wrong
// bytes: the archive's single executable entry must be the tool itself, and
// windows assets are zip while everything else is tar.gz.
func TestReleaseArchiveEntryMatchesAsset(t *testing.T) {
	cfg := releaseConfig()
	if cfg.ArchiveFor == nil {
		t.Fatal("ArchiveFor is nil; the updater would install the archive bytes as the binary")
	}

	kind, entry := cfg.ArchiveFor("linux", "amd64")
	if kind != selfupdate.ArchiveTarGz || entry != "toha3ee" {
		t.Errorf("ArchiveFor(linux, amd64) = (%v, %q), want (ArchiveTarGz, toha3ee)", kind, entry)
	}

	kind, entry = cfg.ArchiveFor("windows", "amd64")
	if kind != selfupdate.ArchiveZip || entry != "toha3ee.exe" {
		t.Errorf("ArchiveFor(windows, amd64) = (%v, %q), want (ArchiveZip, toha3ee.exe)", kind, entry)
	}
}

// TestChecksumAssetIsTheReleaseManifest pins the checksum source. A per-artifact
// ".sha256" sidecar holds a bare digest, which does not match a manifest line of
// the form "<sha256>  <name>", so verification silently fails against it.
func TestChecksumAssetIsTheReleaseManifest(t *testing.T) {
	cfg := releaseConfig()
	if cfg.ChecksumAsset == nil {
		t.Fatal("ChecksumAsset is nil; the update would be unverified")
	}
	for _, artifact := range []string{
		"toha3ee_0.1.0_linux_amd64.tar.gz", "toha3ee_0.1.0_macos_arm64.tar.gz",
		"toha3ee_0.1.0_windows_amd64.zip",
	} {
		if got := cfg.ChecksumAsset(artifact); got != "checksums.txt" {
			t.Errorf("ChecksumAsset(%q) = %q, want \"checksums.txt\"", artifact, got)
		}
	}
}

// TestReleaseArtifactNameStripsVersionPrefix is the specific bug this contract
// exists for: leaving the "v" on produces a name no release ever published.
func TestReleaseArtifactNameStripsVersionPrefix(t *testing.T) {
	cfg := releaseConfig()
	for _, tag := range []string{"v0.1.0", "V0.1.0", "0.1.0"} {
		got := cfg.ArtifactName(tag, "linux", "amd64")
		if strings.Contains(got, "_v0.1.0_") || strings.Contains(got, "_V0.1.0_") {
			t.Errorf("ArtifactName(%q, linux, amd64) = %q, kept the version prefix", tag, got)
		}
	}
}

package main

import "testing"

// TestReleaseArtifactName pins the release asset naming contract for toha3ee.
//
// The same names are produced in three places that can drift apart: the
// release workflow (.github/workflows/release.yml), install.sh, and this
// updater. When they disagree the updater requests an asset that no release
// has ever published and the user is told to reinstall by hand.
//
// The cases that have actually been wrong in this ecosystem:
//
//   - macOS assets are published as "macos", but Go reports GOOS "darwin".
//   - Android/Termux is its own target: GOOS is "android" for a GOOS=android
//     build and the asset is "{tool}-android-arm64". A linux/arm64 asset must
//     never be substituted, because Android's bionic linker rejects an ET_EXEC
//     binary with "unexpected e_type: 2".
//   - Assets are bare executables. The updater writes the downloaded bytes to
//     the executable path, so naming an archive produces a "successful" update
//     that leaves an unrunnable binary.
func TestReleaseArtifactName(t *testing.T) {
	cfg := releaseConfig()
	if cfg.ArtifactName == nil {
		t.Fatal("ArtifactName is nil; the updater cannot resolve a release asset")
	}

	tests := []struct {
		goos, goarch, want string
	}{
		{"linux", "amd64", "toha3ee-linux-amd64"},
		{"linux", "arm64", "toha3ee-linux-arm64"},
		{"darwin", "amd64", "toha3ee-macos-amd64"},
		{"darwin", "arm64", "toha3ee-macos-arm64"},
		{"windows", "amd64", "toha3ee-windows-amd64.exe"},
		{"windows", "arm64", "toha3ee-windows-arm64.exe"},
		{"android", "arm64", "toha3ee-android-arm64"},
	}

	for _, tt := range tests {
		if got := cfg.ArtifactName(tt.goos, tt.goarch); got != tt.want {
			t.Errorf("ArtifactName(%q, %q) = %q, want %q", tt.goos, tt.goarch, got, tt.want)
		}
	}
}

// TestReleaseArtifactNameIsNeverAnArchive guards the specific failure mode of
// an update that reports success and leaves an unrunnable binary behind.
func TestReleaseArtifactNameIsNeverAnArchive(t *testing.T) {
	cfg := releaseConfig()
	for _, goos := range []string{"linux", "darwin", "windows", "android"} {
		name := cfg.ArtifactName(goos, "arm64")
		for _, bad := range []string{".tar.gz", ".tgz", ".zip", ".tar"} {
			if len(name) >= len(bad) && name[len(name)-len(bad):] == bad {
				t.Errorf("ArtifactName(%q, \"arm64\") = %q, which names an archive; "+
					"the updater installs these bytes as the executable directly", goos, name)
			}
		}
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
		"toha3ee-linux-amd64", "toha3ee-macos-arm64", "toha3ee-android-arm64",
	} {
		if got := cfg.ChecksumAsset(artifact); got != "checksums.txt" {
			t.Errorf("ChecksumAsset(%q) = %q, want \"checksums.txt\"", artifact, got)
		}
	}
}

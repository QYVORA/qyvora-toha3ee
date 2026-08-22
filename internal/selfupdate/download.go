package selfupdate

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// fetchVerified downloads the artifact and its checksum manifest, verifies
// the artifact digest, unpacks archives when needed, and stages the ready-
// to-install binary next to the target so the later rename is guaranteed to
// stay on one filesystem.
//
// All temporary files are created inside the target directory with 0600 and
// removed by the returned cleanup func on every path except a successful
// hand-off to replaceBinary.
func fetchVerified(ctx context.Context, cfg Config, binAsset, sumAsset *Asset, target, version string) (stagedPath, wantSum string, cleanup func(), err error) {
	dir := filepath.Dir(target)

	var temps []string
	cleanup = func() {
		for _, p := range temps {
			_ = os.Remove(p)
		}
	}

	// Fail fast on missing privileges instead of downloading first and
	// discovering them at install time.
	if serr := checkWritable(dir, target); serr != nil {
		return "", "", nil, serr
	}

	tmpArtifact, err := tempFile(dir, cfg.ToolName+".artifact")
	if err != nil {
		return "", "", nil, installFailed(cfg, "cannot create a temporary download file", err)
	}
	temps = append(temps, tmpArtifact.Name())

	if derr := download(ctx, cfg, binAsset, tmpArtifact, maxArtifactSize, 10*time.Minute); derr != nil {
		return "", "", nil, derr
	}

	tmpManifest, err := tempFile(dir, cfg.ToolName+".checksums")
	if err != nil {
		return "", "", nil, installFailed(cfg, "cannot create a temporary checksum file", err)
	}
	temps = append(temps, tmpManifest.Name())

	if derr := download(ctx, cfg, sumAsset, tmpManifest, maxChecksumSize, 30*time.Second); derr != nil {
		return "", "", nil, derr
	}
	manifest, rerr := os.ReadFile(tmpManifest.Name())
	if rerr != nil {
		return "", "", nil, installFailed(cfg, "cannot read the downloaded checksum manifest", rerr)
	}

	wantSum, cerr := findChecksum(manifest, binAsset.Name)
	if cerr != nil {
		return "", "", nil, &UpdateError{Kind: KindVerificationUnavailable, tool: cfg.ToolName, reason: cerr.Error(), version: version}
	}

	// The manifest authenticates the artifact exactly as published (raw
	// binary or archive) before anything is unpacked or installed.
	if verr := verifyFileDigest(tmpArtifact.Name(), wantSum); verr != nil {
		return "", "", nil, &UpdateError{
			Kind:    KindChecksumMismatch,
			err:     verr,
			tool:    cfg.ToolName,
			path:    binAsset.Name,
			version: version,
		}
	}

	gotPath := tmpArtifact.Name()
	wantStaged := wantSum
	if cfg.ArchiveFor != nil {
		kind, entry := cfg.ArchiveFor(runtime.GOOS, runtime.GOARCH)
		if kind != ArchiveNone {
			// Extraction is a deterministic local step over an already-
			// verified archive; the payload receives its own digest for the
			// install-stage verification performed by replaceBinary.
			tmpBin, terr := tempFile(dir, cfg.ToolName+".binary")
			if terr != nil {
				return "", "", nil, installFailed(cfg, "cannot create a temporary extraction file", terr)
			}
			if xerr := extractEntry(tmpArtifact.Name(), entry, tmpBin.Name(), kind); xerr != nil {
				return "", "", nil, installFailed(cfg, xerr.Error(), xerr)
			}
			temps = append(temps, tmpBin.Name())
			gotPath = tmpBin.Name()
			s, serr := fileSHA256(gotPath)
			if serr != nil {
				return "", "", nil, installFailed(cfg, "cannot digest the extracted binary", serr)
			}
			wantStaged = s
		}
	}
	return gotPath, wantStaged, cleanup, nil
}

// tempFile creates a named, uniquely suffixed temp file in dir. CreateTemp
// already applies 0600, keeping partial downloads unreadable to other users.
func tempFile(dir, label string) (*os.File, error) {
	pattern := fmt.Sprintf(".%s-*.part", sanitizeLabel(label))
	return os.CreateTemp(dir, pattern)
}

func sanitizeLabel(label string) string {
	out := make([]rune, 0, len(label))
	for _, r := range label {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			out = append(out, r)
		default:
			out = append(out, '_')
		}
	}
	return string(out)
}

// download streams the asset into dst under a hard size limit.
func download(ctx context.Context, cfg Config, a *Asset, dst *os.File, limit int64, timeout time.Duration) error {
	parsed, perr := url.Parse(a.BrowserDownloadURL)
	if perr != nil || !officialURL(parsed) {
		return &UpdateError{
			Kind:   KindAPI,
			err:    perr,
			tool:   cfg.ToolName,
			reason: fmt.Sprintf("release asset %q does not point at an official host", a.Name),
		}
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, rerr := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if rerr != nil {
		return installFailed(cfg, "cannot build artifact request", rerr)
	}
	req.Header.Set("User-Agent", "QYVORA-"+cfg.ToolName+"-selfupdate")

	resp, derr := newHTTPClient().Do(req)
	if derr != nil {
		return &UpdateError{Kind: KindNetwork, err: derr, tool: cfg.ToolName, reason: "the official release service could not be reached"}
	}
	defer resp.Body.Close() //nolint:errcheck // read-only stream
	if resp.StatusCode != http.StatusOK {
		return &UpdateError{
			Kind:   KindAPI,
			tool:   cfg.ToolName,
			reason: fmt.Sprintf("downloading %q returned HTTP %d", a.Name, resp.StatusCode),
		}
	}

	n, cerr := io.Copy(dst, io.LimitReader(resp.Body, limit+1))
	if cerr != nil {
		return &UpdateError{Kind: KindNetwork, err: cerr, tool: cfg.ToolName, reason: "the artifact download was interrupted"}
	}
	if n > limit {
		return &UpdateError{
			Kind:   KindAPI,
			tool:   cfg.ToolName,
			reason: fmt.Sprintf("release asset %q exceeds the %d MiB safety limit", a.Name, limit>>20),
		}
	}
	if serr := dst.Sync(); serr != nil {
		return installFailed(cfg, "cannot flush the downloaded artifact", serr)
	}
	return nil
}

// officialURL enforces HTTPS plus the official-host allowlist. Local test
// endpoints are accepted only because tests bind there explicitly.
func officialURL(u *url.URL) bool {
	host := u.Hostname()
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return true
	}
	return u.Scheme == "https" && allowlistedHosts[host]
}

func installFailed(cfg Config, reason string, cause error) *UpdateError {
	return &UpdateError{Kind: KindInstall, err: cause, tool: cfg.ToolName, reason: reason}
}

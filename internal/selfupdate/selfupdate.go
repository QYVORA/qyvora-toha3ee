// Package selfupdate implements the QYVORA binary self-update flow.
//
// The flow is identical across the QYVORA tools:
//
//	installed version
//	  → official GitHub release (Releases API)
//	  → platform artifact selection
//	  → download to a temporary file
//	  → verify SHA-256 against the official checksum manifest
//	  → atomically replace the installed binary, preserving permissions
//	  → verify the installed bytes
//	  → report
//
// Only the configured official QYVORA repository is ever contacted. Every
// failure mode — network outage, checksum mismatch, missing permissions —
// leaves the existing binary untouched. The package deliberately depends on
// the standard library only, so each repository keeps an independent copy
// without coupling their release cycles or Go modules together.
package selfupdate

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Status classifies the outcome of an update run.
type Status int

const (
	// StatusUpdated means a newer release was downloaded, verified and installed.
	StatusUpdated Status = iota
	// StatusCurrent means the installed version equals the latest release.
	StatusCurrent
	// StatusNewerInstalled means the installed version is newer than the
	// latest release; downgrades are refused by design.
	StatusNewerInstalled
)

// Result reports what an update run decided and did.
type Result struct {
	Status   Status
	Current  string // installed version before the run (as reported by the CLI)
	Latest   string // latest release tag observed on GitHub
	Path     string // executable path, set when Status == StatusUpdated
	Artifact string // release asset selected for this platform
}

// Options tune output for one update run. A nil Out disables progress output,
// which is how machine-readable callers consume Run without parsing chatter.
type Options struct {
	Out   io.Writer // progress output; nil silences all progress lines
	Quiet bool      // convenience alias for Out == io.Discard semantics
}

func (o Options) writer() io.Writer {
	if o.Quiet || o.Out == nil {
		return io.Discard
	}
	return o.Out
}

// Config pins one tool to its official QYVORA release source. The zero value
// is not usable; every field must be set by the embedding tool except
// APIBaseURL and ExecutablePath which have safe defaults.
type Config struct {
	Owner    string // GitHub organization, always "QYVORA".
	Repo     string // Repository name, e.g. "qyvora-aksum".
	ToolName string // Display name used in messages, e.g. "aksum".

	// CurrentVersion returns the running binary's version. It must be the
	// same value `tool version` prints so the two commands cannot disagree.
	CurrentVersion func() string

	// ArtifactName maps GOOS/GOARCH to the exact release asset name.
	// An empty string means the release pipeline does not publish that
	// platform; the update then fails cleanly instead of guessing.
	ArtifactName func(goos, goarch string) string

	// ChecksumAsset returns the name of the release asset holding the
	// SHA-256 entry for the given artifact, e.g. "SHA256SUMS" or
	// "<artifact>.sha256".
	ChecksumAsset func(artifact string) string

	// ArchiveFor returns how the platform's artifact is packaged and the
	// exact single entry holding the installable binary when it is archived.
	// ArchiveNone means the asset itself is the raw binary.
	ArchiveFor func(goos, goarch string) (kind ArchiveKind, entry string)

	// APIBaseURL overrides the GitHub API base URL. Empty uses the public
	// API; tests point it at a local server.
	APIBaseURL string

	// ExecutablePath resolves the path to replace. Empty means os.Executable
	// with symlinks resolved to the real install location.
	ExecutablePath func() (string, error)
}

const (
	apiBaseDefault = "https://api.github.com"
	// maxArtifactSize bounds a downloaded artifact so a hostile or broken
	// endpoint cannot exhaust the disk. Release binaries are tens of MB.
	maxArtifactSize = 512 << 20
	// maxChecksumSize bounds checksum manifests (a few KB in practice).
	maxChecksumSize = 1 << 20
)

// devVersions are values reported by unstamped builds. Such binaries carry no
// release identity, so no comparison against a release can be honest.
var devVersions = map[string]bool{
	"": true, "dev": true, "unknown": true, "(devel)": true, "none": true,
}

// Run executes the full update flow and returns what happened. Progress
// messages are written to opts.Out when set; errors are returned as
// *UpdateError so callers can render them without matching on strings.
//
// Run never removes or replaces the existing binary unless download,
// verification and staging all succeeded.
func Run(ctx context.Context, cfg Config, opts Options) (Result, error) {
	out := opts.writer()

	current := strings.TrimSpace(cfg.CurrentVersion())
	if devVersions[strings.ToLower(current)] {
		return Result{}, &UpdateError{Kind: KindDevBuild, current: current, tool: cfg.ToolName}
	}

	fmt.Fprintf(out, "%s %s\n\n", cfg.ToolName, normalizeDisplay(current))
	fmt.Fprintln(out, "Checking for updates...")

	release, err := fetchLatestRelease(ctx, cfg)
	if err != nil {
		return Result{}, err
	}
	fmt.Fprintf(out, "Latest version: %s\n", release.TagName)

	cmp := CompareVersions(current, release.TagName)
	switch {
	case cmp > 0:
		fmt.Fprintf(out, "\n✓ Installed version %s is newer than the latest release %s.\n", normalizeDisplay(current), release.TagName)
		fmt.Fprintln(out, "\nNo downgrade performed.")
		return Result{Status: StatusNewerInstalled, Current: current, Latest: release.TagName}, nil
	case cmp == 0:
		fmt.Fprintf(out, "\n✓ %s is already up to date.\n", cfg.ToolName)
		return Result{Status: StatusCurrent, Current: current, Latest: release.TagName}, nil
	}
	fmt.Fprintf(out, "\nUpdate available: %s → %s\n\n", normalizeDisplay(current), release.TagName)

	goos, goarch := runtime.GOOS, runtime.GOARCH
	artifact := cfg.ArtifactName(goos, goarch)
	if artifact == "" {
		return Result{}, &UpdateError{Kind: KindPlatform, tool: cfg.ToolName, platform: goos + "/" + goarch}
	}

	target, err := resolveTarget(cfg)
	if err != nil {
		return Result{}, err
	}

	binAsset := findAsset(release, artifact)
	if binAsset == nil {
		return Result{}, &UpdateError{
			Kind:     KindPlatform,
			tool:     cfg.ToolName,
			platform: goos + "/" + goarch,
			reason:   fmt.Sprintf("release %s publishes no artifact named %q", release.TagName, artifact),
		}
	}
	sumAsset := findAsset(release, cfg.ChecksumAsset(artifact))
	if sumAsset == nil {
		return Result{}, &UpdateError{
			Kind:    KindVerificationUnavailable,
			tool:    cfg.ToolName,
			reason:  fmt.Sprintf("release %s publishes no checksum manifest %q; refusing to install unverified artifacts", release.TagName, cfg.ChecksumAsset(artifact)),
			version: release.TagName,
		}
	}

	fmt.Fprintf(out, "Downloading %s %s...\n", cfg.ToolName, release.TagName)
	staged, wantSum, cleanup, err := fetchVerified(ctx, cfg, binAsset, sumAsset, target, release.TagName)
	if err != nil {
		return Result{}, err
	}
	defer cleanup()
	fmt.Fprintln(out, "✓ Download complete")
	fmt.Fprintln(out, "✓ Artifact verified")

	if err := replaceBinary(cfg, target, staged, wantSum); err != nil {
		return Result{}, err
	}
	fmt.Fprintln(out, "✓ Binary installed")

	fmt.Fprintf(out, "\n%s has been updated to %s.\n", cfg.ToolName, release.TagName)
	return Result{
		Status:   StatusUpdated,
		Current:  current,
		Latest:   release.TagName,
		Path:     target,
		Artifact: artifact,
	}, nil
}

// CheckForUpdates resolves the latest official release and compares it with
// the installed version without downloading anything else. It backs
// check-only UX and the test suite; Run shares it via fetchLatestRelease.
func CheckForUpdates(ctx context.Context, cfg Config) (Result, error) {
	current := strings.TrimSpace(cfg.CurrentVersion())
	if devVersions[strings.ToLower(current)] {
		return Result{}, &UpdateError{Kind: KindDevBuild, current: current, tool: cfg.ToolName}
	}
	release, err := fetchLatestRelease(ctx, cfg)
	if err != nil {
		return Result{}, err
	}
	res := Result{Current: current, Latest: release.TagName}
	switch CompareVersions(current, release.TagName) {
	case 1:
		res.Status = StatusNewerInstalled
	case 0:
		res.Status = StatusCurrent
	default:
		res.Status = StatusUpdated
	}
	return res, nil
}

// resolveTarget determines which on-disk file the updater owns. Symlinks are
// resolved so an install through a PATH symlink replaces the real binary.
func resolveTarget(cfg Config) (string, error) {
	resolve := cfg.ExecutablePath
	if resolve == nil {
		resolve = func() (string, error) { return os.Executable() }
	}
	exe, err := resolve()
	if err != nil {
		return "", &UpdateError{Kind: KindInstall, tool: cfg.ToolName, reason: "cannot locate the running executable"}
	}
	real, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return "", &UpdateError{Kind: KindInstall, tool: cfg.ToolName, reason: fmt.Sprintf("cannot resolve the executable path %q", exe)}
	}
	abs, err := filepath.Abs(real)
	if err != nil {
		abs = real
	}
	return abs, nil
}

// findAsset returns the release asset whose name matches exactly. Names are
// never used as proof of authenticity — only as the deterministic selector;
// authenticity comes exclusively from the checksum step.
func findAsset(r *Release, name string) *Asset {
	for i := range r.Assets {
		if r.Assets[i].Name == name {
			return &r.Assets[i]
		}
	}
	return nil
}

// normalizeDisplay renders a version for humans, adding the conventional
// leading "v" when the build stamped a bare number.
func normalizeDisplay(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || v[0] == 'v' || v[0] == 'V' || !IsReleaseVersion(v) {
		return v
	}
	return "v" + v
}

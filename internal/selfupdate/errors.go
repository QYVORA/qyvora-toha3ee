package selfupdate

import "fmt"

// Kind classifies updater failures so command layers can render them cleanly
// (and map them to exit codes) without matching on strings.
type Kind string

const (
	KindNetwork                 Kind = "network"
	KindAPI                     Kind = "api"
	KindRateLimited             Kind = "rate_limited"
	KindPlatform                Kind = "unsupported_platform"
	KindVerificationUnavailable Kind = "verification_unavailable"
	KindChecksumMismatch        Kind = "checksum_mismatch"
	KindPermission              Kind = "permission_denied"
	KindInstall                 Kind = "install_failed"
	KindDevBuild                Kind = "dev_build"
)

// UpdateError is the only error type Run returns. The wrapped cause is kept
// for debug output but is never dumped at ordinary CLI users.
type UpdateError struct {
	Kind     Kind
	err      error
	tool     string
	reason   string
	platform string
	path     string
	version  string
	current  string
}

func (e *UpdateError) Error() string {
	switch e.Kind {
	case KindDevBuild:
		return fmt.Sprintf("%s reports no release version (%q); updates need a binary stamped by an official release", e.tool, e.current)
	case KindPlatform:
		if e.reason != "" {
			return e.reason
		}
		return fmt.Sprintf("No release exists for %s.", e.platform)
	case KindVerificationUnavailable:
		return e.reason
	case KindChecksumMismatch:
		return fmt.Sprintf("checksum mismatch for %s %s (%s); the download was discarded and nothing was installed", e.tool, e.version, e.path)
	case KindPermission:
		if e.reason != "" {
			return e.reason
		}
		return fmt.Sprintf("cannot replace the installed binary at %s: permission denied", e.path)
	default:
		if e.reason != "" {
			return e.reason
		}
		return "update failed"
	}
}

// Unwrap exposes the cause to errors.Is/As and debug logging.
func (e *UpdateError) Unwrap() error { return e.err }

// Path reports the file involved in a permission/install failure, if any.
func (e *UpdateError) Path() string { return e.path }

// Platform reports the os/arch string of a platform failure, if any.
func (e *UpdateError) Platform() string { return e.platform }

package selfupdate

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
)

// checkWritable probes whether dir accepts new files, which is the permission
// that matters: replacement happens by renaming a staged file over the
// target, never by writing to the running executable's inode (Linux answers
// such writes with ETXTBSY).
func checkWritable(dir, target string) error {
	probe, err := os.CreateTemp(dir, ".qyvora-update-probe-*")
	if err != nil {
		if isPermissionErr(err) {
			return &UpdateError{Kind: KindPermission, path: target}
		}
		return &UpdateError{
			Kind:   KindInstall,
			err:    err,
			path:   target,
			reason: fmt.Sprintf("cannot write to the install directory %s", dir),
		}
	}
	name := probe.Name()
	_ = probe.Close()
	_ = os.Remove(name)
	return nil
}

func isPermissionErr(err error) bool {
	return errors.Is(err, fs.ErrPermission) || errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM)
}

// replaceBinary moves the verified staged file over the installed binary.
//
// The staged file already carries a verified digest; this step preserves the
// existing file mode, swaps atomically where the OS allows it, rolls back on
// failure so the previous binary always survives, and finally re-verifies
// the bytes that landed at target.
func replaceBinary(cfg Config, target, staged, wantSum string) error {
	mode := fs.FileMode(0o755)
	if info, serr := os.Stat(target); serr == nil {
		mode = info.Mode().Perm()
	} else if !errors.Is(serr, fs.ErrNotExist) {
		return installFailed(cfg, "cannot inspect the installed binary", serr)
	}
	if cherr := os.Chmod(staged, mode); cherr != nil {
		return installFailed(cfg, "cannot set permissions on the staged binary", cherr)
	}

	// Re-verify immediately before the swap; cheap insurance against any
	// mid-flight modification of the staged file.
	if verr := verifyFileDigest(staged, wantSum); verr != nil {
		return &UpdateError{Kind: KindChecksumMismatch, err: verr, path: filepath.Base(target)}
	}

	var rerr error
	if runtime.GOOS == "windows" {
		rerr = replaceWindows(target, staged)
	} else {
		// POSIX rename within one directory is atomic: readers see either
		// the old or the new binary, never a partial file.
		rerr = os.Rename(staged, target)
	}
	if rerr != nil {
		if isPermissionErr(rerr) {
			return &UpdateError{Kind: KindPermission, path: target}
		}
		return &UpdateError{
			Kind:   KindInstall,
			err:    rerr,
			path:   target,
			reason: fmt.Sprintf("cannot replace %s: %v", target, rerr),
		}
	}

	// Final gate: confirm the bytes that actually landed on disk are the
	// verified ones before reporting success.
	if verr := verifyFileDigest(target, wantSum); verr != nil {
		return &UpdateError{
			Kind:   KindInstall,
			err:    verr,
			path:   target,
			reason: fmt.Sprintf("the binary at %s failed post-install verification", target),
		}
	}
	return nil
}

// replaceWindows handles Windows' rule that a running executable cannot be
// deleted or overwritten in place: the old binary is renamed aside first and
// removed best-effort afterwards, with rollback if the swap fails.
func replaceWindows(target, staged string) error {
	old := target + ".old"
	_ = os.Remove(old)
	if _, err := os.Stat(target); err == nil {
		if err := os.Rename(target, old); err != nil {
			return fmt.Errorf("close running instances of %s first: %w", filepath.Base(target), err)
		}
	}
	if err := os.Rename(staged, target); err != nil {
		if rbErr := os.Rename(old, target); rbErr != nil {
			_ = rbErr // report the primary failure; the old copy stays beside it
		}
		return err
	}
	_ = os.Remove(old)
	return nil
}

// PermissionHint renders the multi-line guidance shown when an update cannot
// proceed because the install location needs elevated privileges. It is kept
// here so every QYVORA tool prints identical advice.
func PermissionHint(tool, path string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "✗ Cannot replace the installed binary.\n\n")
	fmt.Fprintf(&b, "The binary is located at:\n%s\n\n", path)
	fmt.Fprintf(&b, "This location requires elevated privileges.\n\n")
	fmt.Fprintf(&b, "Run the update with the appropriate permissions or reinstall %s\ninto a user-writable location.", tool)
	return b.String()
}

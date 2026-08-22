package selfupdate

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// findChecksum extracts the expected SHA-256 hex digest for name from a
// manifest. It understands:
//
//   - the coreutils format produced by `sha256sum *`:
//     "<hex>  <name>" or "<hex> *<name>"
//   - single-artifact manifests holding nothing but the bare hex digest
//     (the TOHA3EE per-artifact .sha256 files)
//
// Anything else fails closed: a manifest without an unambiguous entry for
// name yields an error, never "assume it is fine".
func findChecksum(manifest []byte, name string) (string, error) {
	var (
		bare      string
		bareLines int
		matched   bool
		digest    string
	)
	for _, line := range strings.Split(string(manifest), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 1 {
			bare = fields[0]
			bareLines++
			continue
		}
		if len(fields) < 2 {
			return "", fmt.Errorf("checksum manifest contains malformed line %q", line)
		}
		candidate := strings.TrimPrefix(fields[1], "*")
		if candidate == name || filepathBase(candidate) == name {
			if matched && digest != fields[0] {
				return "", fmt.Errorf("checksum manifest lists conflicting entries for %q", name)
			}
			matched = true
			digest = fields[0]
		}
	}
	switch {
	case matched && validHex(digest):
		return strings.ToLower(digest), nil
	case matched:
		return "", fmt.Errorf("checksum manifest entry for %q is not a SHA-256 digest", name)
	case bareLines == 1 && validHex(bare):
		// Per-artifact manifest: the file name itself identifies the subject.
		return strings.ToLower(bare), nil
	default:
		return "", fmt.Errorf("checksum manifest has no entry for %q; refusing to proceed", name)
	}
}

func filepathBase(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

func validHex(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// verifyFileDigest streams path through SHA-256 and compares against wantHex.
func verifyFileDigest(path, wantHex string) error {
	got, err := fileSHA256(path)
	if err != nil {
		return err
	}
	want := strings.ToLower(wantHex)
	if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		return errors.New("digest mismatch")
	}
	return nil
}

// fileSHA256 returns the lowercase hex SHA-256 of the file at path.
func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close() //nolint:errcheck // read-only handle
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

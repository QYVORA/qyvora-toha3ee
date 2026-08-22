package selfupdate

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// ArchiveKind selects how a release artifact is packaged.
type ArchiveKind int

const (
	// ArchiveNone means the asset itself is the raw binary.
	ArchiveNone ArchiveKind = iota
	// ArchiveTarGz means the asset is a gzipped tar containing ArchiveEntry.
	ArchiveTarGz
	// ArchiveZip means the asset is a zip archive containing ArchiveEntry.
	ArchiveZip
)

// extractEntry copies the single named file out of an archive into dest,
// creating it with 0600. The extraction is deliberately paranoid:
//
//   - only the exact entry name is accepted (no globbing, no prefix match),
//     which structurally rules out path traversal ("../", absolute paths);
//   - symlinks, hardlinks, devices and directories are rejected rather than
//     followed or created;
//   - decompressed size is capped at maxArtifactSize so a zip bomb cannot
//     exhaust the disk.
func extractEntry(archivePath, entryName, dest string, kind ArchiveKind) error {
	// Defense in depth: the updater only ever requests bare file names, so
	// refuse anything with separators or dot-dot components outright.
	if entryName == "" || strings.ContainsAny(entryName, "/\\") || strings.Contains(entryName, "..") {
		return fmt.Errorf("invalid archive entry name %q", entryName)
	}
	switch kind {
	case ArchiveTarGz:
		return extractFromTarGz(archivePath, entryName, dest)
	case ArchiveZip:
		return extractFromZip(archivePath, entryName, dest)
	default:
		return errors.New("artifact is not packaged as an archive")
	}
}

func extractFromTarGz(archivePath, entryName, dest string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close() //nolint:errcheck // read-only handle

	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("release artifact is not valid gzip: %w", err)
	}
	defer gz.Close() //nolint:errcheck // read-only stream

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("release artifact is not a valid tar: %w", err)
		}
		if normalizeEntryName(hdr.Name) != entryName {
			continue
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA { //nolint:staticcheck // TypeRegA covers legacy writers
			return fmt.Errorf("archive entry %q is not a regular file", entryName)
		}
		return copyLimited(tr, dest, maxArtifactSize, entryName)
	}
	return fmt.Errorf("release archive contains no entry %q", entryName)
}

// normalizeEntryName reduces harmless spellings ("./bin", "/bin") to their
// base form so the exact-name comparison cannot be evaded or confused.
// Multi-component names such as "sub/dir/bin" do NOT normalize to "bin":
// they simply do not match, which structurally rules out traversal.
func normalizeEntryName(name string) string {
	name = strings.TrimPrefix(name, "/")
	for strings.HasPrefix(name, "./") {
		name = name[2:]
	}
	return name
}

func extractFromZip(archivePath, entryName, dest string) error {
	zr, err := zip.OpenReader(archivePath)
	if err != nil {
		return fmt.Errorf("release artifact is not a valid zip: %w", err)
	}
	defer zr.Close() //nolint:errcheck // read-only handle

	for _, zf := range zr.File {
		if normalizeEntryName(zf.Name) != entryName {
			continue
		}
		if zf.Mode()&os.ModeType != 0 {
			return fmt.Errorf("archive entry %q is not a regular file", entryName)
		}
		rc, err := zf.Open()
		if err != nil {
			return err
		}
		defer rc.Close() //nolint:errcheck // read-only stream
		return copyLimited(rc, dest, maxArtifactSize, entryName)
	}
	return fmt.Errorf("release archive contains no entry %q", entryName)
}

// copyLimited writes at most limit bytes from r into dest; one extra byte is
// permitted through the reader to detect overflow deterministically.
func copyLimited(r io.Reader, dest string, limit int64, label string) error {
	out, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	n, err := io.Copy(out, io.LimitReader(r, limit+1))
	if closeErr := out.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(dest)
		return err
	}
	if n > limit {
		_ = os.Remove(dest)
		return fmt.Errorf("archive entry %q exceeds the %d MiB safety limit", label, limit>>20)
	}
	return nil
}

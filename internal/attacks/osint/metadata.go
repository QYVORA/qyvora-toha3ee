package osint

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/qyvora/toha3ee/internal/attacks"
)

// Metadata harvests authorship and tooling metadata from documents (PDF, DOCX,
// XLSX, PPTX) that an org has left reachable, exposing real usernames and
// software versions useful for targeted phishing or version-based findings.
type Metadata struct{}

// Meta implements attacks.Module.
func (*Metadata) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "osint.metadata",
		Category:    "osint",
		Risk:        attacks.RiskInfo,
		Targets:     []string{"file", "dir"},
		Description: "extract author/tooling metadata from PDF, DOCX, XLSX and PPTX documents",
		Limitations: "operates on files already in your possession; redact or scrub copies before sharing",
	}
}

type docMeta struct {
	File    string
	Title   string
	Author  string
	Creator string
	Producer string
	Created string
	Software string
}

type metadataResult struct {
	Files  []docMeta
	Total  int
}

// Preflight needs a file or directory path.
func (*Metadata) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	p := ctx.Conf.Get("osint.metadata", "path")
	if p == "" {
		rep.AddFixable("path", "set osint.metadata.path to a file or directory of documents")
		return rep, nil
	}
	if fi, err := os.Stat(p); err != nil {
		rep.AddFixable("path", fmt.Sprintf("cannot stat %s: %v", p, err))
	} else if fi.IsDir() {
		rep.AddOK("path", "directory "+p)
	} else {
		rep.AddOK("path", "file "+p)
	}
	return rep, nil
}

// Run walks the path and parses metadata from supported document types.
func (*Metadata) Run(ctx *attacks.AttackCtx, opts map[string]string) error {
	p := ctx.Conf.Get("osint.metadata", "path")
	if o, ok := opts["path"]; ok && o != "" {
		p = o
	}
	var files []string
	fi, err := os.Stat(p)
	if err != nil {
		return fmt.Errorf("osint.metadata: %w", err)
	}
	if fi.IsDir() {
		_ = filepath.Walk(p, func(path string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() && isSupported(path) {
				files = append(files, path)
			}
			return nil
		})
	} else {
		files = []string{p}
	}

	var out []docMeta
	for _, f := range files {
		if m, ok := parseDocMeta(f); ok {
			out = append(out, m)
			emit(ctx, "finding", fmt.Sprintf("osint.metadata: %s author=%q creator=%q prod=%q created=%q", m.File, m.Author, m.Creator, m.Producer, m.Created))
		}
	}
	ctx.SetState("osint.metadata", metadataResult{Files: out, Total: len(files)})
	ctx.Printf("[*] osint.metadata: parsed %d document(s), extracted metadata from %d.\n", len(files), len(out))
	return nil
}

func isSupported(p string) bool {
	switch strings.ToLower(filepath.Ext(p)) {
	case ".pdf", ".docx", ".xlsx", ".pptx":
		return true
	}
	return false
}

func parseDocMeta(path string) (docMeta, bool) {
	m := docMeta{File: path}
	data, err := os.ReadFile(path)
	if err != nil {
		return m, false
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".pdf":
		parsePDFMeta(data, &m)
	case ".docx", ".xlsx", ".pptx":
		parseOOXMLMeta(data, &m)
	}
	return m, m.Author != "" || m.Creator != "" || m.Producer != "" || m.Title != ""
}

func parsePDFMeta(data []byte, m *docMeta) {
	info := regexp.MustCompile(`(?s)/Info\s*<<(.*?)>>`).FindSubmatch(data)
	if info == nil {
		return
	}
	str := string(info[1])
	pick := func(key string) string {
		re := regexp.MustCompile(`/` + key + `\s*\(([^)]*)\)`)
		if mm := re.FindStringSubmatch(str); mm != nil {
			return mm[1]
		}
		return ""
	}
	m.Title = pick("Title")
	m.Author = pick("Author")
	m.Creator = pick("Creator")
	m.Producer = pick("Producer")
	m.Created = pick("CreationDate")
	// Trailer /Info sometimes sits outside an object; grab XMP creator as a
	// fallback for documents that strip classic Info entries.
	if m.Author == "" && m.Creator == "" {
		if x := regexp.MustCompile(`dc:creator[^>]*>([^<]+)`).FindSubmatch(data); x != nil {
			m.Author = string(x[1])
		}
	}
	m.Software = m.Producer
}

type coreProps struct {
	XMLName  xml.Name `xml:"core-properties"`
	Title    string   `xml:"title"`
	Creator  string   `xml:"creator"`
	Created  string   `xml:"created"`
	LastMod  string   `xml:"modified"`
}

func parseOOXMLMeta(data []byte, m *docMeta) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return
	}
	for _, f := range zr.File {
		if f.Name != "docProps/core.xml" && f.Name != "docProps/app.xml" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		content, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			continue
		}
		if f.Name == "docProps/core.xml" {
			var cp coreProps
			if xml.Unmarshal(content, &cp) == nil {
				m.Title = cp.Title
				m.Creator = cp.Creator
				m.Created = cp.Created
				if m.Author == "" {
					m.Author = cp.Creator
				}
			}
		}
		if f.Name == "docProps/app.xml" {
			if x := regexp.MustCompile(`<Application>([^<]+)`).FindSubmatch(content); x != nil {
				m.Software = string(x[1])
				m.Producer = m.Software
			}
		}
	}
}

// Verify reports extracted metadata.
func (*Metadata) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	v, ok := ctx.GetState("osint.metadata")
	if !ok {
		return nil, fmt.Errorf("osint.metadata not run")
	}
	r, _ := v.(metadataResult)
	imp := &attacks.Impact{Summary: fmt.Sprintf("metadata extracted from %d/%d document(s)", len(r.Files), r.Total)}
	for _, m := range r.Files {
		imp.Add(filepath.Base(m.File), fmt.Sprintf("author=%q prod=%q", m.Author, m.Producer))
	}
	return imp, nil
}

// Cleanup is a no-op.
func (*Metadata) Cleanup(ctx *attacks.AttackCtx) error { return nil }

var _ attacks.Module = (*Metadata)(nil)

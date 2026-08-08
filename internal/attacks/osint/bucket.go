package osint

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/qyvora/toha3ee/internal/attacks"
)

// BucketEnum enumerates publicly readable cloud storage buckets (AWS S3, Google
// Cloud Storage, Azure Blob) that share an org's naming pattern. Buckets are
// legitimate third-party infrastructure; only HTTP HEAD/GET to the public
// endpoints is used.
type BucketEnum struct{}

// Meta implements attacks.Module.
func (*BucketEnum) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "osint.bucket",
		Category:    "osint",
		Risk:        attacks.RiskInfo,
		Targets:     []string{"keyword"},
		Description: "discover publicly listable S3 / GCS / Azure storage buckets matching an org naming pattern",
		Limitations: "only probes public cloud endpoints; a 403/404 tells buckets apart but cannot read private ones",
	}
}

type bucketFinding struct {
	Provider string
	URL      string
	Status   int
}

var bucketSuffixes = []string{
	"", "-backup", "-backups", "-backup2", "-dev", "-development", "-stage", "-staging",
	"-prod", "-production", "-test", "-testing", "-demo", "-qa", "-uat", "-logs",
	"-log", "-data", "-files", "-file", "-uploads", "-upload", "-assets", "-static",
	"-media", "-public", "-private", "-internal", "-old", "-archive", "-archives",
	"-snapshots", "-snapshot", "-database", "-db", "-sql", "-export", "-exports",
}

// Preflight needs a keyword.
func (*BucketEnum) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	t, err := target(ctx, "osint.bucket", "target")
	if err != nil {
		rep.AddFixable("target", err.Error())
		return rep, nil
	}
	rep.AddOK("target", t)
	return rep, nil
}

// Run probes candidate bucket names across the three big providers.
func (*BucketEnum) Run(ctx *attacks.AttackCtx, opts map[string]string) error {
	t := ctx.Conf.Get("osint.bucket", "target")
	if o, ok := opts["target"]; ok && o != "" {
		t = o
	}
	timeout := ctx.Conf.GetDuration("osint.bucket", "timeout", 8*time.Second)
	suffixes := bucketSuffixes
	if s := ctx.Conf.Get("osint.bucket", "suffixes"); s != "" {
		suffixes = strings.Fields(s)
	}

	client := &http.Client{Timeout: timeout}
	var found []bucketFinding
	checked := 0
	for _, suf := range suffixes {
		name := strings.ToLower(t + suf)
		if strings.Contains(name, ".") || strings.Contains(name, "_") {
			continue
		}
		checked++
		if res, ok := probeS3(client, name); ok {
			found = append(found, res)
		}
		if res, ok := probeGCS(client, name); ok {
			found = append(found, res)
		}
		if res, ok := probeAzure(client, name); ok {
			found = append(found, res)
		}
	}
	ctx.SetState("osint.bucket", found)
	ctx.Printf("[*] osint.bucket: checked %d candidate name(s), found %d accessible bucket(s).\n", checked, len(found))
	return nil
}

func probeS3(client *http.Client, name string) (bucketFinding, bool) {
	url := "https://" + name + ".s3.amazonaws.com/"
	resp, err := client.Get(url)
	if err != nil {
		return bucketFinding{}, false
	}
	defer resp.Body.Close()
	body := make([]byte, 256)
	n, _ := resp.Body.Read(body)
	text := strings.ToLower(string(body[:n]))
	if resp.StatusCode == http.StatusOK {
		if strings.Contains(text, "<listbucketresult") || strings.Contains(text, "<key>") || strings.Contains(text, "<name>") {
			return bucketFinding{"s3", url, 200}, true
		}
	}
	if resp.StatusCode == 403 && strings.Contains(text, "accessdenied") {
		return bucketFinding{"s3", url, 403}, true
	}
	return bucketFinding{}, false
}

func probeGCS(client *http.Client, name string) (bucketFinding, bool) {
	url := "https://storage.googleapis.com/" + name + "/"
	resp, err := client.Get(url)
	if err != nil {
		return bucketFinding{}, false
	}
	defer resp.Body.Close()
	body := make([]byte, 256)
	n, _ := resp.Body.Read(body)
	text := strings.ToLower(string(body[:n]))
	if resp.StatusCode == http.StatusOK && strings.Contains(text, "<listbucketresult") {
		return bucketFinding{"gcs", url, 200}, true
	}
	if resp.StatusCode == 403 {
		return bucketFinding{"gcs", url, 403}, true
	}
	return bucketFinding{}, false
}

func probeAzure(client *http.Client, name string) (bucketFinding, bool) {
	url := "https://" + name + ".blob.core.windows.net/?comp=list"
	resp, err := client.Get(url)
	if err != nil {
		return bucketFinding{}, false
	}
	defer resp.Body.Close()
	body := make([]byte, 256)
	n, _ := resp.Body.Read(body)
	text := strings.ToLower(string(body[:n]))
	if resp.StatusCode == http.StatusOK && strings.Contains(text, "enumerationresults") {
		return bucketFinding{"azure", url, 200}, true
	}
	if resp.StatusCode == 403 || resp.StatusCode == 409 {
		return bucketFinding{"azure", url, resp.StatusCode}, true
	}
	return bucketFinding{}, false
}

// Verify reports accessible buckets.
func (*BucketEnum) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	v, ok := ctx.GetState("osint.bucket")
	if !ok {
		return nil, fmt.Errorf("osint.bucket not run")
	}
	found, _ := v.([]bucketFinding)
	imp := &attacks.Impact{Summary: fmt.Sprintf("%d accessible cloud bucket(s)", len(found))}
	for _, f := range found {
		imp.Add(f.Provider, fmt.Sprintf("%s (HTTP %d)", f.URL, f.Status))
	}
	return imp, nil
}

// Cleanup is a no-op.
func (*BucketEnum) Cleanup(ctx *attacks.AttackCtx) error { return nil }

var _ attacks.Module = (*BucketEnum)(nil)

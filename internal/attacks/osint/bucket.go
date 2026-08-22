package osint

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/QYVORA/qyvora-toha3ee/internal/attacks"
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

// bucketFinding records one accessible bucket: which cloud provider it lives
// on, the public URL probed, and the HTTP status that confirmed access (200 for
// a listable bucket, 403 for an existing-but-locked one).
type bucketFinding struct {
	Provider string
	URL      string
	Status   int
}

// bucketSuffixes is the default wordlist of environment/role suffixes appended
// to the org keyword (prod, staging, backups, uploads, ...). These mirror the
// naming conventions teams commonly use, which is what makes unauthenticated
// discovery realistic. The empty first entry probes the bare keyword itself.
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
	// Pull the configured keyword, but let an on-the-fly --target override win.
	t := ctx.Conf.Get("osint.bucket", "target")
	if o, ok := opts["target"]; ok && o != "" {
		t = o
	}
	timeout := ctx.Conf.GetDuration("osint.bucket", "timeout", 8*time.Second)
	suffixes := bucketSuffixes
	// An operator-supplied "suffixes" config replaces the built-in wordlist.
	if s := ctx.Conf.Get("osint.bucket", "suffixes"); s != "" {
		suffixes = strings.Fields(s)
	}

	// One shared client is reused for every probe; the timeout on it is the
	// only pacing mechanism — probing is deliberately sequential to stay low-key.
	client := &http.Client{Timeout: timeout}
	var found []bucketFinding
	checked := 0
	for _, suf := range suffixes {
		name := strings.ToLower(t + suf)
		// Bucket names cannot contain dots or underscores; names that do could
		// never exist, so skip them rather than waste an HTTP round trip.
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

// probeS3 checks whether the candidate name exists as an S3 bucket by GETting
// the bucket's REST endpoint. A 200 whose body lists objects means the bucket
// is publicly listable; a 403 "AccessDenied" means the bucket exists but is
// private — both are useful signal.
func probeS3(client *http.Client, name string) (bucketFinding, bool) {
	// Virtual-hosted style URL: https://<bucket>.s3.amazonaws.com/
	url := "https://" + name + ".s3.amazonaws.com/"
	resp, err := client.Get(url)
	if err != nil {
		// DNS/network failure usually means no such bucket; treat as not found.
		return bucketFinding{}, false
	}
	defer func() { _ = resp.Body.Close() }()
	// Read only the first 256 bytes — enough to fingerprint the XML envelope —
	// without pulling a potentially large bucket listing into memory.
	body := make([]byte, 256)
	n, _ := resp.Body.Read(body)
	text := strings.ToLower(string(body[:n]))
	if resp.StatusCode == http.StatusOK {
		// A real listing contains <ListBucketResult> with <Key> entries; a
		// "NoSuchBucket" XML error also returns 404/200-family responses but
		// lacks these markers.
		if strings.Contains(text, "<listbucketresult") || strings.Contains(text, "<key>") || strings.Contains(text, "<name>") {
			return bucketFinding{"s3", url, 200}, true
		}
	}
	if resp.StatusCode == 403 && strings.Contains(text, "accessdenied") {
		// Existing but access-controlled bucket — still worth reporting as the
		// org's infrastructure footprint.
		return bucketFinding{"s3", url, 403}, true
	}
	return bucketFinding{}, false
}

// probeGCS checks Google Cloud Storage. Unlike S3, GCS names all live under
// one hostname (https://storage.googleapis.com/<bucket>/), so a name collision
// cannot be told apart by host alone and the XML body is the discriminator.
func probeGCS(client *http.Client, name string) (bucketFinding, bool) {
	url := "https://storage.googleapis.com/" + name + "/"
	resp, err := client.Get(url)
	if err != nil {
		return bucketFinding{}, false
	}
	defer func() { _ = resp.Body.Close() }()
	body := make([]byte, 256)
	n, _ := resp.Body.Read(body)
	text := strings.ToLower(string(body[:n]))
	// GCS returns the same <ListBucketResult> envelope as S3 for public buckets.
	if resp.StatusCode == http.StatusOK && strings.Contains(text, "<listbucketresult") {
		return bucketFinding{"gcs", url, 200}, true
	}
	if resp.StatusCode == 403 {
		// A 403 here implies an existing bucket (GCS returns 404 for unknown
		// namespaces), so record it as an access-controlled footprint.
		return bucketFinding{"gcs", url, 403}, true
	}
	return bucketFinding{}, false
}

// probeAzure checks Azure Blob containers. The listing is triggered by the
// special "?comp=list" query parameter; public containers reply with an
// <EnumerationResults> document.
func probeAzure(client *http.Client, name string) (bucketFinding, bool) {
	url := "https://" + name + ".blob.core.windows.net/?comp=list"
	resp, err := client.Get(url)
	if err != nil {
		return bucketFinding{}, false
	}
	defer func() { _ = resp.Body.Close() }()
	body := make([]byte, 256)
	n, _ := resp.Body.Read(body)
	text := strings.ToLower(string(body[:n]))
	if resp.StatusCode == http.StatusOK && strings.Contains(text, "enumerationresults") {
		return bucketFinding{"azure", url, 200}, true
	}
	// 403 = private container; 409 = container exists but the listing request
	// was refused. Both indicate an existing Azure resource under the org name.
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
func (*BucketEnum) Cleanup(_ *attacks.AttackCtx) error { return nil }

var _ attacks.Module = (*BucketEnum)(nil)

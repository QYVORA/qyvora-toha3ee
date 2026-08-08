package recon

import "testing"

func TestParseNVD(t *testing.T) {
	body := `{
	  "vulnerabilities": [
	    {"cve": {
	      "id": "CVE-2023-44487",
	      "descriptions": [{"lang":"en","value":"The HTTP/2 protocol allows request smuggling and rapid-reset DoS."}],
	      "metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": "HIGH"}}]}
	    }},
	    {"cve": {
	      "id": "CVE-2020-1472",
	      "descriptions": [{"lang":"en","value":"Zerologon privilege escalation."}],
	      "metrics": {"cvssMetricV2": [{"baseSeverity": "HIGH"}]}
	    }}
	  ]
	}`
	cves, err := parseNVD([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(cves) != 2 {
		t.Fatalf("got %d CVEs", len(cves))
	}
	if cves[0].ID != "CVE-2023-44487" || cves[0].Severity != "HIGH" {
		t.Errorf("first CVE wrong: %+v", cves[0])
	}
	if cves[1].Severity != "HIGH" {
		t.Errorf("v2 metric severity fallback failed: %+v", cves[1])
	}
}

func TestParseCVEOrg(t *testing.T) {
	body := `{
	  "cveId": "CVE-2023-44487",
	  "containers": {"cna": {
	    "descriptions": [{"lang":"en","value":"HTTP/2 rapid reset."}],
	    "metrics": [{"cvssV3_1": {"baseSeverity": "CRITICAL"}}]
	  }}
	}`
	c, err := parseCVEOrg([]byte(body), "cve-2023-44487")
	if err != nil {
		t.Fatal(err)
	}
	if c.ID != "CVE-2023-44487" || c.Severity != "CRITICAL" || c.Service != "cve.org" {
		t.Errorf("wrong record: %+v", c)
	}
}

func TestParseCVEOrgFallbackID(t *testing.T) {
	// A record with an empty cveId must fall back to the requested ID.
	c, err := parseCVEOrg([]byte(`{"containers":{"cna":{"descriptions":[]}}}`), "CVE-2021-0001")
	if err != nil {
		t.Fatal(err)
	}
	if c.ID != "CVE-2021-0001" {
		t.Errorf("fallback ID = %q", c.ID)
	}
}

func TestFirstEnglish(t *testing.T) {
	ds := []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	}{
		{Lang: "es", Value: "espanol"},
		{Lang: "en", Value: "english"},
	}
	if got := firstEnglish(ds); got != "english" {
		t.Errorf("got %q", got)
	}
}

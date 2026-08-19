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

func TestMatchBannerNarrowMatching(t *testing.T) {
	tests := []struct {
		name    string
		banner  string
		port    uint16
		wantCVE string // empty = no match
	}{
		{"nginx without version does not match CVE-2023-44487", "nginx", 80, ""},
		{"nginx with version matches CVE-2023-44487", "nginx/1.24.0", 80, "CVE-2023-44487"},
		{"httpd without version does not match", "Apache", 80, ""},
		{"httpd with version matches", "Apache/2.4.49", 80, "CVE-2021-41773"},
		{"generic HP printer does not match CVE-2023-27350", "HP Printer", 80, ""},
		{"specific HP LaserJet matches", "HP LaserJet Pro MFP M428", 80, "CVE-2023-27350"},
		{"Brother HL-L matches", "Brother HL-L2350DW", 80, "CVE-2023-27350"},
		{"port 8443 without cisco banner no match", "Apache Tomcat", 8443, ""},
		{"port 8443 with cisco banner matches", "Cisco ASA 5506", 8443, "CVE-2020-3452"},
		{"OpenSSH old version matches", "OpenSSH_8.4p1", 22, "CVE-2023-48795"},
		{"OpenSSH new version does not match", "OpenSSH_9.6p1", 22, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchBanner(tt.banner, tt.port)
			if tt.wantCVE == "" {
				if got != nil {
					t.Errorf("expected no match, got %s", got.id)
				}
			} else {
				if got == nil {
					t.Errorf("expected %s, got no match", tt.wantCVE)
				} else if got.id != tt.wantCVE {
					t.Errorf("expected %s, got %s", tt.wantCVE, got.id)
				}
			}
		})
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

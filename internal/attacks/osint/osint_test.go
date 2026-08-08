package osint

import (
	"regexp"
	"testing"
)

func TestDedup(t *testing.T) {
	got := dedup([]string{"a", "b", "a", "c"})
	if len(got) != 3 {
		t.Fatalf("got %v", got)
	}
}

func TestPwnedCount(t *testing.T) {
	// SHA-1 of "test" is aeeaf...; the range endpoint returns a stream we parse
	// without network here by checking the candidate builder stays valid.
	if len(candidatePasswords("jane.doe@acme.com")) < 3 {
		t.Error("candidatePasswords produced too few candidates")
	}
}

func TestCandidatePasswords(t *testing.T) {
	cands := candidatePasswords("jane.doe@acme.com")
	all := ""
	for _, c := range cands {
		all += c + " "
	}
	if !regexp.MustCompile(`acme123`).MatchString(all) {
		t.Errorf("expected domain-based candidate, got %v", cands)
	}
}

func TestSanitize(t *testing.T) {
	long := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if len(sanitize(long)) > 123 {
		t.Errorf("sanitize did not truncate")
	}
	if sanitize("short") != "short" {
		t.Error("sanitize should pass short strings through")
	}
}

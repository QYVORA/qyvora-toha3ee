package osint

import (
	"fmt"
	"strings"
	"time"

	"github.com/QYVORA/qyvora-toha3ee/internal/attacks"
)

// HIBP checks whether candidate passwords have appeared in public breach data
// using the Pwned Passwords range API, which returns hashed suffixes only and
// never transmits the plaintext password off the client.
type HIBP struct{}

// Meta implements attacks.Module.
func (*HIBP) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "osint.hibp",
		Category:    "osint",
		Risk:        attacks.RiskInfo,
		Targets:     []string{"password", "email"},
		Description: "breach-exposure check via Pwned Passwords k-anonymity range API",
		Limitations: "only proves historical exposure, not current use; the breach feed itself needs a HIBP key",
	}
}

// hibpResult carries just the count of exposed candidate passwords.
type hibpResult struct {
	Count int
}

// Preflight needs a password (or email to test common candidates).
func (*HIBP) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	if ctx.Conf.Get("osint.hibp", "password") == "" && ctx.Conf.Get("osint.hibp", "email") == "" {
		rep.AddFixable("password", "set osint.hibp.password to a candidate password to check")
		return rep, nil
	}
	rep.AddOK("target", "password/email configured")
	return rep, nil
}

// Run checks each candidate password against the range API.
func (*HIBP) Run(ctx *attacks.AttackCtx, opts map[string]string) error {
	timeout := ctx.Conf.GetDuration("osint.hibp", "timeout", 15*time.Second)
	// Whitespace-separated list of literal candidate passwords from config.
	passwords := strings.Fields(ctx.Conf.Get("osint.hibp", "password"))
	email := ctx.Conf.Get("osint.hibp", "email")
	if email != "" {
		// An email alone can still seed the check with derived candidates.
		passwords = append(passwords, candidatePasswords(email)...)
	}
	if len(passwords) == 0 {
		return fmt.Errorf("osint.hibp: set osint.hibp.password or osint.hibp.email first")
	}
	exposed := 0
	for _, pw := range passwords {
		count, err := pwnedCount(pw, timeout)
		if err != nil {
			// A single failed range lookup (network hiccup, rate limit) is
			// skipped; the other candidates still get checked.
			continue
		}
		if count > 0 {
			exposed++
			emit(ctx, "finding", fmt.Sprintf("osint.hibp: password appeared %d time(s) in public breach data", count))
		}
	}
	ctx.SetState("osint.hibp", hibpResult{Count: exposed})
	ctx.Printf("[*] osint.hibp: %d of %d candidate password(s) appear in breach data.\n", exposed, len(passwords))
	return nil
}

// pwnedCount returns how many times pw appears in breach data, using HIBP's
// k-anonymity range API: only the first 5 hex chars of the SHA-1 sum are ever
// sent, and the full suffix is matched against the returned list client-side.
func pwnedCount(pw string, timeout time.Duration) (int, error) {
	sum := sha1Hex(pw)
	// The range endpoint is keyed on the 5-character prefix; the remainder is
	// the suffix we must match locally — the plaintext never leaves this host.
	prefix, suffix := sum[:5], sum[5:]
	raw, err := httpGet("https://api.pwnedpasswords.com/range/"+prefix, timeout)
	if err != nil {
		return 0, err
	}
	want := strings.ToUpper(suffix)
	// The response is one "<SUFFIX>:<count>" per line; compare case-insensitively
	// since the API uppercases while our hex digest is lowercase.
	for _, line := range strings.Split(string(raw), "\r\n") {
		line = strings.TrimSpace(line)
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], want) {
			n := 0
			// The count field is a plain integer; Sscanf tolerates stray
			// whitespace around it. A count of 0 means "seen but unused".
			_, _ = fmt.Sscanf(parts[1], "%d", &n)
			return n, nil
		}
	}
	// Suffix not present in the returned range: never seen in a breach.
	return 0, nil
}

// candidatePasswords derives typical guess-password candidates from an email
// (name + company + year patterns) so an email address can seed the check.
func candidatePasswords(email string) []string {
	// The local part of the address is the most likely personal seed.
	user := email
	if i := strings.Index(email, "@"); i > 0 {
		user = email[:i]
	}
	// The org's SLD (e.g. "acme" from user@acme.example.com) seeds company
	// variants; the TLD and subdomains are dropped as noise.
	domain := ""
	if i := strings.Index(email, "@"); i >= 0 {
		domain = email[i+1:]
		if j := strings.Index(domain, "."); j > 0 {
			domain = domain[:j]
		}
	}
	// Common weak-password scaffolding: bare name, name+suffix, year suffixes.
	seeds := []string{user, domain, user + "123", user + "2024", user + "2025", user + "2026"}
	if domain != "" {
		seeds = append(seeds, domain+"123", user+"@"+domain)
	}
	return seeds
}

// Verify reports the exposure count.
func (*HIBP) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	v, ok := ctx.GetState("osint.hibp")
	if !ok {
		return nil, fmt.Errorf("osint.hibp not run")
	}
	r, _ := v.(hibpResult)
	return &attacks.Impact{Summary: fmt.Sprintf("%d password(s) exposed in breach data", r.Count)}, nil
}

// Cleanup is a no-op.
func (*HIBP) Cleanup(ctx *attacks.AttackCtx) error { return nil }

var _ attacks.Module = (*HIBP)(nil)

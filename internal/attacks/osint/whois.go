package osint

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/QYVORA/qyvora-toha3ee/internal/attacks"
	"github.com/QYVORA/qyvora-toha3ee/internal/events"
)

// WHOIS performs a WHOIS/RDAP query for a domain or IP address through the
// IANA referral chain, then extracts the ownership record's key fields.
type WHOIS struct{}

// Meta implements attacks.Module.
func (*WHOIS) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "osint.whois",
		Category:    "osint",
		Risk:        attacks.RiskInfo,
		Targets:     []string{"domain"},
		Passive:     true,
		Description: "WHOIS lookup of domain ownership, registrar and registration dates via the IANA referral chain",
		Limitations: "WHOIS data is as reliable as the registrar reports it; privacy services may redact registrant fields",
	}
}

// Preflight needs a query target.
func (*WHOIS) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	if _, err := target(ctx, "osint.whois", "query"); err != nil {
		rep.AddFixable("query", "set osint.whois.query, e.g. 'set osint.whois.query example.com' or an IP")
	} else {
		rep.AddOK("query", ctx.Conf.Get("osint.whois", "query"))
	}
	return rep, nil
}

// whoisLine contains the raw WHOIS response and its originating server.
type whoisLine struct {
	server string
	text   string
}

// whoisQuery talks the WHOIS protocol (TCP 43) to a server: it opens a
// connection, writes the query as a CRLF-terminated line, and reads the
// server's reply. A single 64 KiB read is used because WHOIS responses for
// single objects fit comfortably under that; anything larger would simply be
// truncated after the first chunk.
func whoisQuery(server, query string, timeout time.Duration) (string, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(server, "43"), timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	// Bound the whole exchange (dial + write + read) with one deadline so a
	// hung registry server cannot stall the module.
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := fmt.Fprintf(conn, "%s\r\n", query); err != nil {
		return "", err
	}
	buf := make([]byte, 64<<10)
	n, _ := conn.Read(buf)
	return string(buf[:n]), nil
}

// Run walks the IANA referral chain and extracts the record's key fields.
func (*WHOIS) Run(ctx *attacks.AttackCtx, opts map[string]string) error {
	query, err := target(ctx, "osint.whois", "query")
	if err != nil {
		return err
	}
	query = strings.TrimSpace(query)
	timeout := ctx.Conf.GetDuration("osint.whois", "timeout", 8*time.Second)
	// An explicit "server" config short-circuits the referral chain: the query
	// goes straight to the configured WHOIS host. The timeout is doubled here
	// because authoritative servers are often slow on the first connection.
	if s := ctx.Conf.Get("osint.whois", "server"); s != "" {
		timeout *= 2
		raw, err := whoisQuery(s, query, timeout)
		if err != nil {
			return fmt.Errorf("osint.whois: %w", err)
		}
		emitWhois(ctx, whoisLine{server: s, text: raw})
		return nil
	}

	// IANA referral: for domains it names the registry WHOIS server; for IPs
	// it names the responsible RIR. whois.iana.org is the fixed entry point
	// that tells us which registry actually holds the record.
	ref, err := whoisQuery("whois.iana.org", query, timeout)
	if err != nil {
		return fmt.Errorf("osint.whois: iana referral: %w", err)
	}
	if !strings.Contains(strings.ToLower(ref), "refer:") && !strings.Contains(strings.ToLower(ref), "whois:") {
		// IANA returned the record directly (rare); emit it as-is.
		emitWhois(ctx, whoisLine{server: "whois.iana.org", text: ref})
		return nil
	}
	// The referral answer itself is useful (it names the registry), so it is
	// emitted before the authoritative record overwrites nothing.
	emitWhois(ctx, whoisLine{server: "whois.iana.org", text: ref})
	authoritative := referralServer(ref)
	if authoritative == "" {
		return fmt.Errorf("osint.whois: no authoritative WHOIS server found in IANA referral")
	}
	// Second hop: query the registry/RIR server the referral named.
	raw, err := whoisQuery(authoritative, query, timeout)
	if err != nil {
		return fmt.Errorf("osint.whois: %s: %w", authoritative, err)
	}
	emitWhois(ctx, whoisLine{server: authoritative, text: raw})
	return nil
}

// referRe matches the "refer:" line in an IANA domain referral; whoisRe
// matches the "whois:" line in an IANA IP/RIR referral. keyRe matches any
// "Field: value" line in a WHOIS record, tolerating spaces and hyphens in the
// field name — it is the workhorse of the extraction loop.
var (
	referRe = regexp.MustCompile(`(?m)^refer:\s*(\S+)`)
	whoisRe = regexp.MustCompile(`(?m)^whois:\s*(\S+)`)
	keyRe   = regexp.MustCompile(`(?m)^([A-Za-z][A-Za-z -]{0,32}):\s*(.+)$`)
)

// referralServer extracts the authoritative WHOIS server from an IANA answer.
// Domains use "refer:"; IPs use "whois:" — try both, return the first hit.
func referralServer(s string) string {
	for _, re := range []*regexp.Regexp{referRe, whoisRe} {
		if m := re.FindStringSubmatch(s); len(m) == 2 {
			return strings.TrimSpace(m[1])
		}
	}
	return ""
}

// knownFields maps the many label spellings registries use onto a canonical
// report key: "creation date"/"registration date" both become "created", etc.
// Unlisted fields are simply not surfaced in the report.
var knownFields = map[string]string{
	"registrar": "registrar", "registration date": "created", "creation date": "created",
	"updated date": "updated", "expiration date": "expires", "name server": "nameservers",
	"registrant": "registrant", "organisation": "organisation", "netname": "netname",
	"inetnum": "inetnum", "country": "country", "status": "status",
}

// emitWhois extracts and emits the record's key fields. It parses every
// "Field: value" line, folds matched labels into their canonical key, and
// pushes one log line per canonical field plus the whole set into state.
func emitWhois(ctx *attacks.AttackCtx, wl whoisLine) {
	// Multiple registrars/registrants with the same field are collected so a
	// record with several name servers lists all of them on one line.
	extracted := map[string][]string{}
	var lines []string
	for _, m := range keyRe.FindAllStringSubmatch(wl.text, -1) {
		k := strings.ToLower(strings.TrimSpace(m[1]))
		v := strings.TrimSpace(m[2])
		if canon, ok := knownFields[k]; ok {
			extracted[canon] = append(extracted[canon], v)
		}
	}
	// Collect the canonical keys into a slice; iteration order follows map
	// iteration order, which is fine for a report-style log output.
	keys := make([]string, 0, len(extracted))
	for k := range extracted {
		keys = append(keys, k)
	}
	for _, k := range keys {
		msg := fmt.Sprintf("osint.whois: %s = %s", k, strings.Join(extracted[k], ", "))
		lines = append(lines, msg)
		ctx.Emit(events.TopicLog, msg, nil)
	}
	ctx.SetState("osint.whois", lines)
}

// Verify reports the extracted record.
func (*WHOIS) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	v, ok := ctx.GetState("osint.whois")
	if !ok {
		return nil, fmt.Errorf("osint.whois not run")
	}
	lines, _ := v.([]string)
	imp := &attacks.Impact{Summary: fmt.Sprintf("extracted %d WHOIS field(s)", len(lines))}
	imp.Add("fields", strconv.Itoa(len(lines)))
	for _, l := range lines {
		imp.Add("field", strings.TrimPrefix(l, "osint.whois: "))
	}
	return imp, nil
}

// Cleanup is a no-op.
func (*WHOIS) Cleanup(ctx *attacks.AttackCtx) error { return nil }

var _ attacks.Module = (*WHOIS)(nil)

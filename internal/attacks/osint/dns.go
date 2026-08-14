package osint

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/QYVORA/qyvora-toha3ee/internal/attacks"
	"github.com/QYVORA/qyvora-toha3ee/internal/events"
)

// DNSEnum enumerates public DNS records for a domain and attempts an AXFR
// zone transfer against its authoritative nameservers.
type DNSEnum struct{}

// Meta implements attacks.Module.
func (*DNSEnum) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "osint.dns",
		Category:    "osint",
		Risk:        attacks.RiskInfo,
		Targets:     []string{"domain"},
		Passive:     true,
		Description: "enumerate A/AAAA/MX/NS/TXT/SOA/CNAME records and attempt AXFR zone transfer for a domain",
		Limitations: "misconfigured resolvers may rate-limit; AXFR succeeds only when the target allows it",
	}
}

// Preflight needs a target domain.
func (*DNSEnum) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	if _, err := target(ctx, "osint.dns", "domain"); err != nil {
		rep.AddFixable("domain", "set osint.dns.domain, e.g. 'set osint.dns.domain example.com'")
	} else {
		rep.AddOK("domain", ctx.Conf.Get("osint.dns", "domain"))
	}
	return rep, nil
}

// recordTypes is the default answer record set queried for a domain, mapping
// the config-facing type names to the miekg/dns wire type constants. Records
// like A/AAAA/MX expose the org's hosting topology without touching it.
var recordTypes = map[string]uint16{
	"A": dns.TypeA, "AAAA": dns.TypeAAAA, "MX": dns.TypeMX,
	"NS": dns.TypeNS, "TXT": dns.TypeTXT, "SOA": dns.TypeSOA,
	"CNAME": dns.TypeCNAME, "PTR": dns.TypePTR,
}

// Run queries each record type and tries an AXFR.
func (*DNSEnum) Run(ctx *attacks.AttackCtx, opts map[string]string) error {
	domain, err := target(ctx, "osint.dns", "domain")
	if err != nil {
		return err
	}
	// Normalize: lower-case, strip whitespace and any trailing root dot so the
	// query is always built from a clean FQDN.
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")

	// Use a configured resolver if given (e.g. a public DNS over UDP endpoint);
	// otherwise fall back to the machine's first /etc/resolv.conf nameserver.
	resolver := ctx.Conf.Get("osint.dns", "resolver")
	if resolver == "" {
		resolver, err = systemResolver()
		if err != nil {
			return fmt.Errorf("osint.dns: %w", err)
		}
	}
	// Resolvers given without a port get the standard DNS port appended so a
	// bare "8.8.8.8" still dials correctly.
	if !strings.Contains(resolver, ":") {
		resolver += ":53"
	}

	// Restrict the query set if configured; the default is every type in
	// recordTypes, sorted for deterministic behavior.
	types := splitFields(ctx.Conf.Get("osint.dns", "types"))
	if len(types) == 0 {
		for t := range recordTypes {
			types = append(types, t)
		}
		sort.Strings(types)
	}

	var records []string
	for _, t := range types {
		qt, ok := recordTypes[strings.ToUpper(t)]
		if !ok {
			// Unknown/unsupported type names are skipped silently.
			continue
		}
		for _, rr := range queryRecords(domain, qt, resolver) {
			records = append(records, rr)
			// Stream each answer onto the shared log topic as it is found.
			ctx.Emit(events.TopicLog, fmt.Sprintf("osint.dns: %s %s", domain, rr), nil)
		}
	}

	// AXFR zone transfer is attempted by default; it is a passive read of
	// whatever the authoritative server is willing to hand over.
	axfr := ctx.Conf.GetBool("osint.dns", "axfr", true)
	if axfr {
		for _, ns := range queryRecords(domain, dns.TypeNS, resolver) {
			// The NS answer is formatted like "NS ns1.example.com." — take the
			// second field and strip its trailing dot to get the hostname.
			host := strings.Fields(ns)
			if len(host) < 2 {
				continue
			}
			name := strings.TrimSuffix(host[1], ".")
			for _, rr := range tryAXFR(domain, name) {
				records = append(records, "AXFR "+rr)
				ctx.Emit(events.TopicLog, fmt.Sprintf("osint.dns: axfr %s <- %s: %s", domain, name, rr), nil)
			}
		}
	}

	ctx.SetState("osint.dns", records)
	ctx.Printf("[*] osint.dns complete: %d record(s) for %s.\n", len(records), domain)
	return nil
}

// splitFields tokenizes a config value on commas and spaces, dropping empties
// so "A, MX NS" yields ["A", "MX", "NS"].
func splitFields(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' }) {
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

// queryRecords performs a single DNS query over UDP for the given type and
// renders each answer into a compact, human-readable string. Errors (timeouts,
// NXDOMAIN, truncated responses) yield no records rather than aborting the run.
func queryRecords(domain string, qt uint16, server string) []string {
	var out []string
	// One short-lived UDP client per query; 5s bounds a stuck resolver.
	c := &dns.Client{Net: "udp", Timeout: 5 * time.Second}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), qt)
	m.RecursionDesired = true
	r, _, err := c.Exchange(m, server)
	if err != nil || r == nil {
		return out
	}
	for _, rr := range r.Answer {
		// Type-specific formatting pulls out the interesting fields (MX
		// preference, SOA serial, TXT payload); everything else falls through
		// to the wire-format string for completeness.
		switch q := rr.(type) {
		case *dns.MX:
			out = append(out, fmt.Sprintf("MX %s pri %d", q.Mx, q.Preference))
		case *dns.SOA:
			out = append(out, fmt.Sprintf("SOA ns=%s hostmaster=%s serial=%d", q.Ns, q.Mbox, q.Serial))
		case *dns.TXT:
			// TXT chunks are joined without separators to reconstruct the
			// logical string (e.g. SPF fragments split at 255 bytes).
			out = append(out, fmt.Sprintf("TXT %q", strings.Join(q.Txt, "")))
		default:
			h := rr.Header()
			out = append(out, fmt.Sprintf("%s %s", typeName(h.Rrtype), rr.String()))
		}
	}
	return out
}

// tryAXFR attempts a zone transfer of domain from the nameserver over TCP.
// Zone transfers are the single biggest DNS misconfiguration payoff — a
// successful AXFR hands over every record in the zone. A refused transfer
// (REFUSED/NOTAUTH) simply yields no output.
func tryAXFR(domain, ns string) []string {
	var out []string
	m := new(dns.Msg)
	m.SetAxfr(dns.Fqdn(domain))
	// AXFR is TCP-only and streamed, so the transfer needs explicit dial and
	// read deadlines to avoid hanging on a server that never completes.
	t := &dns.Transfer{DialTimeout: 4 * time.Second, ReadTimeout: 8 * time.Second}
	en, err := t.In(m, netJoinHostPort(ns))
	if err != nil {
		return out
	}
	for env := range en {
		if env.Error != nil {
			// Mid-stream failure (e.g. server closed the connection) ends the
			// transfer; keep whatever RRs already arrived.
			return out
		}
		for _, rr := range env.RR {
			out = append(out, rr.String())
		}
	}
	return out
}

// netJoinHostPort joins a bare hostname with the standard DNS port.
func netJoinHostPort(host string) string {
	return host + ":53"
}

// typeName maps a numeric DNS RR type to its mnemonic ("MX", "SOA", ...);
// unknown types fall back to the bare integer so nothing is silently dropped.
func typeName(t uint16) string {
	if s, ok := dns.TypeToString[t]; ok {
		return s
	}
	return strconv.Itoa(int(t))
}

// systemResolver returns the first nameserver in /etc/resolv.conf as the
// default upstream for queries when no explicit resolver is configured.
func systemResolver() (string, error) {
	cc, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return "", fmt.Errorf("read /etc/resolv.conf: %w", err)
	}
	if len(cc.Servers) == 0 {
		return "", fmt.Errorf("no nameservers in /etc/resolv.conf")
	}
	return netJoinHostPort(cc.Servers[0]), nil
}

// Verify reports the enumerated record count.
func (*DNSEnum) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	v, ok := ctx.GetState("osint.dns")
	if !ok {
		return nil, fmt.Errorf("osint.dns not run")
	}
	records, _ := v.([]string)
	imp := &attacks.Impact{Summary: fmt.Sprintf("enumerated %d DNS record(s)", len(records))}
	imp.Add("records", strconv.Itoa(len(records)))
	// Cap the individual records in the report at 50 to keep output readable.
	for i, r := range records {
		if i >= 50 {
			break
		}
		imp.Add("record", r)
	}
	return imp, nil
}

// Cleanup is a no-op.
func (*DNSEnum) Cleanup(ctx *attacks.AttackCtx) error { return nil }

var _ attacks.Module = (*DNSEnum)(nil)

package osint

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/qyvora/toha3ee/internal/attacks"
	"github.com/qyvora/toha3ee/internal/events"
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

// recordTypes is the default answer record set.
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
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")

	resolver := ctx.Conf.Get("osint.dns", "resolver")
	if resolver == "" {
		resolver, err = systemResolver()
		if err != nil {
			return fmt.Errorf("osint.dns: %w", err)
		}
	}
	if !strings.Contains(resolver, ":") {
		resolver += ":53"
	}

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
			continue
		}
		for _, rr := range queryRecords(domain, qt, resolver) {
			records = append(records, rr)
			ctx.Emit(events.TopicLog, fmt.Sprintf("osint.dns: %s %s", domain, rr), nil)
		}
	}

	axfr := ctx.Conf.GetBool("osint.dns", "axfr", true)
	if axfr {
		for _, ns := range queryRecords(domain, dns.TypeNS, resolver) {
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

func splitFields(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' }) {
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

// queryRecords returns human-readable records of type qt for the domain.
func queryRecords(domain string, qt uint16, server string) []string {
	var out []string
	c := &dns.Client{Net: "udp", Timeout: 5 * time.Second}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), qt)
	m.RecursionDesired = true
	r, _, err := c.Exchange(m, server)
	if err != nil || r == nil {
		return out
	}
	for _, rr := range r.Answer {
		switch q := rr.(type) {
		case *dns.MX:
			out = append(out, fmt.Sprintf("MX %s pri %d", q.Mx, q.Preference))
		case *dns.SOA:
			out = append(out, fmt.Sprintf("SOA ns=%s hostmaster=%s serial=%d", q.Ns, q.Mbox, q.Serial))
		case *dns.TXT:
			out = append(out, fmt.Sprintf("TXT %q", strings.Join(q.Txt, "")))
		default:
			h := rr.Header()
			out = append(out, fmt.Sprintf("%s %s", typeName(h.Rrtype), rr.String()))
		}
	}
	return out
}

// tryAXFR attempts a zone transfer of domain from the nameserver.
func tryAXFR(domain, ns string) []string {
	var out []string
	m := new(dns.Msg)
	m.SetAxfr(dns.Fqdn(domain))
	t := &dns.Transfer{DialTimeout: 4 * time.Second, ReadTimeout: 8 * time.Second}
	en, err := t.In(m, netJoinHostPort(ns))
	if err != nil {
		return out
	}
	for env := range en {
		if env.Error != nil {
			return out
		}
		for _, rr := range env.RR {
			out = append(out, rr.String())
		}
	}
	return out
}

func netJoinHostPort(host string) string {
	return host + ":53"
}

func typeName(t uint16) string {
	if s, ok := dns.TypeToString[t]; ok {
		return s
	}
	return strconv.Itoa(int(t))
}

// systemResolver returns the first nameserver in /etc/resolv.conf.
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

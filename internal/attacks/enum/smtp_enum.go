package enum

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/QYVORA/qyvora-toha3ee/internal/attacks"
)

// SMTPEnum probes SMTP servers for user enumeration via VRFY/EXPN/RCPT TO.
// It also reports open-relay behaviour and the greeting banner.
//
// SMTP reply codes do the enumeration: VRFY <user> answers 250 when the
// mailbox exists and 550 when it does not; RCPT TO is accepted (250) for
// existing users and refused (550) otherwise. An open relay additionally
// accepts MAIL/RCPT for completely foreign domains.
type SMTPEnum struct{}

// Meta implements attacks.Module.
func (*SMTPEnum) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "smtp.enum",
		Category:    "enum",
		Risk:        attacks.RiskInfo,
		Targets:     []string{"service"},
		Description: "enumerate mail users via SMTP VRFY/EXPN/RCPT TO and test for open-relay",
		Limitations: "modern servers disable VRFY/EXPN and rate-limit RCPT TO; results depend on the server's policy",
	}
}

// smtpResult captures one server's enumeration results.
type smtpResult struct {
	Host   string
	Users  []string
	Relay  bool
	Banner string
}

// Preflight needs at least a host with port 25 open.
func (*SMTPEnum) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	for _, h := range openHosts(ctx) {
		for _, p := range h.Ports {
			if p == 25 {
				rep.AddOK("targets", fmt.Sprintf("SMTP service on %s:25", h.IP))
				return rep, nil
			}
		}
	}
	rep.AddFixable("targets", "no SMTP service (port 25) discovered; run service.synscan first")
	return rep, nil
}

// Run performs the SMTP probes.
func (*SMTPEnum) Run(ctx *attacks.AttackCtx, opts map[string]string) error {
	users := splitUsers(opts["users"], ctx.Conf.Get("smtp.enum", "users"))
	timeout := ctx.Conf.GetDuration("smtp.enum", "timeout", 4*time.Second)
	var out []smtpResult
	for _, h := range openHosts(ctx) {
		if !hasPort(h, 25) {
			continue
		}
		res, err := smtpProbe(h.IP.String(), users, timeout)
		if err != nil {
			continue
		}
		out = append(out, *res)
		if res.Relay {
			emit(ctx, "finding", fmt.Sprintf("smtp.enum: %s:25 OPEN RELAY", h.IP))
		}
		for _, u := range res.Users {
			emit(ctx, "finding", fmt.Sprintf("smtp.enum: %s:25 user=%q confirmed", h.IP, u))
		}
		emit(ctx, "log", fmt.Sprintf("smtp.enum: %s:25 banner=%q", h.IP, res.Banner))
	}
	ctx.SetState("smtp.enum", out)
	ctx.Printf("[*] smtp.enum complete: %d server(s) probed.\n", len(out))
	return nil
}

// smtpProbe drives a full SMTP conversation against one host: banner grab,
// EHLO, VRFY/EXPN per user, RCPT TO fallback and the open-relay test.
func smtpProbe(host string, users []string, timeout time.Duration) (*smtpResult, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, "25"), timeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	// A hard deadline bounds the whole conversation so a chatty or hung
	// server cannot stall the module forever.
	_ = conn.SetDeadline(time.Now().Add(timeout))
	rd := bufio.NewReader(conn)

	res := &smtpResult{Host: host}
	// The greeting is the first line the server sends on connect; it usually
	// discloses the MTA product and version.
	banner, _ := rd.ReadString('\n')
	res.Banner = strings.TrimSpace(banner)

	// cmd sends one SMTP command and reads the (possibly multi-line) reply.
	cmd := func(line string) string {
		_, _ = conn.Write([]byte(line + "\r\n"))
		reply, _ := rd.ReadString('\n')
		// Multi-line replies end with " " after 3-digit code: "250-..." lines
		// continue, a "250 ..." line terminates. Position 3 holds the dash.
		for len(reply) >= 4 && reply[3] == '-' {
			next, _ := rd.ReadString('\n')
			reply += next
		}
		return strings.TrimSpace(reply)
	}

	cmd("EHLO toha3ee")
	seen := map[string]bool{}
	for _, u := range users {
		for _, verb := range []string{"VRFY", "EXPN"} {
			r := cmd(verb + " " + u)
			// 250/251/252 => address resolved; 550 => rejected.
			if len(r) >= 3 && (r[0] == '2' || strings.HasPrefix(r, "252")) && !seen[u] {
				seen[u] = true
				res.Users = append(res.Users, u)
			}
		}
	}
	// RCPT TO: 250 => accepted (enumerable), 550 => not. This is the fallback
	// for servers with VRFY/EXPN disabled — the address is probed by starting
	// a mail transaction and watching the recipient verdict, then RSET clears
	// the envelope.
	for _, u := range users {
		if seen[u] {
			continue
		}
		r := cmd("MAIL FROM:<postmaster@" + host + ">")
		_ = r
		r = cmd("RCPT TO:<" + u + "@" + host + ">")
		cmd("RSET")
		if strings.HasPrefix(r, "250") {
			res.Users = append(res.Users, u)
		}
	}
	// Open-relay test: relay through an unrelated destination. A legit server
	// rejects the foreign recipient; accepting it proves relaying.
	r := cmd("MAIL FROM:<relaytest@example.net>")
	if strings.HasPrefix(r, "250") {
		r = cmd("RCPT TO:<relaytest@example.com>")
		res.Relay = strings.HasPrefix(r, "250")
	}
	cmd("QUIT")
	return res, nil
}

// Verify reports the confirmed users.
func (*SMTPEnum) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	v, ok := ctx.GetState("smtp.enum")
	if !ok {
		return nil, fmt.Errorf("smtp.enum not run")
	}
	res, _ := v.([]smtpResult)
	imp := &attacks.Impact{Summary: fmt.Sprintf("enumerated users on %d SMTP server(s)", len(res))}
	for _, r := range res {
		imp.Add("host", r.Host+" users="+fmt.Sprint(r.Users)+" relay="+fmt.Sprint(r.Relay))
	}
	return imp, nil
}

// Cleanup is a no-op.
func (*SMTPEnum) Cleanup(_ *attacks.AttackCtx) error { return nil }

// hasPort reports whether a HostRef has the given port open.
func hasPort(h *HostRef, want uint16) bool {
	for _, p := range h.Ports {
		if p == want {
			return true
		}
	}
	return false
}

// splitUsers turns a comma/space/newline separated username string into a
// cleaned list. Invocation options take precedence over the configured value.
func splitUsers(opt, cfg string) []string {
	src := opt
	if src == "" {
		src = cfg
	}
	var out []string
	for _, u := range strings.FieldsFunc(src, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' }) {
		u = strings.TrimSpace(u)
		if u != "" {
			out = append(out, u)
		}
	}
	return out
}

// Compile-time assertion that SMTPEnum satisfies the Module contract.
var _ attacks.Module = (*SMTPEnum)(nil)

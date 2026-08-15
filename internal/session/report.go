package session

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/QYVORA/qyvora-toha3ee/internal/store"
)

// Report is the serialized session report.
type Report struct {
	Generated time.Time       `json:"generated"`       // when the report was written
	Running   []string        `json:"running_modules"` // module ids still live at report time
	Hosts     []reportHost    `json:"hosts"`           // discovered network hosts
	Creds     []reportCred    `json:"credentials"`     // captured credentials
	Sessions  []reportSession `json:"sessions"`        // captured web sessions
	Runs      []reportRun     `json:"runs"`            // structured module execution records
	Events    []reportEvent   `json:"events"`          // framework event log
}

// reportHost is the JSON-safe view of a store host.
type reportHost struct {
	IP      string            `json:"ip"`
	MAC     string            `json:"mac"`
	Vendor  string            `json:"vendor"`
	Name    string            `json:"name"`
	OSGuess string            `json:"os_guess"`
	Ports   map[uint16]string `json:"ports"` // open port number -> service guess
}

// reportCred is the JSON-safe view of a captured credential.
type reportCred struct {
	ID       int    `json:"id"`
	Service  string `json:"service"`
	Username string `json:"username"`
	Password string `json:"password"`
	Extra    string `json:"extra,omitempty"`
	Host     string `json:"host"`
	VictimIP string `json:"victim_ip"`
	Source   string `json:"source"` // how the credential was captured
}

// reportSession is the JSON-safe view of a hijacked web session.
type reportSession struct {
	ID       int               `json:"id"`
	VictimIP string            `json:"victim_ip"`
	Host     string            `json:"host"`
	Cookies  map[string]string `json:"cookies"`
	Auth     string            `json:"auth_header,omitempty"`
}

// reportEvent is the JSON-safe view of a framework event.
type reportEvent struct {
	Time  time.Time `json:"time"`
	Topic string    `json:"topic"`
	Msg   string    `json:"message"`
}

// reportRun is the JSON-safe view of a structured module run. Metrics and
// summary carry verified impact; error/evidence_ref only appear when relevant.
type reportRun struct {
	ID          int               `json:"id"`
	Module      string            `json:"module"`
	Started     time.Time         `json:"started"`
	Finished    time.Time         `json:"finished"`
	Status      string            `json:"status"`                 // success | failed | stopped
	Error       string            `json:"error,omitempty"`        // failure message when failed
	Summary     string            `json:"summary,omitempty"`      // verified verdict
	Metrics     map[string]string `json:"metrics,omitempty"`      // quantified proof
	EvidenceRef string            `json:"evidence_ref,omitempty"` // loot this run produced
}

// buildReport snapshots the current store state into a serializable Report.
func buildReport(db *store.Store, running []string) *Report {
	rep := &Report{Generated: time.Now(), Running: running}

	// Hosts: MAC bytes are formatted to "aa:bb:..." and the ports map is
	// copied so the report does not share memory with the live store.
	for _, h := range db.Hosts() {
		rep.Hosts = append(rep.Hosts, reportHost{
			IP:      h.IP.String(),
			MAC:     macString(h.MAC),
			Vendor:  h.Vendor,
			Name:    h.Name,
			OSGuess: h.OSGuess,
			Ports:   copyPortsMap(h.Ports),
		})
	}
	for _, c := range db.Creds() {
		rep.Creds = append(rep.Creds, reportCred{
			ID: c.ID, Service: c.Service, Username: c.Username, Password: c.Password,
			Extra: c.Extra, Host: c.Host, VictimIP: c.VictimIP, Source: c.Source,
		})
	}
	for _, s := range db.Sessions() {
		rep.Sessions = append(rep.Sessions, reportSession{
			ID: s.ID, VictimIP: s.VictimIP, Host: s.Host, Cookies: s.Cookies, Auth: s.AuthHeader,
		})
	}
	for _, r := range db.Runs() {
		rep.Runs = append(rep.Runs, reportRun{
			ID: r.ID, Module: r.Module, Started: r.Started, Finished: r.Finished,
			Status: r.Status, Error: r.Error, Summary: r.Summary,
			Metrics: copyStringMap(r.Metrics), EvidenceRef: r.EvidenceRef,
		})
	}
	for _, e := range db.Events() {
		rep.Events = append(rep.Events, reportEvent{Time: e.Time, Topic: e.Topic, Msg: e.Msg})
	}
	return rep
}

// writeReport serializes rep as indented JSON to path.
func writeReport(path string, rep *Report) error {
	data, err := rep.RenderJSON()
	if err != nil {
		return err
	}
	// 0o600 keeps captured credentials unreadable by other users on the box.
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	return nil
}

// RenderJSON serializes the report as indented JSON.
func (r *Report) RenderJSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// RenderTerminal renders a human-readable summary. Credential passwords are
// redacted: the JSON format is the only one that carries plaintext loot.
func (r *Report) RenderTerminal() string {
	var b strings.Builder
	b.WriteString("toha3ee session report\n")
	b.WriteString("=====================\n")
	fmt.Fprintf(&b, "generated: %s\n", r.Generated.Format(time.RFC3339))
	fmt.Fprintf(&b, "running modules: %s\n", strings.Join(r.Running, ", "))
	b.WriteString("\n")
	if len(r.Hosts) == 0 {
		b.WriteString("hosts: none\n")
	} else {
		fmt.Fprintf(&b, "hosts (%d):\n", len(r.Hosts))
		for _, h := range r.Hosts {
			fmt.Fprintf(&b, "  %s  %s  %s\n", h.IP, h.MAC, h.Vendor)
		}
	}
	b.WriteString("\n")
	if len(r.Creds) == 0 {
		b.WriteString("credentials: none\n")
	} else {
		fmt.Fprintf(&b, "credentials (%d):\n", len(r.Creds))
		for _, c := range r.Creds {
			fmt.Fprintf(&b, "  #%d %s  %s:%s  %s\n", c.ID, c.Service, c.Username, redacted(c.Password), c.VictimIP)
		}
	}
	b.WriteString("\n")
	if len(r.Sessions) == 0 {
		b.WriteString("sessions: none\n")
	} else {
		fmt.Fprintf(&b, "sessions (%d):\n", len(r.Sessions))
		for _, ss := range r.Sessions {
			fmt.Fprintf(&b, "  #%d %s  host=%s cookies=%d\n", ss.ID, ss.VictimIP, ss.Host, len(ss.Cookies))
		}
	}
	b.WriteString("\n")
	if len(r.Runs) == 0 {
		b.WriteString("module runs: none\n")
	} else {
		fmt.Fprintf(&b, "module runs (%d):\n", len(r.Runs))
		for _, run := range r.Runs {
			fmt.Fprintf(&b, "  #%d %s  %s", run.ID, run.Module, run.Status)
			if run.Summary != "" {
				fmt.Fprintf(&b, "  %s", run.Summary)
			}
			if run.Error != "" {
				fmt.Fprintf(&b, "  error: %s", run.Error)
			}
			b.WriteString("\n")
		}
	}
	return b.String()
}

// RenderMarkdown renders the report as Markdown. Passwords are redacted.
func (r *Report) RenderMarkdown() string {
	var b strings.Builder
	b.WriteString("# toha3ee session report\n\n")
	fmt.Fprintf(&b, "- **generated**: %s\n", r.Generated.Format(time.RFC3339))
	fmt.Fprintf(&b, "- **running modules**: %s\n", strings.Join(r.Running, ", "))
	b.WriteString("\n## Hosts\n\n")
	if len(r.Hosts) == 0 {
		b.WriteString("_none_\n")
	} else {
		b.WriteString("| ip | mac | vendor |\n| --- | --- | --- |\n")
		for _, h := range r.Hosts {
			fmt.Fprintf(&b, "| %s | %s | %s |\n", h.IP, h.MAC, h.Vendor)
		}
	}
	b.WriteString("\n## Credentials\n\n")
	if len(r.Creds) == 0 {
		b.WriteString("_none_\n")
	} else {
		b.WriteString("| id | service | username | victim | source |\n| --- | --- | --- | --- | --- |\n")
		for _, c := range r.Creds {
			fmt.Fprintf(&b, "| %d | %s | %s | %s | %s |\n", c.ID, c.Service, c.Username, c.VictimIP, c.Source)
		}
	}
	b.WriteString("\n## Sessions\n\n")
	if len(r.Sessions) == 0 {
		b.WriteString("_none_\n")
	} else {
		b.WriteString("| id | victim | host | cookies |\n| --- | --- | --- | --- |\n")
		for _, ss := range r.Sessions {
			fmt.Fprintf(&b, "| %d | %s | %s | %d |\n", ss.ID, ss.VictimIP, ss.Host, len(ss.Cookies))
		}
	}
	b.WriteString("\n## Module Runs\n\n")
	if len(r.Runs) == 0 {
		b.WriteString("_none_\n")
	} else {
		b.WriteString("| id | module | status | result | evidence |\n| --- | --- | --- | --- | --- |\n")
		for _, run := range r.Runs {
			fmt.Fprintf(&b, "| %d | %s | %s | %s | %s |\n", run.ID, run.Module, run.Status, run.Summary, run.EvidenceRef)
		}
	}
	b.WriteString("\n## Events\n\n")
	if len(r.Events) == 0 {
		b.WriteString("_none_\n")
	} else {
		b.WriteString("| time | topic | message |\n| --- | --- | --- |\n")
		for _, e := range r.Events {
			fmt.Fprintf(&b, "| %s | %s | %s |\n", e.Time.Format(time.RFC3339), e.Topic, e.Msg)
		}
	}
	return b.String()
}

// LoadReport reads a previously written report file into a Report.
func LoadReport(path string) (*Report, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read report: %w", err)
	}
	var rep Report
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, fmt.Errorf("parse report %s: %w", path, err)
	}
	return &rep, nil
}

// redacted masks a secret so human-readable reports never leak plaintext
// credentials to the terminal or to markdown consumers.
func redacted(secret string) string {
	if secret == "" {
		return "<empty>"
	}
	return "<redacted>"
}

// macString renders raw MAC bytes as colon-separated lowercase hex.
func macString(m []byte) string {
	if len(m) == 0 {
		return ""
	}
	out := ""
	for i, b := range m {
		if i > 0 {
			out += ":"
		}
		out += fmt.Sprintf("%02x", b)
	}
	return out
}

// copyPortsMap deep-copies a port map so the report snapshot is independent
// of the live store (which the harvesters keep mutating).
func copyPortsMap(src map[uint16]string) map[uint16]string {
	out := make(map[uint16]string, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

// copyStringMap deep-copies a string map for report snapshots.
func copyStringMap(src map[string]string) map[string]string {
	if len(src) == 0 {
		return nil
	}
	out := make(map[string]string, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

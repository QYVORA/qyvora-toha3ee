package session

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/qyvora/toha3ee/internal/store"
)

// Report is the serialized session report.
type Report struct {
	Generated time.Time       `json:"generated"`       // when the report was written
	Running   []string        `json:"running_modules"` // module ids still live at report time
	Hosts     []reportHost    `json:"hosts"`           // discovered network hosts
	Creds     []reportCred    `json:"credentials"`     // captured credentials
	Sessions  []reportSession `json:"sessions"`        // captured web sessions
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
	for _, e := range db.Events() {
		rep.Events = append(rep.Events, reportEvent{Time: e.Time, Topic: e.Topic, Msg: e.Msg})
	}
	return rep
}

// writeReport serializes rep as indented JSON to path.
func writeReport(path string, rep *Report) error {
	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	// 0o600 keeps captured credentials unreadable by other users on the box.
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	return nil
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

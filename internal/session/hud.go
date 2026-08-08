package session

import (
	"fmt"
	"strconv"
	"strings"
)

// hud renders the persistent one-line status strip shown above the prompt.
// It mirrors the live session state — interface, host/port/credential counts
// and running modules — so the operator can read the battlefield at a glance
// without dumping tables.
func (s *Session) hud() {
	if !s.UI.Enabled() {
		return
	}
	var left strings.Builder
	left.WriteString(s.UI.DimWhite("iface "))
	if s.Iface != nil {
		left.WriteString(s.UI.White(s.Iface.Name))
		if s.Iface.IP != nil {
			left.WriteString(" ")
			left.WriteString(s.UI.DimWhite(s.Iface.IP.String()))
		}
	} else {
		left.WriteString(s.UI.DimWhite("none"))
	}
	left.WriteString(s.UI.DimWhite("  ·  running "))
	running := s.Running()
	if len(running) == 0 {
		left.WriteString(s.UI.DimWhite("none"))
	} else {
		left.WriteString(s.UI.Red(strings.Join(running, ",")))
	}

	var right strings.Builder
	hosts := len(s.Store.Hosts())
	ports := 0
	for _, h := range s.Store.Hosts() {
		ports += len(h.OpenPorts())
	}
	right.WriteString(s.UI.DimWhite("hosts "))
	right.WriteString(s.UI.White(strconv.Itoa(hosts)))
	right.WriteString(s.UI.DimWhite("  ·  ports "))
	right.WriteString(s.UI.White(strconv.Itoa(ports)))
	right.WriteString(s.UI.DimWhite("  ·  creds "))
	right.WriteString(s.UI.White(strconv.Itoa(len(s.Store.Creds()))))
	right.WriteString(s.UI.DimWhite("  ·  events "))
	right.WriteString(s.UI.White(strconv.Itoa(len(s.Store.Events()))))

	s.UI.HUD(left.String(), right.String())
}

// statusSummary formats the HUD content as plain text for non-terminal output.
func (s *Session) hudSummary() string {
	iface := "none"
	if s.Iface != nil {
		iface = fmt.Sprintf("%s %s", s.Iface.Name, s.Iface.IP)
	}
	running := s.Running()
	if len(running) == 0 {
		running = []string{"none"}
	}
	hosts := len(s.Store.Hosts())
	return fmt.Sprintf("iface %s running [%s] hosts %d creds %d",
		iface, strings.Join(running, ","), hosts, len(s.Store.Creds()))
}

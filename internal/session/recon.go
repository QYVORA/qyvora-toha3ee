package session

import (
	"fmt"
	"time"

	"github.com/QYVORA/qyvora-toha3ee/internal/netx/ports"
)

// deepReconChain is the ordered reconnaissance progression that net.recon and
// the wizard run once hosts are discovered: SYN-scan the hosts, then
// banner/fingerprint the open ports. Protocol-specific enumeration is appended
// reactively afterwards (see selectEnumModules).
func deepReconChain() []string {
	return []string{"service.synscan", "service.fingerprint"}
}

// serviceEnumModule maps a discovered open service to the enum module that
// deepens it. This is the propagating half of the recon hand-off: discovery
// finds an open port, and the matching protocol advances into its own
// enumeration module rather than stopping at the banner.
func serviceEnumModule(svc string, port uint16) string {
	switch svc {
	case "microsoft-ds", "netbios-ssn":
		return "smb.enum"
	case "ldap", "ldaps":
		return "ldap.enum"
	case "nfs":
		return "nfs.enum"
	case "smtp", "smtp-submission":
		return "smtp.enum"
	case "http", "http-proxy", "https", "https-alt":
		return "web.dir"
	}
	// GuessService leaves SNMP port 161/162 unknown, so fall back to an explicit
	// port check to keep SNMP enumeration reachable from a scan.
	switch port {
	case 161, 162:
		return "snmp.enum"
	}
	return ""
}

// selectEnumModules returns the enum modules warranted by the services seen on
// the discovered hosts, in a stable, deduplicated order. It is a pure function
// of the store so it is unit-testable without a network.
func (s *Session) selectEnumModules() []string {
	want := map[string]bool{}
	for _, h := range s.Store.Hosts() {
		for _, p := range h.OpenPorts() {
			if m := serviceEnumModule(ports.GuessService(p), p); m != "" {
				want[m] = true
			}
		}
	}
	enumOrder := []string{"smb.enum", "ldap.enum", "nfs.enum", "smtp.enum", "snmp.enum", "web.dir"}
	var out []string
	for _, id := range enumOrder {
		if want[id] {
			out = append(out, id)
		}
	}
	return out
}

// runReconChain makes reconnaissance procedural and propagating: it SYN-scans
// discovered hosts, fingerprints the open ports, then advances straight into
// the protocol enumeration the discovered services call for. Steps that cannot
// run (missing capability or no matching service) degrade to warnings instead
// of aborting, so a partial chain still propagates forward.
func (s *Session) runReconChain() error {
	if s.Iface == nil {
		s.warnf("net.recon: no interface configured")
		return nil
	}

	// Bootstrap discovery when the store is empty so net.recon is self-starting
	// rather than a confusing no-op.
	if len(s.Store.Hosts()) == 0 {
		s.statusf("no hosts known; sweeping subnet briefly (net.scan)...")
		if err := s.StartModule("net.scan", nil); err != nil {
			s.warnf("net.recon: discovery unavailable (%v)", err)
			s.goodf("net.recon done: no hosts to enumerate")
			return nil
		}
		time.Sleep(5 * time.Second)
		_ = s.StopModule("net.scan")
		if len(s.Store.Hosts()) == 0 {
			s.warnf("net.recon: no hosts discovered; check the interface or subnet")
			return nil
		}
	}

	// Sequential deep recon. Each step runs to completion before the next so
	// later stages consume the earlier stage's results (fingerprint needs the
	// open ports that synscan recorded).
	for _, id := range deepReconChain() {
		if s.IsRunning(id) {
			continue
		}
		if err := s.StartModule(id, nil); err != nil {
			s.warnf("net.recon: %s skipped (%v)", id, err)
			continue
		}
		if err := waitModule(s, id, 45*time.Second); err != nil {
			s.warnf("net.recon: %s did not settle (%v)", id, err)
		}
	}

	// Propagate the discovered services into protocol enumeration.
	for _, id := range s.selectEnumModules() {
		if err := s.StartModule(id, nil); err != nil {
			s.warnf("net.recon: %s skipped (%v)", id, err)
			continue
		}
		_ = waitModule(s, id, 60*time.Second)
	}

	s.goodf("net.recon complete. use 'net.profile' for attack vectors, 'creds.show' for loot.")
	return nil
}

// waitModule blocks until a bounded module leaves the running set, stopping it
// if it does not finish within timeout.
func waitModule(s *Session, id string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for s.IsRunning(id) {
		if time.Now().After(deadline) {
			_ = s.StopModule(id)
			return fmt.Errorf("%s did not finish within %s", id, timeout)
		}
		time.Sleep(250 * time.Millisecond)
	}
	return nil
}

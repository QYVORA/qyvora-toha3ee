// Package enum implements network service enumeration modules: SMTP user
// enumeration, SNMP community probing and MIB walks, LDAP unauthenticated
// binds, NFS export listing, SMB null-session checks and IPv6 neighbor
// discovery sweeps. These are read-only probes.
package enum

import (
	"net"
	"strconv"

	"github.com/QYVORA/qyvora-toha3ee/internal/attacks"
	"github.com/QYVORA/qyvora-toha3ee/internal/events"
	"github.com/QYVORA/qyvora-toha3ee/internal/safety"
)

// init self-registers every enumeration module into the global registry.
func init() {
	attacks.Register(&SMTPEnum{})
	attacks.Register(&SNMPEnum{})
	attacks.Register(&LDAPEnum{})
	attacks.Register(&NFSEnum{})
	attacks.Register(&SMBEnum{})
	attacks.Register(&IP6Sweep{})
}

// requireRoot adds the raw-socket capability check to a preflight report.
// Enumeration modules that must craft packets (like the IPv6 ND sweep) need
// root; this centralises the check so every module reports the same way.
func requireRoot(rep *attacks.PreflightReport) error {
	if err := safety.RequireRoot(); err != nil {
		rep.AddBlocked("root", err.Error())
		return err
	}
	rep.AddOK("root", "raw packet injection available")
	return nil
}

// emit logs a finding through the session.
func emit(ctx *attacks.AttackCtx, topic, msg string) {
	ctx.Emit(events.TopicLog, msg, nil)
}

// openHosts returns hosts that have at least one known open port. Enumeration
// modules iterate this so a host with zero discovered services is skipped
// without each module duplicating the filter.
func openHosts(ctx *attacks.AttackCtx) []*HostRef {
	var out []*HostRef
	for _, h := range ctx.Store.Hosts() {
		if len(h.OpenPorts()) > 0 {
			out = append(out, &HostRef{IP: h.IP, Ports: h.OpenPorts()})
		}
	}
	return out
}

// HostRef is a store host plus its discovered ports.
type HostRef struct {
	IP    net.IP
	Ports []uint16
}

// portStr renders a port as an int string.
func portStr(p uint16) string { return strconv.Itoa(int(p)) }

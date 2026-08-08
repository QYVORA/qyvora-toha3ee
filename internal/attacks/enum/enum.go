// Package enum implements network service enumeration modules: SMTP user
// enumeration, SNMP community probing and MIB walks, LDAP unauthenticated
// binds, NFS export listing, SMB null-session checks and IPv6 neighbor
// discovery sweeps. These are read-only probes.
package enum

import (
	"fmt"
	"net"
	"strconv"

	"github.com/qyvora/toha3ee/internal/attacks"
	"github.com/qyvora/toha3ee/internal/events"
	"github.com/qyvora/toha3ee/internal/safety"
)

func init() {
	attacks.Register(&SMTPEnum{})
	attacks.Register(&SNMPEnum{})
	attacks.Register(&LDAPEnum{})
	attacks.Register(&NFSEnum{})
	attacks.Register(&SMBEnum{})
	attacks.Register(&IP6Sweep{})
}

// requireRoot adds the raw-socket capability check to a preflight report.
func requireRoot(rep *attacks.PreflightReport) error {
	if err := safety.RequireRoot(); err != nil {
		rep.AddBlocked("root", err.Error())
		return err
	}
	rep.AddOK("root", "raw packet injection available")
	return nil
}

// hostsReport summarizes the store host population for a preflight report.
func hostsReport(ctx *attacks.AttackCtx, rep *attacks.PreflightReport) {
	if len(ctx.Store.Hosts()) == 0 {
		rep.AddFixable("targets", "no hosts discovered; run net.scan first")
		return
	}
	rep.AddOK("targets", fmt.Sprintf("%d host(s) discovered", len(ctx.Store.Hosts())))
}

// emit logs a finding through the session.
func emit(ctx *attacks.AttackCtx, topic, msg string) {
	ctx.Emit(events.TopicLog, msg, nil)
}

// openHosts returns hosts that have at least one known open port.
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

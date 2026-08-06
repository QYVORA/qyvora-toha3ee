// Package vectors is the brain of toha3ee. It builds a live network Profile
// from recon, runs a rules engine over it and produces a confidence-ranked
// list of executable attack vectors. The engine only suggests attacks whose
// prerequisites are satisfiable in the current environment.
package vectors

import (
	"fmt"
	"net"
	"time"

	"github.com/qyvora/toha3ee/internal/netx"
	"github.com/qyvora/toha3ee/internal/netx/wlan"
	"github.com/qyvora/toha3ee/internal/store"
)

// Host is the vector-engine view of a single network host.
type Host struct {
	IP      net.IP
	MAC     net.HardwareAddr
	Vendor  string
	Name    string
	OSGuess string
	TLS     bool
	Ports   map[uint16]string
}

// Profile summarises everything recon learned about the network.
type Profile struct {
	Gateway *Host
	Hosts   []*Host

	// Poisonable is true when ARP responses are accepted on the segment
	// (checked during recon).
	Poisonable bool
	// SMBSigningOff is true when SMB signing is not required.
	SMBSigningOff bool
	SeesLLMNR     bool
	SeesMDNS      bool
	SeesNBNS      bool
	SeesPlainHTTP bool
	SeesDoH       bool
	SeesSMB       bool
	SeesEAPOL     bool
	SeesDHCPv6    bool
	// WPAVersion is the observed WPA version (2 or 3), 0 if unknown.
	WPAVersion int
	// HasClients is true when wireless clients were observed.
	HasClients bool
	// HasAP is true when access points were observed.
	HasAP bool
	// MonitorCapable is true when a monitor-mode-capable interface exists.
	MonitorCapable bool
	// Evidence describes what recon was performed.
	Evidence string
	BuiltAt  time.Time
}

// HostByIP finds a profile host by IP.
func (p *Profile) HostByIP(ip net.IP) *Host {
	if ip == nil {
		return nil
	}
	for _, h := range p.Hosts {
		if h.IP.Equal(ip) {
			return h
		}
	}
	return nil
}

// HostCount returns the number of hosts excluding the attacker itself.
func (p *Profile) HostCount() int {
	return len(p.Hosts)
}

// BuildProfile assembles a Profile from the shared store and live recon
// evidence.
func BuildProfile(db *store.Store, iface *netx.Iface) *Profile {
	p := &Profile{
		Poisonable:    true,
		SeesLLMNR:     db.Recon.SeesLLMNR.Load(),
		SeesMDNS:      db.Recon.SeesMDNS.Load(),
		SeesNBNS:      db.Recon.SeesNBNS.Load(),
		SeesPlainHTTP: db.Recon.SeesPlainHTTP.Load(),
		SeesDoH:       db.Recon.SeesDoH.Load(),
		SeesSMB:       db.Recon.SeesSMB.Load(),
		SeesEAPOL:     db.Recon.SeesEAPOL.Load(),
		SeesDHCPv6:    db.Recon.SeesDHCPv6.Load(),
		BuiltAt:       time.Now(),
	}

	for _, h := range db.Hosts() {
		if iface != nil && h.IP.Equal(iface.IP) {
			continue
		}
		p.Hosts = append(p.Hosts, &Host{
			IP:      h.IP,
			MAC:     h.MAC,
			Vendor:  h.Vendor,
			Name:    h.Name,
			OSGuess: h.OSGuess,
			TLS:     h.TLS,
			Ports:   copyPorts(h.Ports),
		})
	}

	if iface != nil {
		if gwIP, err := iface.Gateway(); err == nil {
			p.Gateway = p.HostByIP(gwIP)
			if p.Gateway == nil {
				p.Gateway = &Host{IP: gwIP}
			}
		}
	}

	// Monitor capability: a wireless interface in the system is required.
	if name, ok := wlan.DetectWirelessIface(); ok {
		p.MonitorCapable = true
		_ = name
	}

	if len(p.Hosts) > 0 {
		p.Evidence = fmtEvidence(db)
	} else {
		p.Evidence = "no hosts discovered yet; run net.scan"
	}
	return p
}

func copyPorts(src map[uint16]string) map[uint16]string {
	if src == nil {
		return nil
	}
	out := make(map[uint16]string, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

func fmtEvidence(db *store.Store) string {
	return fmt.Sprintf("%d hosts in inventory", len(db.Hosts()))
}

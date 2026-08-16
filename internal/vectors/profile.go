// Package vectors is the brain of toha3ee. It builds a live network Profile
// from recon, runs a rules engine over it and produces a confidence-ranked
// list of executable attack vectors. The engine only suggests attacks whose
// prerequisites are satisfiable in the current environment.
package vectors

import (
	"fmt"
	"net"
	"time"

	"github.com/QYVORA/qyvora-toha3ee/internal/netx"
	"github.com/QYVORA/qyvora-toha3ee/internal/netx/wlan"
	"github.com/QYVORA/qyvora-toha3ee/internal/store"
)

// Host is the vector-engine view of a single network host.
type Host struct {
	// IP is the host's address (nil when unknown, e.g. the gateway).
	IP net.IP
	// MAC is the host's hardware address.
	MAC net.HardwareAddr
	// Vendor is the OUI-derived manufacturer when known.
	Vendor string
	// Name is the hostname when known.
	Name string
	// OSGuess is the fingerprinting guess when known.
	OSGuess string
	// TLS reports whether the host served HTTPS (or TLS traffic was seen).
	TLS bool
	// Ports maps open TCP ports to their grabbed banners.
	Ports map[uint16]string
}

// Profile summarises everything recon learned about the network.
type Profile struct {
	// Gateway is the resolved default gateway, if discoverable.
	Gateway *Host
	// Hosts lists every discovered host except the attacker itself.
	Hosts []*Host

	// Poisonable is true when ARP responses are accepted on the segment
	// (checked during recon).
	Poisonable bool
	// SMBSigningOff is true when SMB signing is not required.
	SMBSigningOff bool
	SeesLLMNR     bool // LLMNR queries observed
	SeesMDNS      bool // mDNS queries observed
	SeesNBNS      bool // NetBIOS name service observed
	SeesPlainHTTP bool // plaintext HTTP observed
	SeesDoH       bool // DNS-over-HTTPS observed
	SeesSMB       bool // SMB traffic observed
	SeesEAPOL     bool // 802.1X EAPOL observed
	SeesDHCPv6    bool // DHCPv6 solicit observed
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
	// BuiltAt is when this profile snapshot was assembled.
	BuiltAt time.Time
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
	// BuildProfile already excludes the attacker's own IP from Hosts, so
	// this is a plain length — kept as a method so the exclusion contract
	// lives in one documented place.
	return len(p.Hosts)
}

// BuildProfile assembles a Profile from the shared store and live recon
// evidence.
func BuildProfile(db *store.Store, iface *netx.Iface) *Profile {
	p := &Profile{
		// Assume ARP poisoning works unless recon proved otherwise; the
		// poisonability probe is what flips this to false.
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

	// Convert every store host into its engine view, skipping the attacker's
	// own interface address so the profile never suggests attacking self.
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
			// Snapshot the ports so later store writes cannot mutate the
			// profile under the rules engine.
			Ports: copyPorts(h.PortsSnapshot()),
		})
	}

	// Resolve the gateway from the interface's default route and attach it
	// (as a placeholder if it was never seen in the host inventory).
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
		// No inventory yet: point the user at the next recon step.
		p.Evidence = "no hosts discovered yet; run net.scan"
	}
	return p
}

// copyPorts deep-copies a ports map so profile snapshots are independent of
// the store's live host data.
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

// fmtEvidence renders the recon-evidence summary for the profile.
func fmtEvidence(db *store.Store) string {
	return fmt.Sprintf("%d hosts in inventory", len(db.Hosts()))
}

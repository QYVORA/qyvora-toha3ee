package recon

import (
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/qyvora/toha3ee/internal/attacks"
	"github.com/qyvora/toha3ee/internal/events"
	"github.com/qyvora/toha3ee/internal/netx/ports"
	"github.com/qyvora/toha3ee/internal/stealth"
)

// NetOSDetect guesses the operating system of discovered hosts by reading the
// TCP-stack behavior of their SYN-ACK reply (initial TTL, window size, MSS and
// options) against a small signature database.
type NetOSDetect struct{}

// Meta implements attacks.Module.
func (*NetOSDetect) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{
		ID:          "net.osdetect",
		Category:    "recon",
		Risk:        attacks.RiskInfo,
		Targets:     []string{"host"},
		Requires:    []string{"cap.raw_socket"},
		Description: "passive-by-design OS fingerprinting of discovered hosts from TCP SYN-ACK stack quirks",
		Limitations: "a single-sample guess; custom kernels and middleboxes can skew the verdict. Verify with banner evidence",
	}
}

// Preflight needs hosts.
func (*NetOSDetect) Preflight(ctx *attacks.AttackCtx) (*attacks.PreflightReport, error) {
	rep := &attacks.PreflightReport{}
	if len(ctx.Store.Hosts()) == 0 {
		rep.AddFixable("targets", "no hosts discovered; run net.scan first")
	} else {
		rep.AddOK("targets", fmt.Sprintf("%d host(s) discovered", len(ctx.Store.Hosts())))
	}
	return rep, nil
}

// osSignature is one fingerprint rule; Score returns 0 for no match.
type osSignature struct {
	OS      string
	Family  string
	TTL     uint8
	Window  uint16
	MSS     uint16
	WS      uint8
	SACKOK  bool
	DF      bool
	Variant []osVariant
}

type osVariant struct {
	TTL    uint8
	Window uint16
}

// osSignatures is a small, honest signature set covering the dominant stacks.
var osSignatures = []osSignature{
	{OS: "Linux (2.6+/3.x/4.x/5.x)", Family: "linux", TTL: 64, MSS: 1460, WS: 7, SACKOK: true, DF: true,
		Variant: []osVariant{{TTL: 64, Window: 64240}, {TTL: 64, Window: 65160}, {TTL: 64, Window: 29200}}},
	{OS: "Linux (recent, default window)", Family: "linux", TTL: 64, MSS: 1460, WS: 7, SACKOK: true, DF: true,
		Variant: []osVariant{{TTL: 64, Window: 65535}}},
	{OS: "Windows 10/11", Family: "windows", TTL: 128, MSS: 1460, WS: 8, SACKOK: true, DF: true,
		Variant: []osVariant{{TTL: 128, Window: 65535}, {TTL: 128, Window: 64240}}},
	{OS: "Windows 7/Server 2008", Family: "windows", TTL: 128, MSS: 1460, WS: 2, SACKOK: true, DF: true,
		Variant: []osVariant{{TTL: 128, Window: 8192}}},
	{OS: "Windows Server 2012/2016/2019", Family: "windows", TTL: 128, MSS: 1460, WS: 8, SACKOK: true, DF: true,
		Variant: []osVariant{{TTL: 128, Window: 65535}, {TTL: 128, Window: 65520}}},
	{OS: "macOS / Darwin", Family: "bsd", TTL: 64, MSS: 1460, WS: 3, SACKOK: true, DF: true,
		Variant: []osVariant{{TTL: 64, Window: 65535}, {TTL: 64, Window: 64240}}},
	{OS: "FreeBSD", Family: "bsd", TTL: 64, MSS: 1460, WS: 3, SACKOK: true, DF: true,
		Variant: []osVariant{{TTL: 64, Window: 65535}}},
	{OS: "Solaris / illumos", Family: "unix", TTL: 255, MSS: 1460, WS: 2, SACKOK: true, DF: true,
		Variant: []osVariant{{TTL: 255, Window: 49152}, {TTL: 254, Window: 49152}}},
	{OS: "AIX", Family: "unix", TTL: 64, MSS: 1460, WS: 0, SACKOK: false, DF: false,
		Variant: []osVariant{{TTL: 64, Window: 16384}}},
	{OS: "Cisco IOS (router/switch)", Family: "network", TTL: 255, MSS: 1460, WS: 0, SACKOK: false, DF: false,
		Variant: []osVariant{{TTL: 255, Window: 4128}, {TTL: 255, Window: 8192}}},
}

// osVerdict is one host's fingerprint guess.
type osVerdict struct {
	Host  string
	Guess string
	Score int
	Hops  int
}

// Run fingerprints each discovered host.
func (*NetOSDetect) Run(ctx *attacks.AttackCtx, opts map[string]string) error {
	scanner, err := ports.NewScanner(ctx.Iface)
	if err != nil {
		return fmt.Errorf("net.osdetect: %w", err)
	}
	defer scanner.Close()
	scanner.SetStealth(stealth.FromConfig(ctx.Conf, "net.osdetect"))

	timeout := ctx.Conf.GetDuration("net.osdetect", "timeout", 1500*time.Millisecond)
	port := ctx.Conf.GetInt("net.osdetect", "port", 0)

	var verdicts []osVerdict
	for _, h := range ctx.Store.Hosts() {
		select {
		case <-ctx.Done:
			return nil
		default:
		}
		p := uint16(port)
		if p == 0 {
			p = pickFingerprintPort(h)
		}
		if p == 0 {
			continue
		}
		fp, err := scanner.Fingerprint(h.IP, p, timeout)
		if err != nil {
			continue
		}
		guess, score := matchOSFingerprint(fp)
		hops := hopEstimate(fp.TTL)
		verdicts = append(verdicts, osVerdict{Host: h.IP.String(), Guess: guess, Score: score, Hops: hops})
		h.OSGuess = guess
		ctx.Emit(events.TopicLog, fmt.Sprintf("net.osdetect: %s -> %s (score %d, ~%d hop(s))", h.IP, guess, score, hops), nil)
	}
	ctx.SetState("net.osdetect", verdicts)
	ctx.Printf("[*] net.osdetect complete: %d host(s) fingerprinted.\n", len(verdicts))
	return nil
}

// pickFingerprintPort chooses an open port to fingerprint, preferring a
// service that must answer with a real SYN-ACK.
func pickFingerprintPort(h interface {
	OpenPorts() []uint16
}) uint16 {
	for _, p := range h.OpenPorts() {
		switch p {
		case 80, 443, 22, 445, 3389, 8080, 8443:
			return p
		}
	}
	if ps := h.OpenPorts(); len(ps) > 0 {
		return ps[0]
	}
	return 0
}

// matchOS scores each signature against the observed fingerprint.
func matchOSFingerprint(fp *ports.TCPFingerprint) (string, int) {
	best, bestScore := "unknown (no signature match)", 0
	for _, s := range osSignatures {
		score := 0
		ttlMatch := false
		for _, v := range s.Variant {
			if v.TTL == fp.TTL {
				ttlMatch = true
				if v.Window == fp.Window {
					score += 3
				} else {
					score += 1
				}
				break
			}
		}
		if s.TTL == fp.TTL {
			ttlMatch = true
		}
		if !ttlMatch {
			continue
		}
		if s.MSS == fp.MSS {
			score += 2
		}
		if s.WS == fp.WS {
			score += 2
		}
		if s.SACKOK == fp.SACKOK {
			score++
		}
		if s.DF == fp.DF {
			score++
		}
		if score > bestScore {
			best, bestScore = s.OS, score
		}
	}
	return best, bestScore
}

// hopEstimate converts an observed TTL into a hop-distance estimate.
func hopEstimate(observed uint8) int {
	base := []uint8{64, 128, 255}
	best := 0
	for _, b := range base {
		if observed <= b {
			d := int(b) - int(observed)
			if d < 0 {
				continue
			}
			if best == 0 || d < best {
				best = d
			}
		}
	}
	return best
}

// Verify reports the guesses.
func (*NetOSDetect) Verify(ctx *attacks.AttackCtx) (*attacks.Impact, error) {
	v, ok := ctx.GetState("net.osdetect")
	if !ok {
		return nil, fmt.Errorf("net.osdetect not run")
	}
	got, _ := v.([]osVerdict)
	sort.Slice(got, func(i, j int) bool { return got[i].Host < got[j].Host })
	imp := &attacks.Impact{Summary: fmt.Sprintf("fingerprinted %d host(s)", len(got))}
	imp.Add("hosts", strconv.Itoa(len(got)))
	for _, r := range got {
		imp.Add("os", fmt.Sprintf("%s ~ %s", r.Host, r.Guess))
	}
	return imp, nil
}

// Cleanup is a no-op.
func (*NetOSDetect) Cleanup(ctx *attacks.AttackCtx) error { return nil }

var _ attacks.Module = (*NetOSDetect)(nil)

// Package stealth implements the always-on low-noise packet engineering used
// across the recon and exploitation pipeline. Every knob defaults to a
// stealth-optimized value so modules ship quiet by default: randomized
// ordering, per-probe jitter, burst pacing and randomized IP/TCP fields make
// activity hard to fingerprint while burst concurrency keeps scans fast.
package stealth

import (
	cryptorand "crypto/rand"
	"encoding/binary"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/qyvora/toha3ee/internal/config"
)

// Default is the stealth profile used by code paths that are not configured
// through a module (e.g. banner grabbing helpers).
var Default = New()

// Config carries the timing and randomization knobs shared by every
// packet-sending module. Zero value disables all stealth behavior.
type Config struct {
	// Enabled is the master switch; false disables all stealth behavior.
	Enabled bool

	// Jitter is the maximum random delay inserted before each probe.
	Jitter time.Duration
	// Burst is the number of probes sent before a pause. 0 disables pacing.
	Burst int
	// Pause is the pause applied after each burst.
	Pause time.Duration

	RandomizePort bool // vary the source port per probe
	RandomizeTTL  bool // vary the IP TTL per probe
	RandomizeID   bool // vary the IP identification field per probe
	RandomizePad  bool // pad frames with random bytes instead of zeros
	ShuffleOrder  bool // randomize probe order within a scan

	// rng is the per-Config random source. It is not safe for concurrent
	// use; callers guard it or pass a shared Pacer.
	rng *rand.Rand
}

// New returns a Config with stealth-optimized defaults.
func New() *Config {
	return &Config{
		Enabled:       true,
		Jitter:        3 * time.Millisecond,
		Burst:         64,
		Pause:         20 * time.Millisecond,
		RandomizePort: true,
		RandomizeTTL:  true,
		RandomizeID:   true,
		RandomizePad:  true,
		ShuffleOrder:  true,
		rng:           newRNG(),
	}
}

// FromConfig builds a Config from the per-module configuration namespace,
// applying the user's tunables on top of the stealth defaults.
func FromConfig(c *config.Config, module string) *Config {
	cfg := New()
	if c == nil {
		// No config backend at all: keep the stealth defaults verbatim.
		return cfg
	}
	if !c.GetBool(module, "stealth", true) {
		// The master knob is off: return a disabled config so the caller can
		// still use it as a "no stealth" marker without special-casing nil.
		cfg.Enabled = false
		return cfg
	}
	// Overlay each tunable; GetDuration/GetInt fall back to the current
	// default when the user has not set that knob.
	cfg.Jitter = c.GetDuration(module, "stealth_jitter", cfg.Jitter)
	cfg.Burst = c.GetInt(module, "stealth_burst", cfg.Burst)
	cfg.Pause = c.GetDuration(module, "stealth_pause", cfg.Pause)
	cfg.RandomizePort = c.GetBool(module, "stealth_ports", cfg.RandomizePort)
	cfg.RandomizeTTL = c.GetBool(module, "stealth_ttl", cfg.RandomizeTTL)
	cfg.RandomizeID = c.GetBool(module, "stealth_id", cfg.RandomizeID)
	cfg.RandomizePad = c.GetBool(module, "stealth_pad", cfg.RandomizePad)
	cfg.ShuffleOrder = c.GetBool(module, "stealth_shuffle", cfg.ShuffleOrder)
	return cfg
}

// Feature reports whether a specific stealth behavior is active.
func (c *Config) Feature(b bool) bool {
	if c == nil {
		// A nil Config (callers passing a zeroed *Config) behaves as
		// stealth-disabled rather than panicking.
		return false
	}
	return c.Enabled && b
}

// On reports whether the master switch is on.
func (c *Config) On() bool {
	if c == nil {
		return false
	}
	return c.Enabled
}

// Shuffle randomizes the first n elements of a collection using the provided
// swap function (the standard sort.Interface contract).
func (c *Config) Shuffle(n int, swap func(i, j int)) {
	// Nothing to randomize for fewer than two items; also honors the master
	// switch and the per-feature ShuffleOrder knob.
	if !c.Feature(c.ShuffleOrder) || n < 2 {
		return
	}
	c.rng.Shuffle(n, swap)
}

// JitterSleep blocks for a random delay within [0, Jitter).
func (c *Config) JitterSleep() {
	if !c.Feature(c.Jitter > 0) {
		return
	}
	// Int64N returns [0, Jitter), keeping the delay strictly below the cap
	// so bursts never line up at the exact same interval.
	time.Sleep(time.Duration(c.rng.Int64N(int64(c.Jitter))))
}

// RandomSrcPort returns an ephemeral source port from the Linux dynamic range.
func (c *Config) RandomSrcPort() uint16 {
	// Linux defaults to ephemeral ports 32768-60999; the offset keeps
	// generated ports inside that range so middleboxes do not flag them.
	return uint16(32768 + c.rng.IntN(28232))
}

// RandomIPID returns a random IP identification value.
func (c *Config) RandomIPID() uint16 {
	// Take the high 16 bits of a 32-bit value so consecutive draws do not
	// correlate in their low bits.
	return uint16(c.rng.Uint32() >> 16)
}

// RandomSeq returns a random TCP sequence number.
func (c *Config) RandomSeq() uint32 {
	return c.rng.Uint32()
}

// TTL jitters base by at most delta hops, clamped to valid IPv4 TTL values.
func (c *Config) TTL(base, delta uint8) uint8 {
	if delta == 0 {
		// Default jitter of 8 hops: enough to defeat TTL fingerprinting of
		// the scanner without overshooting real-world hop counts.
		delta = 8
	}
	// Draw an offset in [-delta, +delta] so the TTL both rises and falls.
	off := int8(c.rng.IntN(int(delta)*2+1)) - int8(delta)
	v := int32(base) + int32(off)
	if v < 1 {
		// TTL 0 is invalid/discarded by routers; clamp at 1.
		v = 1
	}
	if v > 255 {
		v = 255
	}
	return uint8(v)
}

// Window picks a TCP window size from common real-stack values so that
// SYN probes do not all advertise an identical, tool-specific window.
func (c *Config) Window() uint16 {
	// These are values actually observed from Windows/macOS/Linux/BSD TCP
	// stacks; picking one at random blends the scanner into background noise.
	vals := []uint16{64240, 65535, 65536 >> 1, 16384, 8192, 5840, 29200, 57344}
	return vals[c.rng.IntN(len(vals))]
}

// DF drops the IPv4 dont-fragment flag with the given probability (0..1).
func (c *Config) DF(prob float64) bool {
	// The DF bit stays set unless the random draw exceeds prob, so prob is
	// the chance of *clearing* the bit (i.e. dropping the flag).
	return c.rng.Float64() > prob
}

// Pad returns n randomized bytes for Ethernet frame padding. Random padding
// avoids the tell-tale zero-padded frames emitted by many scanner stacks. If
// secure randomness is unavailable it falls back to a cheap mix.
func (c *Config) Pad(n int) []byte {
	out := make([]byte, n)
	if _, err := cryptorand.Read(out); err != nil {
		// Fallback: a linear congruential generator seeded from the clock.
		// Not cryptographically secure, but adequate for padding bytes where
		// unpredictability against a passive observer is the only goal.
		t := time.Now().UnixNano()
		for i := range out {
			// MMIX-style LCG constants: multiplier and increment with good
			// statistical spread across the full 64-bit state.
			t = t*6364136223846793005 + 1442695040888963407
			out[i] = byte(t >> 56)
		}
	}
	return out
}

// UserAgent returns a realistic browser user agent so that HTTP probing does
// not advertise the framework.
func (c *Config) UserAgent() string {
	if !c.On() {
		// Stealth disabled: identify the tool explicitly instead of hiding.
		return "Mozilla/5.0 toha3ee/1.0"
	}
	// A spread of current Chrome/Safari/Firefox strings; each request picks
	// one at random so repeated probes do not share a tell-tale agent.
	uas := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
	}
	return uas[c.rng.IntN(len(uas))]
}

// Pacer paces packet emission with burst/jitter cadence. It is safe for
// concurrent use so a whole scan can share one cadence.
type Pacer struct {
	// mu serializes Wait/Reset so the shared cadence stays consistent.
	mu sync.Mutex
	// cfg is the Config whose burst/jitter settings drive the pacing.
	cfg *Config
	// sent counts probes sent since the last burst reset.
	sent int
}

// NewPacer returns a Pacer bound to cfg.
func NewPacer(cfg *Config) *Pacer {
	return &Pacer{cfg: cfg}
}

// Wait blocks for the next allowed send slot.
func (p *Pacer) Wait() {
	// Nil-safe: an unset Pacer or a stealth-disabled Config means "send
	// immediately", i.e. no pacing at all.
	if p == nil || p.cfg == nil || !p.cfg.Enabled {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sent++
	if p.cfg.Burst > 0 && p.sent >= p.cfg.Burst {
		// Burst completed: reset the counter and sleep for the pause plus a
		// jitter so bursts do not recur on a fixed, fingerprintable cadence.
		p.sent = 0
		pause := p.cfg.Pause
		if j := p.cfg.Jitter; j > 0 {
			pause += time.Duration(p.cfg.rng.Int64N(int64(j)))
		}
		if pause > 0 {
			time.Sleep(pause)
		}
		return
	}
	// Inside a burst: sleep a per-probe jitter so probes are not emitted at
	// machine-exact intervals.
	if j := p.cfg.Jitter; j > 0 {
		time.Sleep(time.Duration(p.cfg.rng.Int64N(int64(j))))
	}
}

// Reset clears the burst counter.
func (p *Pacer) Reset() {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.sent = 0
	p.mu.Unlock()
}

// newRNG builds a math/rand/v2 source seeded from the OS entropy pool.
func newRNG() *rand.Rand {
	// Two independent PCG seeds make the source effectively
	// non-reproducible across runs, so probes cannot be predicted.
	return rand.New(rand.NewPCG(seed(), seed()))
}

// seed returns 64 bits of OS randomness, falling back to the clock when the
// entropy pool is unavailable (e.g. some containers).
func seed() uint64 {
	var b [8]byte
	if _, err := cryptorand.Read(b[:]); err == nil {
		return binary.LittleEndian.Uint64(b[:])
	}
	return uint64(time.Now().UnixNano())
}

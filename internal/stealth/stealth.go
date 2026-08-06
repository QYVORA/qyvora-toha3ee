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
	Enabled bool

	// Jitter is the maximum random delay inserted before each probe.
	Jitter time.Duration
	// Burst is the number of probes sent before a pause. 0 disables pacing.
	Burst int
	// Pause is the pause applied after each burst.
	Pause time.Duration

	RandomizePort bool
	RandomizeTTL  bool
	RandomizeID   bool
	RandomizePad  bool
	ShuffleOrder  bool

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
		return cfg
	}
	if !c.GetBool(module, "stealth", true) {
		cfg.Enabled = false
		return cfg
	}
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
	time.Sleep(time.Duration(c.rng.Int64N(int64(c.Jitter))))
}

// RandomSrcPort returns an ephemeral source port from the Linux dynamic range.
func (c *Config) RandomSrcPort() uint16 {
	return uint16(32768 + c.rng.IntN(28232))
}

// RandomIPID returns a random IP identification value.
func (c *Config) RandomIPID() uint16 {
	return uint16(c.rng.Uint32() >> 16)
}

// RandomSeq returns a random TCP sequence number.
func (c *Config) RandomSeq() uint32 {
	return c.rng.Uint32()
}

// TTL jitters base by at most delta hops, clamped to valid IPv4 TTL values.
func (c *Config) TTL(base, delta uint8) uint8 {
	if delta == 0 {
		delta = 8
	}
	off := int8(c.rng.IntN(int(delta)*2+1)) - int8(delta)
	v := int32(base) + int32(off)
	if v < 1 {
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
	vals := []uint16{64240, 65535, 65536 >> 1, 16384, 8192, 5840, 29200, 57344}
	return vals[c.rng.IntN(len(vals))]
}

// DF drops the IPv4 dont-fragment flag with the given probability (0..1).
func (c *Config) DF(prob float64) bool {
	return c.rng.Float64() > prob
}

// Pad returns n randomized bytes for Ethernet frame padding. Random padding
// avoids the tell-tale zero-padded frames emitted by many scanner stacks. If
// secure randomness is unavailable it falls back to a cheap mix.
func (c *Config) Pad(n int) []byte {
	out := make([]byte, n)
	if _, err := cryptorand.Read(out); err != nil {
		t := time.Now().UnixNano()
		for i := range out {
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
		return "Mozilla/5.0 toha3ee/1.0"
	}
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
	mu   sync.Mutex
	cfg  *Config
	sent int
}

// NewPacer returns a Pacer bound to cfg.
func NewPacer(cfg *Config) *Pacer {
	return &Pacer{cfg: cfg}
}

// Wait blocks for the next allowed send slot.
func (p *Pacer) Wait() {
	if p == nil || p.cfg == nil || !p.cfg.Enabled {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sent++
	if p.cfg.Burst > 0 && p.sent >= p.cfg.Burst {
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
	return rand.New(rand.NewPCG(seed(), seed()))
}

func seed() uint64 {
	var b [8]byte
	if _, err := cryptorand.Read(b[:]); err == nil {
		return binary.LittleEndian.Uint64(b[:])
	}
	return uint64(time.Now().UnixNano())
}

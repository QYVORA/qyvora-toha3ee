package stealth

import (
	"strings"
	"testing"
	"time"
)

func TestDefaultsAreStealthy(t *testing.T) {
	c := New()
	if !c.Enabled {
		t.Fatal("stealth must be on by default")
	}
	if !c.RandomizePort || !c.RandomizeTTL || !c.RandomizeID || !c.RandomizePad || !c.ShuffleOrder {
		t.Fatal("randomization knobs must default on")
	}
	if c.Jitter <= 0 || c.Burst <= 0 || c.Pause <= 0 {
		t.Fatal("pacing knobs must default to non-zero values")
	}
}

func TestFromConfigDisabled(t *testing.T) {
	// A nil config still returns the stealth defaults.
	if c := FromConfig(nil, "net.scan"); !c.Enabled {
		t.Fatal("nil config should keep stealth enabled")
	}
}

func TestFeatureHonorsMasterSwitch(t *testing.T) {
	c := New()
	c.Enabled = false
	if c.Feature(c.RandomizePort) {
		t.Fatal("feature must be off when master switch is off")
	}
	c.Enabled = true
	if !c.Feature(c.RandomizePort) {
		t.Fatal("feature must be on when master switch is on")
	}
	if New().Feature(false) {
		t.Fatal("explicitly disabled feature reported on")
	}
	var nilC *Config
	if nilC.Feature(true) {
		t.Fatal("nil config reported feature on")
	}
}

func TestRandomSrcPortInEphemeralRange(t *testing.T) {
	c := New()
	for i := 0; i < 1000; i++ {
		p := c.RandomSrcPort()
		if p < 32768 || p > 60999 {
			t.Fatalf("source port %d outside ephemeral range", p)
		}
	}
}

func TestTTLBounds(t *testing.T) {
	c := New()
	for i := 0; i < 10000; i++ {
		ttl := c.TTL(64, 8)
		if ttl < 1 {
			t.Fatalf("ttl %d out of range", ttl)
		}
	}
}

func TestDFProbability(t *testing.T) {
	c := New()
	dropped, total := 0, 400
	for i := 0; i < total; i++ {
		if !c.DF(0.5) {
			dropped++
		}
	}
	if dropped == 0 || dropped == total {
		t.Fatalf("DF should vary: %d/%d dropped", dropped, total)
	}
}

func TestPadLength(t *testing.T) {
	if got := New().Pad(18); len(got) != 18 {
		t.Fatalf("pad length = %d, want 18", len(got))
	}
}

func TestShufflePreservesElements(t *testing.T) {
	c := New()
	in := []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	out := append([]int(nil), in...)
	c.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	seen := make([]bool, len(in))
	for _, v := range out {
		if v < 0 || v >= len(in) {
			t.Fatalf("shuffle produced value %d outside input", v)
		}
		seen[v] = true
	}
	for i, s := range seen {
		if !s {
			t.Fatalf("shuffle lost element %d", i)
		}
	}
}

func TestShuffleDisabledDoesNothing(t *testing.T) {
	c := New()
	c.Enabled = false
	out := []string{"a", "b", "c"}
	c.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	if out[0] != "a" || out[1] != "b" || out[2] != "c" {
		t.Fatalf("disabled shuffle mutated slice: %v", out)
	}
}

func TestUserAgentIsRealistic(t *testing.T) {
	c := New()
	for i := 0; i < 50; i++ {
		ua := c.UserAgent()
		if strings.Contains(ua, "toha3ee") {
			t.Fatalf("user agent advertises the tool: %s", ua)
		}
		if !strings.Contains(ua, "Mozilla/5.0") {
			t.Fatalf("unexpected user agent: %s", ua)
		}
	}
}

func TestPacerDispatches(t *testing.T) {
	c := New()
	c.Enabled = true
	c.Jitter = time.Millisecond
	c.Burst = 2
	c.Pause = time.Millisecond
	p := NewPacer(c)
	start := time.Now()
	p.Wait()
	p.Wait()
	p.Wait()
	if elapsed := time.Since(start); elapsed < time.Millisecond {
		t.Fatalf("pacer did not pace: %s", elapsed)
	}
	p.Reset()
	if p.sent != 0 {
		t.Fatalf("reset left counter at %d", p.sent)
	}
}

func TestPacerDisabledIsFree(t *testing.T) {
	c := New()
	c.Enabled = false
	p := NewPacer(c)
	start := time.Now()
	for i := 0; i < 1000; i++ {
		p.Wait()
	}
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Fatalf("disabled pacer blocked: %s", elapsed)
	}
}

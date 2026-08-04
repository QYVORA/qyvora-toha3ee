package safety

import (
	"errors"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestCleanupRunsInReverseOrder(t *testing.T) {
	m := NewManager(nil, testLogger())
	var mu sync.Mutex
	var order []string

	m.RegisterCleanup("a", "a", func() error { mu.Lock(); defer mu.Unlock(); order = append(order, "a"); return nil })
	m.RegisterCleanup("b", "b", func() error { mu.Lock(); defer mu.Unlock(); order = append(order, "b"); return nil })
	m.RegisterCleanup("c", "c", func() error { mu.Lock(); defer mu.Unlock(); order = append(order, "c"); return nil })

	if err := m.RunAll(); err != nil {
		t.Fatalf("RunAll: %v", err)
	}
	want := []string{"c", "b", "a"}
	if len(order) != len(want) {
		t.Fatalf("order = %v", order)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("order = %v, want %v", order, want)
		}
	}
}

func TestFailedCleanupDoesNotBlockOthers(t *testing.T) {
	m := NewManager(nil, testLogger())
	m.RegisterCleanup("bad", "bad", func() error { return errors.New("boom") })
	m.RegisterCleanup("good", "good", func() error { return nil })
	err := m.RunAll()
	if err == nil {
		t.Fatal("expected error from bad cleanup")
	}
}

func TestRegisterDeduplicatesByID(t *testing.T) {
	m := NewManager(nil, testLogger())
	m.RegisterCleanup("x", "first", func() error { return nil })
	m.RegisterCleanup("x", "second", func() error { return nil })
	if got := len(m.Actions()); got != 1 {
		t.Fatalf("expected 1 action, got %d", got)
	}
}

func TestUnregister(t *testing.T) {
	m := NewManager(nil, testLogger())
	m.RegisterCleanup("x", "x", func() error { return nil })
	m.UnregisterCleanup("x")
	if got := len(m.Actions()); got != 0 {
		t.Fatalf("expected 0 actions, got %d", got)
	}
}

func TestHeartbeatStale(t *testing.T) {
	h := NewHeartbeat()
	if h.Stale(time.Now(), time.Second) {
		t.Fatal("fresh heartbeat should not be stale")
	}
	time.Sleep(5 * time.Millisecond)
	if !h.Stale(time.Now().Add(2*time.Second), time.Second) {
		t.Fatal("heartbeat should be stale when time has passed")
	}
	h.Beat()
	if h.Stale(time.Now(), time.Second) {
		t.Fatal("beat should refresh liveness")
	}
}

func TestWatchdogFires(t *testing.T) {
	m := NewManager(nil, testLogger())
	hb := NewHeartbeat()
	m.RegisterHeartbeat("dead", hb)
	fired := make(chan string, 1)
	m.StartWatchdog(10*time.Millisecond, 50*time.Millisecond, func(owner string) {
		fired <- owner
	})
	select {
	case owner := <-fired:
		if owner != "dead" {
			t.Fatalf("fired owner = %q", owner)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("watchdog never fired")
	}
	m.StopWatchdog()
}

func TestWatchdogNotFiredWhenBeating(t *testing.T) {
	m := NewManager(nil, testLogger())
	hb := NewHeartbeat()
	m.RegisterHeartbeat("alive", hb)
	fired := make(chan struct{}, 1)
	m.StartWatchdog(10*time.Millisecond, 100*time.Millisecond, func(string) {
		fired <- struct{}{}
	})
	stop := make(chan struct{})
	go func() {
		t := time.NewTicker(20 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				hb.Beat()
			}
		}
	}()
	time.Sleep(250 * time.Millisecond)
	close(stop)
	m.StopWatchdog()
	select {
	case <-fired:
		t.Fatal("watchdog should not fire for beating heartbeat")
	default:
	}
}

func TestRiskStringsAndElevation(t *testing.T) {
	for lvl, name := range map[RiskLevel]string{
		RiskInfo: "info", RiskLow: "low", RiskMedium: "medium", RiskHigh: "high", RiskCritical: "critical",
	} {
		if lvl.String() != name {
			t.Errorf("Risk(%d).String() = %q, want %q", lvl, lvl.String(), name)
		}
	}
	if !IsElevated("high") || !IsElevated("CRITICAL") {
		t.Fatal("high/critical should be elevated")
	}
	if IsElevated("low") {
		t.Fatal("low should not be elevated")
	}
	if FromString("High") != RiskHigh {
		t.Fatal("FromString case-insensitive parse failed")
	}
}

func TestPreflightReport(t *testing.T) {
	r := &PreflightReport{}
	r.AddOK("root", "running as root")
	r.AddFixed("ip_forward", "sysctl set to 1")
	r.AddBlocked("monitor_iface", "no monitor interface")
	if r.OK() {
		t.Fatal("report should not be OK with blocked check")
	}
	if r.Blocked() != "monitor_iface" {
		t.Fatalf("blocked = %q", r.Blocked())
	}
	if len(r.Fixed()) != 1 {
		t.Fatal("expected 1 fixed check")
	}
}

func TestRequireRoot(t *testing.T) {
	// On CI/root-less environments the function must not panic and must
	// return an error unless running as root.
	err := RequireRoot()
	if os.Geteuid() == 0 && err != nil {
		t.Fatalf("running as root but got error: %v", err)
	}
	if os.Geteuid() != 0 && err == nil {
		t.Fatal("expected error when not root")
	}
}

func TestSysctlRoundTrip(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to write /proc/sys")
	}
	restore, err := EnableIPForward()
	if err != nil {
		t.Fatalf("EnableIPForward: %v", err)
	}
	if got, _ := os.ReadFile("/proc/sys/net/ipv4/ip_forward"); string(got) != "1\n" {
		t.Fatalf("ip_forward not set: %q", got)
	}
	if err := restore(); err != nil {
		t.Fatalf("restore: %v", err)
	}
}

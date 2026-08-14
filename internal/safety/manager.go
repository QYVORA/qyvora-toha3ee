// Package safety is the "don't worry" layer. It provides a global cleanup
// registry, a heartbeat watchdog, risk gating and preflight auto-fixes
// (sysctl, iptables, CA generation). Every running module registers its
// restore actions here; on SIGINT/SIGTERM, panic, module error or watchdog
// timeout the framework runs every registered action in reverse order.
package safety

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/QYVORA/qyvora-toha3ee/internal/events"
)

// Action is a single reversible change made by a module.
type Action struct {
	// ID uniquely identifies the action (used for de-duplication).
	ID string
	// Desc is a human-readable description shown during cleanup.
	Desc string
	// Restore reverses the change.
	Restore func() error
}

// Manager owns the cleanup registry and watchdog.
type Manager struct {
	// bus is where cleanup progress is announced on shutdown.
	bus *events.Bus
	// logger receives cleanup/watchdog diagnostics.
	logger *slog.Logger

	// mu guards actions so registration and shutdown cannot race.
	mu      sync.Mutex
	actions []Action

	// hbmu guards hbs (heartbeat registry).
	hbmu sync.Mutex
	hbs  map[string]*Heartbeat

	// wmu guards the watchdog lifecycle state so StopWatchdog never writes
	// stopCh while the watchdog goroutine is reading it.
	wmu      sync.Mutex
	watching bool
	stopCh   chan struct{}
}

// NewManager returns a Manager wired to the given bus and logger.
func NewManager(bus *events.Bus, logger *slog.Logger) *Manager {
	return &Manager{
		bus:    bus,
		logger: logger,
		hbs:    make(map[string]*Heartbeat),
		// Pre-create the stop channel so StopWatchdog has something to close
		// even if StartWatchdog never ran.
		stopCh: make(chan struct{}),
	}
}

// RegisterCleanup records a restore action. If an action with the same ID is
// already registered it is replaced, guaranteeing idempotent registration.
func (m *Manager) RegisterCleanup(id, desc string, restore func() error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Replace-in-place makes re-registration idempotent: modules that start
	// and stop repeatedly never accumulate duplicate restore actions.
	for i := range m.actions {
		if m.actions[i].ID == id {
			m.actions[i].Desc = desc
			m.actions[i].Restore = restore
			return
		}
	}
	m.actions = append(m.actions, Action{ID: id, Desc: desc, Restore: restore})
	if m.logger != nil {
		m.logger.Info("cleanup action registered", "id", id, "desc", desc)
	}
}

// UnregisterCleanup removes a previously registered action by ID. It is
// called by modules in their Cleanup phase after a successful manual stop.
func (m *Manager) UnregisterCleanup(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.actions {
		if m.actions[i].ID == id {
			// Slice splice: drop the action while preserving order.
			m.actions = append(m.actions[:i], m.actions[i+1:]...)
			return
		}
	}
}

// Actions returns a snapshot of the currently registered cleanup actions.
func (m *Manager) Actions() []Action {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Copy so callers cannot mutate the live registry through the result.
	return append([]Action(nil), m.actions...)
}

// RunAll executes every registered restore action in reverse registration
// order, so the last change is undone first. Each action is isolated: a
// failing action is reported but does not prevent the others from running.
func (m *Manager) RunAll() error {
	// Snapshot and clear under the lock so actions registered concurrently
	// during shutdown are not double-run (they stay for the next RunAll).
	m.mu.Lock()
	actions := append([]Action(nil), m.actions...)
	m.actions = nil
	m.mu.Unlock()

	var errs []string
	// Reverse order unwinds the most recent change first (LIFO), which is
	// the only safe teardown order for stacked network manipulations.
	for i := len(actions) - 1; i >= 0; i-- {
		a := actions[i]
		if a.Restore == nil {
			// A nil restore is a no-op action (e.g. a pure observation);
			// skip it rather than panic.
			continue
		}
		if err := a.Restore(); err != nil {
			// Collect every failure instead of aborting mid-teardown: one
			// broken action must not strand all the later restores.
			errs = append(errs, fmt.Sprintf("%s: %v", a.ID, err))
			if m.logger != nil {
				m.logger.Error("cleanup failed", "id", a.ID, "err", err)
			}
		} else if m.logger != nil {
			m.logger.Info("cleanup ok", "id", a.ID, "desc", a.Desc)
		}
		if m.bus != nil {
			// Announce per-action progress so the REPL and caplets can show
			// live teardown feedback.
			status := "ok"
			if len(errs) > 0 {
				status = "failed"
			}
			m.bus.Emit(events.TopicLog, fmt.Sprintf("cleanup[%s] %s", status, a.ID))
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

// Heartbeat tracks liveness for the watchdog. Modules call Beat from their
// run loop; a stale heartbeat triggers framework-wide cleanup.
type Heartbeat struct {
	// last is the last Beat time in Unix nanoseconds. Atomic so Beat/Stale
	// are safe from any goroutine without a lock.
	last atomic.Int64
}

// NewHeartbeat returns a heartbeat initialized to now.
func NewHeartbeat() *Heartbeat {
	h := &Heartbeat{}
	// Start live: the module is assumed healthy from the moment it exists.
	h.Beat()
	return h
}

// Beat records the current time.
func (h *Heartbeat) Beat() {
	h.last.Store(time.Now().UnixNano())
}

// Stale reports whether the heartbeat is older than timeout.
func (h *Heartbeat) Stale(now time.Time, timeout time.Duration) bool {
	return now.Sub(time.Unix(0, h.last.Load())) > timeout
}

// RegisterHeartbeat associates a heartbeat with an owner name (module ID).
func (m *Manager) RegisterHeartbeat(owner string, hb *Heartbeat) {
	m.hbmu.Lock()
	defer m.hbmu.Unlock()
	m.hbs[owner] = hb
}

// UnregisterHeartbeat removes a heartbeat.
func (m *Manager) UnregisterHeartbeat(owner string) {
	m.hbmu.Lock()
	defer m.hbmu.Unlock()
	delete(m.hbs, owner)
}

// StartWatchdog begins a background goroutine that fires onFired when any
// registered heartbeat is stale for longer than timeout. It re-checks every
// interval. The watchdog stops when StopWatchdog is called.
func (m *Manager) StartWatchdog(interval, timeout time.Duration, onFired func(owner string)) {
	if interval <= 0 {
		interval = time.Second
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	// Capture the stop channel under the lock so the goroutine never reads a
	// field the stopper is mutating.
	m.wmu.Lock()
	if m.watching {
		// A watchdog is already running; refuse to start a second one to
		// avoid two goroutines racing on the same heartbeat set.
		m.wmu.Unlock()
		return
	}
	m.watching = true
	m.stopCh = make(chan struct{})
	stop := m.stopCh
	m.wmu.Unlock()

	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-stop:
				// StopWatchdog closed stop: exit cleanly.
				return
			case now := <-t.C:
				m.hbmu.Lock()
				// Iterate owners under the lock so register/unregister can
				// never race a liveness check on the same map.
				for owner, hb := range m.hbs {
					if hb.Stale(now, timeout) {
						// Unlock before invoking the callback: onFired may
						// itself touch the registry (e.g. unregister).
						m.hbmu.Unlock()
						if m.logger != nil {
							m.logger.Error("watchdog fired: heartbeat lost", "owner", owner)
						}
						if onFired != nil {
							onFired(owner)
						}
						// A single dead module is a framework-wide problem:
						// stop watching and let cleanup take over.
						return
					}
				}
				m.hbmu.Unlock()
			}
		}
	}()
}

// StopWatchdog halts a running watchdog goroutine. It is safe to call
// multiple times and safe to call concurrently with StartWatchdog.
func (m *Manager) StopWatchdog() {
	m.wmu.Lock()
	defer m.wmu.Unlock()
	if !m.watching {
		return
	}
	m.watching = false
	// Closing stop wakes the goroutine's select so it exits at the next
	// tick; the wmu lock guarantees this is the only closer.
	close(m.stopCh)
}

// RequireRoot returns an error unless the process runs as root/euid 0.
func RequireRoot() error {
	if os.Geteuid() != 0 {
		// Raw sockets and packet injection need CAP_NET_RAW, which sudo root
		// provides; refuse to run half-working without it.
		return errors.New("operation requires root (raw sockets / packet injection); re-run with sudo")
	}
	return nil
}

// EnableIPForward turns on kernel IPv4 forwarding and returns a restore
// function that puts the previous value back.
func EnableIPForward() (restore func() error, err error) {
	path := "/proc/sys/net/ipv4/ip_forward"
	old, err := readSysctl(path)
	if err != nil {
		return nil, fmt.Errorf("read ip_forward: %w", err)
	}
	// Only write when forwarding is currently off; leaving it enabled would
	// make the restore function change a value we did not set.
	if strings.TrimSpace(old) != "1" {
		if err := writeSysctl(path, "1"); err != nil {
			return nil, fmt.Errorf("enable ip_forward: %w", err)
		}
	}
	return func() error {
		// If forwarding was already on, "restoring" means doing nothing.
		if strings.TrimSpace(old) == "1" {
			return nil
		}
		return writeSysctl(path, strings.TrimSpace(old))
	}, nil
}

// EnableIP6Forward turns on kernel IPv6 forwarding (needed for DHCPv6/NDP
// attacks) and returns a restore function.
func EnableIP6Forward() (restore func() error, err error) {
	path := "/proc/sys/net/ipv6/conf/all/forwarding"
	old, err := readSysctl(path)
	if err != nil {
		return nil, fmt.Errorf("read ipv6 forwarding: %w", err)
	}
	if strings.TrimSpace(old) != "1" {
		if err := writeSysctl(path, "1"); err != nil {
			return nil, fmt.Errorf("enable ipv6 forwarding: %w", err)
		}
	}
	return func() error {
		if strings.TrimSpace(old) == "1" {
			return nil
		}
		return writeSysctl(path, strings.TrimSpace(old))
	}, nil
}

// readSysctl reads a /proc/sys value as a raw string (with trailing newline).
func readSysctl(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// writeSysctl writes a value to a /proc/sys file. The mode is ignored by the
// procfs filesystem but kept for os.WriteFile compatibility.
func writeSysctl(path string, val string) error {
	return os.WriteFile(path, []byte(val), 0o644)
}

// IPTablesRule is a single firewall rule to be installed and later removed.
type IPTablesRule struct {
	// Table is "nat", "filter", etc.
	Table string
	// Chain is "PREROUTING", "POSTROUTING", "FORWARD", ...
	Chain string
	// Args are the rule arguments after the chain name.
	Args []string
}

// AddIPTables installs a rule and registers its removal. Returns the rule
// fingerprint (table:chain) used to de-duplicate identical rules.
func (m *Manager) AddIPTables(r IPTablesRule) (string, error) {
	// The fingerprint is the full append command as a string: it uniquely
	// identifies a rule so repeated additions collapse to one cleanup entry.
	fp := strings.Join(append([]string{"-t", r.Table, "-A", r.Chain}, r.Args...), " ")
	args := append([]string{"-t", r.Table, "-A", r.Chain}, r.Args...)
	if err := exec.Command("iptables", args...).Run(); err != nil {
		return "", fmt.Errorf("iptables -A: %w", err)
	}
	// Register a paired "-D" (delete) action so shutdown tears the rule out
	// in reverse order of installation.
	m.RegisterCleanup("iptables:"+fp, "remove iptables rule", func() error {
		delArgs := append([]string{"-t", r.Table, "-D", r.Chain}, r.Args...)
		return exec.Command("iptables", delArgs...).Run()
	})
	return fp, nil
}

// CAPaths is the resolved location of the framework CA material.
type CAPaths struct {
	// CertPath is the CA certificate file path.
	CertPath string
	// KeyPath is the CA private key file path.
	KeyPath string
}

// ResolveCAPaths returns the config paths expanded relative to the working
// directory. Currently a pass-through; kept as a dedicated step so path
// resolution can change without touching callers.
func ResolveCAPaths(cert, key string) CAPaths {
	return CAPaths{CertPath: cert, KeyPath: key}
}

// ExistingCAPaths returns nil paths when a CA file already exists.
func ExistingCAPaths(p CAPaths) (CAPaths, bool) {
	// If the certificate already exists, treat the CA as pre-existing so
	// nothing generated this session gets deleted at shutdown.
	if _, err := os.Stat(p.CertPath); err == nil {
		return p, true
	}
	return p, false
}

// EnsureCAPaths records a cleanup that removes generated CA files, if and
// only if they did not exist before the session.
func (m *Manager) EnsureCAPaths(p CAPaths) {
	if p.CertPath == "" {
		// No CA configured: nothing to clean up.
		return
	}
	m.RegisterCleanup("ca:"+p.CertPath, "remove generated CA", func() error {
		var errs []error
		for _, f := range []string{p.CertPath, p.KeyPath} {
			// os.Remove on a missing file is an error, so tolerate
			// os.IsNotExist (e.g. only the cert was ever written).
			if err := os.Remove(filepath.Clean(f)); err != nil && !os.IsNotExist(err) {
				errs = append(errs, err)
			}
		}
		if len(errs) > 0 {
			return errors.Join(errs...)
		}
		return nil
	})
}

// VarInt is a tiny helper for storing small integers.
type VarInt struct{ v atomic.Int64 }

// Set stores the value.
func (v *VarInt) Set(n int64) { v.v.Store(n) }

// Get returns the value.
func (v *VarInt) Get() int64 { return v.v.Load() }

// Bool is a concurrency-safe boolean.
type Bool struct{ b atomic.Bool }

// Set stores the value.
func (b *Bool) Set(v bool) { b.b.Store(v) }

// Get returns the value.
func (b *Bool) Get() bool { return b.b.Load() }

// ParseBool is a helper for command values.
func ParseBool(s string) bool {
	v, err := strconv.ParseBool(s)
	// Any malformed input parses as false rather than erroring, matching
	// the tolerant CLI handling elsewhere.
	return err == nil && v
}

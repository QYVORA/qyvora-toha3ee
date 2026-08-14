package attacks

import (
	"fmt"
	"io"
	"log/slog"
	"sync"

	"github.com/QYVORA/qyvora-toha3ee/internal/config"
	"github.com/QYVORA/qyvora-toha3ee/internal/events"
	"github.com/QYVORA/qyvora-toha3ee/internal/netx"
	"github.com/QYVORA/qyvora-toha3ee/internal/safety"
	"github.com/QYVORA/qyvora-toha3ee/internal/store"
)

// AttackCtx carries everything a module needs to run, verify and clean up.
// It is created by the session and handed unchanged to every lifecycle method,
// which lets modules talk to the outside world (bus, store, interface) without
// reaching into framework internals.
type AttackCtx struct {
	// ID is the module instance identifier (normally the module ID).
	ID string
	// Bus is the process-wide event bus.
	Bus *events.Bus
	// Conf is the live configuration (modules read their knobs here).
	Conf *config.Config
	// Store is the shared host / credential / session / event store.
	Store *store.Store
	// Iface is the primary network interface.
	Iface *netx.Iface
	// Safety is the cleanup registry and preflight helper.
	Safety *safety.Manager
	// Logger is the structured logger for the session.
	Logger *slog.Logger
	// Out receives human-readable output.
	Out io.Writer
	// Targets is the resolved target host list.
	Targets []*store.Host
	// Done is closed when the session is shutting down or the module was told
	// to stop ("module off"). Long-running modules must select on it; the
	// channel is closed (not signalled) so a receive always unblocks and
	// there is no buffering or lost-wakeup race.
	Done <-chan struct{}
	// Heartbeat must be called periodically by long-running modules so the
	// watchdog can detect a dead poison loop. Assigning it replaces the
	// session-default beat with the module's own.
	Heartbeat func()
	// State is a per-instance key/value bag modules use to carry runtime
	// objects between Run, Verify and Cleanup. It is a sync.Map because
	// capture callbacks may write to it from other goroutines while Run is
	// blocking on ctx.Done.
	State *sync.Map
}

// GetState returns a module's runtime value by key.
func (c *AttackCtx) GetState(key string) (any, bool) {
	if c.State == nil {
		return nil, false
	}
	return c.State.Load(key)
}

// SetState stores a module runtime value by key.
func (c *AttackCtx) SetState(key string, v any) {
	// Lazily allocate the bag on first use so modules that never touch state
	// do not force a heap allocation at session setup.
	if c.State == nil {
		c.State = &sync.Map{}
	}
	c.State.Store(key, v)
}

// Printf writes formatted output to the session console.
func (c *AttackCtx) Printf(format string, args ...any) {
	if c.Out != nil {
		fmt.Fprintf(c.Out, format, args...)
	}
}

// Emit publishes an event and logs it through the store. The payload travels
// on the bus for subscribers; the topic+message also lands in the store's
// event log and in the structured logger so a finding is never lost even if
// no subscriber is attached.
func (c *AttackCtx) Emit(topic, msg string, payload any) {
	if c.Bus != nil {
		c.Bus.Emit(topic, payload)
	}
	if c.Store != nil {
		c.Store.LogEvent(topic, msg)
	}
	if c.Logger != nil {
		c.Logger.Info(msg, "topic", topic, "module", c.ID)
	}
}

// RunOpts normalizes module invocation options with defaults. It guarantees
// every requested key exists (with an empty value when the caller did not
// supply it) so modules can read opts without a nil-map or missing-key check.
func RunOpts(opts map[string]string, keys ...string) map[string]string {
	if opts == nil {
		opts = map[string]string{}
	}
	for _, k := range keys {
		if _, ok := opts[k]; !ok {
			opts[k] = ""
		}
	}
	return opts
}

// ModuleRuntime is the shared per-module runtime state produced by a
// successful Run and consumed by Verify and Cleanup. Modules may keep their
// own state in the AttackCtx keyed by module ID; this struct is a convenience
// for the common pattern of storing a cancel/stop handle.
type ModuleRuntime struct {
	// Stop closes to halt the module's background loop.
	Stop func()
	// Restored is set by Verify to record whether Cleanup already brought the
	// network back to its prior state (e.g. whether a poisoned ARP cache was
	// flushed or an interface was put back into managed mode).
	Restored bool
}

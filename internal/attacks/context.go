package attacks

import (
	"fmt"
	"io"
	"log/slog"
	"sync"

	"github.com/qyvora/toha3ee/internal/config"
	"github.com/qyvora/toha3ee/internal/events"
	"github.com/qyvora/toha3ee/internal/netx"
	"github.com/qyvora/toha3ee/internal/safety"
	"github.com/qyvora/toha3ee/internal/store"
)

// AttackCtx carries everything a module needs to run, verify and clean up.
// It is created by the session and handed unchanged to every lifecycle method.
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
	// to stop ("module off"). Long-running modules must select on it.
	Done <-chan struct{}
	// Heartbeat must be called periodically by long-running modules so the
	// watchdog can detect a dead poison loop.
	Heartbeat func()
	// State is a per-instance key/value bag modules use to carry runtime
	// objects between Run, Verify and Cleanup.
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

// Emit publishes an event and logs it through the store.
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

// RunOpts normalizes module invocation options with defaults.
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
	// Restored is set by Verify.
	Restored bool
}

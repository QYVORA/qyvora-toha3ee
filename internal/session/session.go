// Package session implements the interactive toha3ee session: the module
// lifecycle controller and the REPL that drives it. It is the only place the
// framework core talks to the attacks registry.
package session

import (
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/qyvora/toha3ee/internal/attacks"
	"github.com/qyvora/toha3ee/internal/config"
	"github.com/qyvora/toha3ee/internal/events"
	"github.com/qyvora/toha3ee/internal/netx"
	"github.com/qyvora/toha3ee/internal/safety"
	"github.com/qyvora/toha3ee/internal/store"
	"github.com/qyvora/toha3ee/internal/ui"
)

// Version is the framework version reported by the console banner and the
// `version` subcommand. The CLI overrides it via -ldflags at release builds.
var Version = "0.1.0"

// Session is one interactive framework instance bound to an interface.
type Session struct {
	Iface  *netx.Iface
	Bus    *events.Bus
	Store  *store.Store
	Conf   *config.Config
	Safety *safety.Manager
	Log    *slog.Logger
	Out    io.Writer
	UI     *ui.UI

	mu      sync.Mutex
	running map[string]*runningModule
	hijack  *hijackState
}

// runningModule tracks one live module instance.
type runningModule struct {
	mod     attacks.Module
	ctx     *attacks.AttackCtx
	done    chan struct{}
	started time.Time
	err     error
	wg      sync.WaitGroup
}

// New builds a fresh session with clean bus, store, safety and config.
func New(iface *netx.Iface, out io.Writer, log *slog.Logger) *Session {
	if log == nil {
		log = slog.Default()
	}
	if out == nil {
		out = io.Discard
	}
	bus := events.NewBus()
	return &Session{
		Iface:   iface,
		Bus:     bus,
		Store:   store.New(5000),
		Conf:    config.Default(),
		Safety:  safety.NewManager(bus, log),
		Log:     log,
		Out:     out,
		UI:      ui.New(out),
		running: make(map[string]*runningModule),
	}
}

// SetColor forces colors on or off for the whole session.
func (s *Session) SetColor(on bool) { s.UI.SetColor(on) }

// section prints a section header through the console UI.
func (s *Session) section(title string) { s.UI.Section(title) }

// statusf prints a [*] status line through the console UI.
func (s *Session) statusf(format string, args ...any) {
	s.UI.Status("*", format, args...)
}

// warnf prints a [!] warning line through the console UI.
func (s *Session) warnf(format string, args ...any) {
	s.UI.Status("!", format, args...)
}

// errorf prints a red [x] error line through the console UI.
func (s *Session) errorf(format string, args ...any) {
	s.UI.Err(format, args...)
}

// goodf prints a [+] success line through the console UI.
func (s *Session) goodf(format string, args ...any) {
	s.UI.Status("+", format, args...)
}

// Running returns the IDs of all currently running modules.
func (s *Session) Running() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.running))
	for id := range s.running {
		out = append(out, id)
	}
	return out
}

// IsRunning reports whether a module is live.
func (s *Session) IsRunning(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.running[id]
	return ok
}

// StartModule runs a module's full lifecycle in the background. It blocks
// only long enough to perform Preflight; Run proceeds asynchronously. For
// bounded modules Run completes on its own and Verify/Cleanup are applied.
func (s *Session) StartModule(id string, opts map[string]string) error {
	mod, ok := attacks.Get(id)
	if !ok {
		return fmt.Errorf("unknown module %q", id)
	}
	s.mu.Lock()
	if _, dup := s.running[id]; dup {
		s.mu.Unlock()
		return fmt.Errorf("%s is already running", id)
	}
	s.mu.Unlock()

	done := make(chan struct{})
	ctx := &attacks.AttackCtx{
		ID:        id,
		Bus:       s.Bus,
		Conf:      s.Conf,
		Store:     s.Store,
		Iface:     s.Iface,
		Safety:    s.Safety,
		Logger:    s.Log,
		Out:       ui.NewLineWriter(s.UI),
		Done:      done,
		State:     &sync.Map{},
		Heartbeat: func() {},
	}

	rep, err := mod.Preflight(ctx)
	if err != nil {
		return fmt.Errorf("%s preflight: %w", id, err)
	}
	s.UI.Section("preflight " + id)
	fmt.Fprint(ui.NewLineWriter(s.UI), rep.String())
	if blk := rep.Blocked(); blk != "" {
		s.warnf("%s blocked by %s; not started.", id, blk)
		return fmt.Errorf("%s blocked (missing %s)", id, blk)
	}
	meta := mod.Meta()
	if meta.Risk >= attacks.RiskHigh && !s.Conf.IsRiskConfirmed(id) && !s.Conf.GetBool(id, "risk_confirm", false) {
		return fmt.Errorf("%s is a %s-risk attack; run 'set %s.risk_confirm true' to allow", id, meta.Risk, id)
	}

	rm := &runningModule{mod: mod, ctx: ctx, done: done, started: time.Now()}
	s.mu.Lock()
	s.running[id] = rm
	s.mu.Unlock()

	rm.wg.Add(1)
	go func() {
		defer rm.wg.Done()
		rm.err = mod.Run(ctx, opts)
		select {
		case <-done:
		default:
			// Run returned before being told to stop: bounded module done.
			s.finishModule(id, rm)
		}
	}()

	s.Store.LogEvent(events.TopicModuleStarted, fmt.Sprintf("%s started", id))
	s.Bus.Emit(events.TopicModuleStarted, id)
	return nil
}

// finishModule runs Verify + Cleanup after Run returned.
func (s *Session) finishModule(id string, rm *runningModule) {
	s.mu.Lock()
	delete(s.running, id)
	s.mu.Unlock()

	if rm.err != nil {
		s.UI.Status("!", "%s finished with error: %v", id, rm.err)
		s.Store.LogEvent(events.TopicModuleFailed, fmt.Sprintf("%s failed: %v", id, rm.err))
		return
	}
	if imp, err := rm.mod.Verify(rm.ctx); err == nil && imp != nil {
		s.UI.Section("verified " + id)
		s.goodf("%s", imp.Summary)
		for k, v := range imp.Metrics {
			s.UI.KV(k, v)
		}
	}
	if err := rm.mod.Cleanup(rm.ctx); err != nil {
		s.warnf("%s cleanup: %v", id, err)
	}
	s.Store.LogEvent(events.TopicModuleStopped, fmt.Sprintf("%s stopped", id))
	s.Bus.Emit(events.TopicModuleStopped, id)
}

// StopModule halts a running module: closes its Done channel, waits for Run,
// then Verify + Cleanup.
func (s *Session) StopModule(id string) error {
	s.mu.Lock()
	rm, ok := s.running[id]
	s.mu.Unlock()
	if !ok {
		return fmt.Errorf("%s is not running", id)
	}
	close(rm.done)
	rm.wg.Wait()
	s.finishModule(id, rm)
	return nil
}

// StopAll halts every running module.
func (s *Session) StopAll() {
	for _, id := range s.Running() {
		_ = s.StopModule(id)
	}
}

// Shutdown stops all modules and runs the global cleanup registry so the
// network is restored before exit.
func (s *Session) Shutdown() {
	s.StopAll()
	if err := s.Safety.RunAll(); err != nil {
		s.warnf("cleanup: %v", err)
	}
	s.Bus.Close()
}

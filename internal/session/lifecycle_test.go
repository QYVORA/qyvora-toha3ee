package session

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/QYVORA/qyvora-toha3ee/internal/attacks"
	"github.com/QYVORA/qyvora-toha3ee/internal/events"
	"github.com/QYVORA/qyvora-toha3ee/internal/store"
)

// completedWatcher counts module.completed events for one module as they are
// emitted. A watcher goroutine feeds a counter because the bus is
// emit-as-you-go: reading "now" can miss an event that is still in flight, and
// Bus.Close later closes the subscriber channel.
type completedWatcher struct {
	n atomic.Int32
}

// watchCompleted subscribes before a run starts. stop detaches the subscriber
// and ends the goroutine so a test loop does not leak one per iteration.
func watchCompleted(s *Session, id string) (*completedWatcher, func()) {
	ch := make(chan events.Event, 64)
	s.Bus.Subscribe(events.TopicModuleCompleted, ch)
	w := &completedWatcher{}
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-done:
				return
			case ev, ok := <-ch:
				if !ok { // bus closed
					return
				}
				if run, ok := ev.Payload.(store.ModuleRun); ok && run.Module == id {
					w.n.Add(1)
				}
			}
		}
	}()
	stop := func() {
		s.Bus.Unsubscribe(events.TopicModuleCompleted, ch)
		close(done)
	}
	return w, stop
}

func freshModule(t *testing.T, m *stubModule) {
	t.Helper()
	if _, dup := attacks.Registry[m.Meta().ID]; dup {
		delete(attacks.Registry, m.Meta().ID)
	}
	attacks.Register(m)
	t.Cleanup(func() { delete(attacks.Registry, m.Meta().ID) })
}

// assertExactlyOne fails unless exactly one run and one completed event exist,
// waiting briefly after the run appears so a stray duplicate emission (the
// original bug) has time to surface.
func assertExactlyOne(t *testing.T, s *Session, w *completedWatcher, grace time.Duration) {
	t.Helper()
	waitFor(t, func() bool { return s.Store.RunCount() == 1 })
	waitFor(t, func() bool { return w.n.Load() == 1 })
	time.Sleep(grace)
	if got := s.Store.RunCount(); got != 1 {
		t.Fatalf("RunCount = %d, want exactly 1", got)
	}
	if got := w.n.Load(); got != 1 {
		t.Fatalf("module.completed = %d, want exactly 1", got)
	}
}

// TestStopRacingNaturalEnd reproduces the original double-completion race: a
// bounded module ends at the same instant StopModule runs. Completion must be
// recorded exactly once, no matter how the stop and the natural end interleave.
func TestStopRacingNaturalEnd(t *testing.T) {
	for i := 0; i < 100; i++ {
		s, _ := newTestSession(t)
		mod := &stubModule{id: "test.race", creds: 1}
		freshModule(t, mod)

		w, stop := watchCompleted(s, mod.id)
		if err := s.StartModule(mod.id, nil); err != nil {
			t.Fatalf("iteration %d: StartModule: %v", i, err)
		}
		// Stop while the bounded Run may be finishing on its own; when the
		// module already self-finished, StopModule reports "not running" and
		// the record lands a moment later. Either ordering must leave exactly
		// one run behind.
		_ = s.StopModule(mod.id)
		assertExactlyOne(t, s, w, 20*time.Millisecond)
		stop()
	}
}

// TestConcurrentStops hammers one module with many concurrent StopModule calls
// (the SIGINT Shutdown + StopAll + REPL stop can all overlap). The channel must
// be closed once with no panic, and exactly one stopped run recorded.
func TestConcurrentStops(t *testing.T) {
	s, _ := newTestSession(t)
	mod := &stubModule{id: "test.hammer", stop: true}
	freshModule(t, mod)

	w, stop := watchCompleted(s, mod.id)
	defer stop()
	if err := s.StartModule(mod.id, nil); err != nil {
		t.Fatalf("StartModule: %v", err)
	}

	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = s.StopModule(mod.id)
		}(i)
	}
	wg.Wait()

	assertExactlyOne(t, s, w, 100*time.Millisecond)
	run := s.Store.Runs()[0]
	if run.Status != "stopped" {
		t.Fatalf("run status = %q, want stopped", run.Status)
	}
	// The winning stop must succeed; the rest must report "not running".
	winners := 0
	for _, err := range errs {
		if err == nil {
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("successful StopModule calls = %d, want exactly 1", winners)
	}
}

// TestShutdownTwice exercises the SIGINT path where the signal handler and the
// deferred shutdown both run StopAll. Exactly one run and one completion must
// survive the double shutdown, and nothing may panic.
func TestShutdownTwice(t *testing.T) {
	s, _ := newTestSession(t)
	mod := &stubModule{id: "test.shutdown", stop: true}
	freshModule(t, mod)

	w, stop := watchCompleted(s, mod.id)
	defer stop()
	if err := s.StartModule(mod.id, nil); err != nil {
		t.Fatalf("StartModule: %v", err)
	}
	s.Shutdown()
	s.Shutdown()

	assertExactlyOne(t, s, w, 100*time.Millisecond)
	waitFor(t, func() bool { return len(s.Running()) == 0 })
}

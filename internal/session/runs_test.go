package session

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/QYVORA/qyvora-toha3ee/internal/attacks"
	"github.com/QYVORA/qyvora-toha3ee/internal/events"
	"github.com/QYVORA/qyvora-toha3ee/internal/safety"
	"github.com/QYVORA/qyvora-toha3ee/internal/store"
)

// stubModule is a bounded module used to exercise the run lifecycle without
// touching the network.
type stubModule struct {
	id    string
	err   error
	creds int
	stop  bool
}

func (m *stubModule) Meta() attacks.ModuleMeta {
	return attacks.ModuleMeta{ID: m.id, Category: "test", Risk: attacks.RiskLow}
}

func (m *stubModule) Preflight(_ *attacks.AttackCtx) (*safety.PreflightReport, error) {
	return &safety.PreflightReport{}, nil
}

func (m *stubModule) Run(ctx *attacks.AttackCtx, _ map[string]string) error {
	if m.stop {
		<-ctx.Done
		return nil
	}
	for i := 0; i < m.creds; i++ {
		ctx.Store.AddCred(store.Cred{Service: "test", Username: "u", Password: "p", Source: m.id})
	}
	return m.err
}

func (m *stubModule) Verify(_ *attacks.AttackCtx) (*attacks.Impact, error) {
	if m.err != nil {
		return nil, m.err
	}
	imp := &attacks.Impact{Summary: m.id + " proved"}
	imp.Add("creds", "done")
	return imp, nil
}

func (m *stubModule) Cleanup(_ *attacks.AttackCtx) error { return nil }

func TestModuleRunRecordsAndEmitsCompleted(t *testing.T) {
	s, _ := newTestSession(t)
	mod := &stubModule{id: "test.poc", creds: 1}
	attacks.Register(mod)
	t.Cleanup(func() { delete(attacks.Registry, mod.id) })

	ch := make(chan events.Event, 4)
	s.Bus.Subscribe(events.TopicModuleCompleted, ch)

	if err := s.StartModule(mod.id, nil); err != nil {
		t.Fatalf("StartModule: %v", err)
	}
	waitFor(t, func() bool { return s.Store.RunCount() == 1 })

	runs := s.Store.Runs()
	run := runs[0]
	if run.Module != mod.id || run.Status != "success" {
		t.Fatalf("run = %+v, want module=%s success", run, mod.id)
	}
	if run.Summary != mod.id+" proved" {
		t.Errorf("run summary = %q", run.Summary)
	}
	if run.Metrics["creds"] != "done" {
		t.Errorf("run metrics = %v", run.Metrics)
	}
	if !strings.Contains(run.EvidenceRef, "credentials:1") {
		t.Errorf("evidence_ref = %q, want credentials:1", run.EvidenceRef)
	}
	select {
	case ev := <-ch:
		payload, ok := ev.Payload.(store.ModuleRun)
		if !ok {
			t.Fatalf("module.completed payload type = %T", ev.Payload)
		}
		if payload.ID != run.ID || payload.Module != mod.id {
			t.Errorf("event payload = %+v", payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("module.completed event not emitted")
	}
}

func TestModuleRunFailedRecordsError(t *testing.T) {
	s, _ := newTestSession(t)
	mod := &stubModule{id: "test.fail", err: errors.New("boom")}
	attacks.Register(mod)
	t.Cleanup(func() { delete(attacks.Registry, mod.id) })

	if err := s.StartModule(mod.id, nil); err != nil {
		t.Fatalf("StartModule: %v", err)
	}
	waitFor(t, func() bool { return s.Store.RunCount() == 1 })

	run := s.Store.Runs()[0]
	if run.Status != "failed" || run.Error != "boom" {
		t.Fatalf("run = %+v, want failed with boom", run)
	}
}

func TestModuleRunStoppedRecordsStopped(t *testing.T) {
	s, _ := newTestSession(t)
	mod := &stubModule{id: "test.stop", stop: true}
	attacks.Register(mod)
	t.Cleanup(func() { delete(attacks.Registry, mod.id) })

	if err := s.StartModule(mod.id, nil); err != nil {
		t.Fatalf("StartModule: %v", err)
	}
	if err := s.StopModule(mod.id); err != nil {
		t.Fatalf("StopModule: %v", err)
	}

	run := s.Store.Runs()[0]
	if run.Status != "stopped" {
		t.Fatalf("run status = %q, want stopped", run.Status)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met before timeout")
}

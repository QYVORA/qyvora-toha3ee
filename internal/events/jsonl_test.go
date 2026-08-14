package events

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestEmitterWritesCanonicalJSONL(t *testing.T) {
	var buf bytes.Buffer
	e := NewEmitter(&buf, "t3-test")
	e.Info("toha3ee", RunStarted, map[string]any{"version": "0.1.0"})
	e.Warn("toha3ee", Warning, map[string]any{"message": "slow"})
	e.Fail("toha3ee", Error, map[string]any{"message": "boom"})

	sc := bufio.NewScanner(&buf)
	var got []StreamEvent
	for sc.Scan() {
		var ev StreamEvent
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			t.Fatalf("unmarshal %q: %v", sc.Text(), err)
		}
		got = append(got, ev)
	}
	if len(got) != 3 {
		t.Fatalf("got %d events, want 3", len(got))
	}
	if got[0].SchemaVersion != SchemaVersion || got[0].ExecutionID != "t3-test" || got[0].Framework != "toha3ee" {
		t.Errorf("envelope wrong: %+v", got[0])
	}
	if got[0].Level != LevelInfo || got[0].Event != RunStarted {
		t.Errorf("event = %s/%s", got[0].Level, got[0].Event)
	}
	if got[2].Level != LevelError || got[2].Event != Error {
		t.Errorf("event = %s/%s", got[2].Level, got[2].Event)
	}
}

func TestEmitterNilSafe(t *testing.T) {
	var e *Emitter
	e.Info("toha3ee", RunStarted, nil) // must not panic
}

func TestSafePayloadFallsBackOnString(t *testing.T) {
	if got := safePayload(nil); got != nil {
		t.Errorf("nil payload = %v", got)
	}
	if got := safePayload("plain"); got != "plain" {
		t.Errorf("string payload = %v", got)
	}
	// A channel cannot be JSON-marshalled; it must degrade to a string.
	ch := make(chan int)
	if got := safePayload(ch); got == ch {
		t.Error("unmarshalable payload must not be passed through raw")
	}
	if got := safePayload(map[string]int{"a": 1}); got == nil {
		t.Error("marshalable payload should pass through")
	}
}

// syncBuffer makes bytes.Buffer safe to read while subscriber goroutines write.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// TestSubscribeJSONL bridges the bus to the stream: emitting on a known topic
// produces the mapped stream event with the payload preserved.
func TestSubscribeJSONL(t *testing.T) {
	var buf syncBuffer
	e := NewEmitter(&buf, "t3-bridge")
	bus := NewBus()
	SubscribeJSONL(bus, e)

	bus.Emit(TopicHostNew, "192.168.1.20")
	bus.Emit(TopicCredFound, map[string]string{"user": "alice"})
	bus.Emit(TopicModuleStarted, "net.scan")
	bus.Emit(TopicModuleFailed, "net.scan")
	bus.Emit(TopicARPSpoofStarted, "10.0.0.1")

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if n := strings.Count(buf.String(), "\n"); n == 5 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 5 {
		t.Fatalf("got %d lines, want 5:\n%s", len(lines), buf.String())
	}
	got := map[string]string{}
	for _, ln := range lines {
		var ev StreamEvent
		if err := json.Unmarshal([]byte(ln), &ev); err != nil {
			t.Fatalf("bad line %q: %v", ln, err)
		}
		got[ev.Event] = ln
	}
	for _, want := range []string{HostDiscovered, CredentialFound, ModuleStarted, ModuleFailed, "arp.spoof.started"} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing stream event %q in:\n%s", want, buf.String())
		}
	}
	if !strings.Contains(got[HostDiscovered], `"192.168.1.20"`) {
		t.Errorf("host payload missing from stream:\n%s", got[HostDiscovered])
	}
	if got[ModuleFailed] == "" {
		t.Error("module.failed missing")
	}
}

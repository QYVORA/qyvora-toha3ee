package events

import (
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"
)

// SchemaVersion is the event schema version every emitted event carries. It
// matches the canonical QYVORA contract shared with Jabari and Anansi so an
// agent can consume any framework's stream uniformly.
const SchemaVersion = "1.0"

// JSONL event names. The dotted namespace is stable across frameworks.
const (
	RunStarted      = "run.started"
	RunCompleted    = "run.completed"
	ModuleStarted   = "module.started"
	ModuleStopped   = "module.stopped"
	ModuleFailed    = "module.failed"
	ModuleCompleted = "module.completed"
	HostDiscovered  = "host.discovered"
	CredentialFound = "credential.discovered"
	SessionCaptured = "session.captured"
	Warning         = "warning"
	Error           = "error"
	ReportGenerated = "report.generated"
)

// JSONL levels classify how an event should be treated by a consumer.
const (
	LevelInfo    = "info"
	LevelWarning = "warning"
	LevelError   = "error"
)

// StreamEvent is one line of the JSONL stream.
type StreamEvent struct {
	SchemaVersion string         `json:"schema_version"`
	Timestamp     time.Time      `json:"timestamp"`
	ExecutionID   string         `json:"execution_id"`
	Framework     string         `json:"framework"`
	Level         string         `json:"level"`
	Event         string         `json:"event"`
	Data          map[string]any `json:"data,omitempty"`
}

// Emitter writes StreamEvents as JSON Lines to an io.Writer. It is safe for
// concurrent use because module callbacks emit from many goroutines.
type Emitter struct {
	mu     sync.Mutex
	w      io.Writer
	execID string
}

// NewEmitter returns an Emitter writing JSONL to w. Every event carries
// execID as its execution_id so a stream can be grouped by run.
func NewEmitter(w io.Writer, execID string) *Emitter {
	return &Emitter{w: w, execID: execID}
}

// Emit writes a single event tagged with the framework name.
func (e *Emitter) Emit(framework, level, name string, data map[string]any) {
	if e == nil || e.w == nil {
		return
	}
	line, err := json.Marshal(StreamEvent{
		SchemaVersion: SchemaVersion,
		Timestamp:     time.Now().UTC(),
		ExecutionID:   e.execID,
		Framework:     framework,
		Level:         level,
		Event:         name,
		Data:          data,
	})
	if err != nil {
		return
	}
	line = append(line, '\n')
	e.mu.Lock()
	defer e.mu.Unlock()
	_, _ = e.w.Write(line)
}

// Info emits an informational event.
func (e *Emitter) Info(framework, name string, data map[string]any) {
	e.Emit(framework, LevelInfo, name, data)
}

// Warn emits a warning event.
func (e *Emitter) Warn(framework, name string, data map[string]any) {
	e.Emit(framework, LevelWarning, name, data)
}

// Fail emits an error event.
func (e *Emitter) Fail(framework, name string, data map[string]any) {
	e.Emit(framework, LevelError, name, data)
}

// safePayload turns an arbitrary bus payload into something the JSONL stream
// can carry: the payload itself when it serializes cleanly, otherwise a
// string rendering so the line is never dropped.
func safePayload(payload any) any {
	if payload == nil {
		return nil
	}
	if _, err := json.Marshal(payload); err == nil {
		return payload
	}
	return fmt.Sprintf("%v", payload)
}

// subscribeTopics maps every bus topic to a stable stream event name so the
// framework's audit trail becomes a machine-readable JSONL feed.
var subscribeTopics = map[string]struct {
	name  string
	level string
}{
	TopicHostNew:           {HostDiscovered, LevelInfo},
	TopicCredFound:         {CredentialFound, LevelInfo},
	TopicSessionCaptured:   {SessionCaptured, LevelInfo},
	TopicModuleStarted:     {ModuleStarted, LevelInfo},
	TopicModuleStopped:     {ModuleStopped, LevelInfo},
	TopicModuleFailed:      {ModuleFailed, LevelError},
	TopicModuleCompleted:   {ModuleCompleted, LevelInfo},
	TopicModulePreflighted: {ModuleStarted, LevelInfo},
	TopicARPSpoofStarted:   {"arp.spoof.started", LevelInfo},
	TopicARPSpoofStopped:   {"arp.spoof.stopped", LevelInfo},
	TopicLog:               {"log", LevelInfo},
}

// SubscribeJSONL bridges the framework's event bus to a JSONL emitter: every
// event published on a known topic becomes one stream line carrying the
// original payload in data. The subscription outlives the emitter; Close on
// the emitter only stops writes.
func SubscribeJSONL(bus *Bus, em *Emitter) {
	if bus == nil || em == nil {
		return
	}
	for topic, mapping := range subscribeTopics {
		ch := make(chan Event, 128)
		bus.Subscribe(topic, ch)
		go func(topic string, mapping struct {
			name  string
			level string
		}) {
			for ev := range ch {
				em.Emit("toha3ee", mapping.level, mapping.name, map[string]any{
					"topic": topic,
					"data":  safePayload(ev.Payload),
				})
			}
		}(topic, mapping)
	}
}

package events

import (
	"encoding/json"
	"fmt"
	"io"

	shared "github.com/QYVORA/qyvora-events"
)

// SchemaVersion is the event schema version every emitted event carries. It
// matches the canonical QYVORA contract shared with Jabari and Anansi so an
// agent can consume any framework's stream uniformly.
const SchemaVersion = shared.SchemaVersion

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
	LevelInfo    = shared.LevelInfo
	LevelWarning = shared.LevelWarning
	LevelError   = shared.LevelError
)

type StreamEvent = shared.Event
type Emitter = shared.Emitter

// NewEmitter returns an emitter writing JSONL to w.
func NewEmitter(w io.Writer, execID string) *Emitter { return shared.NewEmitter(w, execID) }

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

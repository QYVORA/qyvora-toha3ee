// Package events implements the framework-wide publish/subscribe event bus.
//
// Every module communicates with the rest of the framework exclusively
// through named topics such as "net.host.new", "credential.found" and
// "session.captured". This allows modules to be chained at runtime without
// the core ever knowing what a specific attack does.
package events

import (
	"sync"
	"time"
)

// Event is a single message published on the bus.
type Event struct {
	// Topic is the event topic, e.g. "credential.found".
	Topic string
	// Time is when the event was emitted.
	Time time.Time
	// Payload carries the event-specific data.
	Payload any
}

// Well-known topic names used across the framework. Modules may introduce
// their own topics; these constants document the stable public surface.
const (
	TopicHostNew           = "net.host.new"
	TopicHostSeen          = "net.host.seen"
	TopicCredFound         = "credential.found"
	TopicCredPhished       = "credential.phished"
	TopicSessionCaptured   = "session.captured"
	TopicARPSpoofStarted   = "arp.spoof.started"
	TopicARPSpoofStopped   = "arp.spoof.stopped"
	TopicModuleStarted     = "module.started"
	TopicModuleStopped     = "module.stopped"
	TopicModulePreflighted = "module.preflighted"
	TopicModuleFailed      = "module.failed"
	TopicPacketCaptured    = "net.packet.captured"
	TopicLog               = "log.message"
)

// ringCapacity is the number of recent events the bus remembers for late
// consumers such as "events.show".
const ringCapacity = 2000

// Bus is a concurrency-safe publish/subscribe hub. Emit never blocks: if a
// subscriber's channel is full the event is dropped for that subscriber. All
// events are additionally stored in an internal ring buffer.
type Bus struct {
	mu      sync.RWMutex
	subs    map[string][]chan Event
	ring    []Event
	ringIdx int
	closed  bool
}

// NewBus returns an empty bus ready for use.
func NewBus() *Bus {
	return &Bus{subs: make(map[string][]chan Event)}
}

// Subscribe registers ch to receive every event published on topic.
// The channel is never written to after Bus.Close is called.
func (b *Bus) Subscribe(topic string, ch chan Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	b.subs[topic] = append(b.subs[topic], ch)
}

// Unsubscribe removes ch from the topic's subscriber list.
func (b *Bus) Unsubscribe(topic string, ch chan Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	subs := b.subs[topic]
	for i, c := range subs {
		if c == ch {
			b.subs[topic] = append(subs[:i], subs[i+1:]...)
			return
		}
	}
}

// Emit publishes payload on topic to every current subscriber. Emit is
// non-blocking: events are dropped for subscribers whose buffer is full.
func (b *Bus) Emit(topic string, payload any) {
	ev := Event{Topic: topic, Time: time.Now(), Payload: payload}

	b.mu.RLock()
	closed := b.closed
	subs := b.subs[topic]
	for _, ch := range subs {
		select {
		case ch <- ev:
		default:
		}
	}
	b.mu.RUnlock()
	if closed {
		return
	}

	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return
	}
	if len(b.ring) < ringCapacity {
		b.ring = append(b.ring, ev)
	} else {
		b.ring[b.ringIdx%ringCapacity] = ev
	}
	b.ringIdx++
	b.mu.Unlock()
}

// Recent returns up to n most recent events, oldest first. It is intended for
// UI features such as "events.show" and for report generation.
func (b *Bus) Recent(n int) []Event {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if n <= 0 || len(b.ring) == 0 {
		return nil
	}
	if n > len(b.ring) {
		n = len(b.ring)
	}
	start := len(b.ring) - n
	return append([]Event(nil), b.ring[start:]...)
}

// Close shuts the bus down, closing every subscriber channel.
func (b *Bus) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	b.closed = true
	for _, subs := range b.subs {
		for _, ch := range subs {
			close(ch)
		}
	}
	b.subs = make(map[string][]chan Event)
}

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
	TopicHostNew           = "net.host.new"        // a previously unseen host appeared
	TopicHostSeen          = "net.host.seen"       // a known host was observed again
	TopicCredFound         = "credential.found"    // credentials recovered from the wire
	TopicCredPhished       = "credential.phished"  // credentials submitted to a phish page
	TopicSessionCaptured   = "session.captured"    // a full HTTP session was harvested
	TopicARPSpoofStarted   = "arp.spoof.started"   // ARP spoofing began on a target
	TopicARPSpoofStopped   = "arp.spoof.stopped"   // ARP spoofing stopped on a target
	TopicModuleStarted     = "module.started"      // a module began running
	TopicModuleStopped     = "module.stopped"      // a module finished
	TopicModulePreflighted = "module.preflighted"  // a module passed preflight
	TopicModuleFailed      = "module.failed"       // a module errored out
	TopicModuleCompleted   = "module.completed"    // a module run finished and recorded verified impact
	TopicPacketCaptured    = "net.packet.captured" // a frame was captured
	TopicLog               = "log.message"         // a generic human-readable log line
)

// ringCapacity is the number of recent events the bus remembers for late
// consumers such as "events.show".
const ringCapacity = 2000

// Bus is a concurrency-safe publish/subscribe hub. Emit never blocks: if a
// subscriber's channel is full the event is dropped for that subscriber. All
// events are additionally stored in an internal ring buffer.
type Bus struct {
	mu      sync.RWMutex            // guards subs, ring, ringIdx and closed
	subs    map[string][]chan Event // topic -> list of subscriber channels
	ring    []Event                 // circular buffer of recent events (see ringCapacity)
	ringIdx int                     // next write slot in ring; modulo len(ring)
	closed  bool                    // set once by Close, never unset
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
		// Once closed the bus never writes to any channel, so registering a
		// new subscriber now would leave it waiting forever.
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
			// Replace the slot with everything but the removed channel,
			// keeping relative order of the remaining subscribers.
			b.subs[topic] = append(subs[:i], subs[i+1:]...)
			return
		}
	}
}

// Emit publishes payload on topic to every current subscriber. Emit is
// non-blocking: events are dropped for subscribers whose buffer is full.
func (b *Bus) Emit(topic string, payload any) {
	ev := Event{Topic: topic, Time: time.Now(), Payload: payload}

	// Deliver to subscribers under a read lock; the select/default pattern
	// makes each send non-blocking so a slow consumer can never stall the
	// emitter or the whole framework.
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
		// Bus is shut down: skip ring bookkeeping and the extra lock.
		return
	}

	// Record the event for late consumers. The closed flag is re-checked
	// under the write lock because it could have flipped between the read
	// lock above and this point.
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return
	}
	if len(b.ring) < ringCapacity {
		// Buffer still growing: plain append keeps events in arrival order.
		b.ring = append(b.ring, ev)
	} else {
		// Buffer full: overwrite the slot written ringCapacity events ago,
		// turning the slice into a circular buffer.
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
		// Never return more than what is stored; n is only an upper bound.
		n = len(b.ring)
	}
	start := len(b.ring) - n
	// Copy so callers cannot mutate the bus's backing array.
	return append([]Event(nil), b.ring[start:]...)
}

// Close shuts the bus down, closing every subscriber channel.
func (b *Bus) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		// Closing a channel twice panics; guard against repeated Close.
		return
	}
	b.closed = true
	// Wake every blocked subscriber by closing its channel. This is the only
	// place channels are closed, so no other goroutine races a send here.
	for _, subs := range b.subs {
		for _, ch := range subs {
			close(ch)
		}
	}
	// Drop the subscriber list so late Subscribe calls see an empty map; the
	// closed flag already makes them no-ops anyway.
	b.subs = make(map[string][]chan Event)
}

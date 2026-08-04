package events

import (
	"testing"
	"time"
)

func TestBusSubscribeAndEmit(t *testing.T) {
	b := NewBus()
	ch := make(chan Event, 16)
	b.Subscribe("credential.found", ch)

	b.Emit("credential.found", "user:pass")
	select {
	case ev := <-ch:
		if ev.Topic != "credential.found" {
			t.Fatalf("wrong topic: %s", ev.Topic)
		}
		if ev.Payload != "user:pass" {
			t.Fatalf("wrong payload: %v", ev.Payload)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for event")
	}
}

func TestBusTopicIsolation(t *testing.T) {
	b := NewBus()
	ch := make(chan Event, 8)
	b.Subscribe("net.host.new", ch)

	b.Emit("credential.found", 1)
	b.Emit("net.host.new", 2)

	select {
	case ev := <-ch:
		if ev.Payload != 2 {
			t.Fatalf("unexpected payload %v", ev.Payload)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for net.host.new")
	}
}

func TestBusNonBlockingEmit(t *testing.T) {
	b := NewBus()
	ch := make(chan Event, 1)
	b.Subscribe("x", ch)

	// Fill the buffer, then emit more than fits. Emit must not block.
	ch <- Event{}
	for i := 0; i < 100; i++ {
		b.Emit("x", i)
	}
	<-ch
}

func TestBusRecent(t *testing.T) {
	b := NewBus()
	for i := 0; i < 10; i++ {
		b.Emit("t", i)
	}
	rec := b.Recent(3)
	if len(rec) != 3 {
		t.Fatalf("expected 3 recent events, got %d", len(rec))
	}
	if rec[2].Payload != 9 {
		t.Fatalf("expected newest payload 9, got %v", rec[2].Payload)
	}
}

func TestBusUnsubscribe(t *testing.T) {
	b := NewBus()
	ch := make(chan Event, 4)
	b.Subscribe("t", ch)
	b.Unsubscribe("t", ch)

	b.Emit("t", 1)
	select {
	case ev := <-ch:
		t.Fatalf("received event after unsubscribe: %v", ev)
	default:
	}
}

func TestBusCloseClosesChannels(t *testing.T) {
	b := NewBus()
	ch := make(chan Event, 4)
	b.Subscribe("t", ch)
	b.Close()
	_, ok := <-ch
	if ok {
		t.Fatal("channel not closed after Bus.Close")
	}
}

func TestBusEmitAfterClose(t *testing.T) {
	b := NewBus()
	ch := make(chan Event, 4)
	b.Subscribe("t", ch)
	b.Close()
	b.Emit("t", 1) // must not panic
}

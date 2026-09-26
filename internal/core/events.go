package core

import "sync"

// Event is a fan-out notification published by the state actor after a
// Command has been applied (§2.5 "event bus"). Handlers such as an SSE
// stream or the notification worker subscribe via Bus.Subscribe. Event
// types match the bus documented in §7.2, e.g. "wan.up", "wan.down",
// "guest.authorized", "guest.expired", "app.state", "config.rejected",
// "portal.sync".
type Event struct {
	Type string
	Data any
}

// Bus is an in-process, buffered, drop-oldest fan-out bus (§2.5: "channel
// ber-buffer, drop-oldest"). Publish never blocks the state actor: a slow
// subscriber loses its oldest unread event rather than stalling command
// processing (PD-3 depends on the actor never blocking on a subscriber).
type Bus struct {
	mu   sync.Mutex
	subs map[int]chan Event
	next int
	cap  int
}

func NewBus(bufferPerSubscriber int) *Bus {
	if bufferPerSubscriber <= 0 {
		bufferPerSubscriber = 64
	}
	return &Bus{subs: make(map[int]chan Event), cap: bufferPerSubscriber}
}

// Subscribe returns a receive-only channel of events and an unsubscribe
// func. Call the unsubscribe func when done to release the channel.
func (b *Bus) Subscribe() (<-chan Event, func()) {
	b.mu.Lock()
	defer b.mu.Unlock()
	id := b.next
	b.next++
	ch := make(chan Event, b.cap)
	b.subs[id] = ch
	return ch, func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		if c, ok := b.subs[id]; ok {
			delete(b.subs, id)
			close(c)
		}
	}
}

// Publish fans e out to every current subscriber. If a subscriber's buffer
// is full, its single oldest event is dropped to make room, so Publish
// itself is always non-blocking.
func (b *Bus) Publish(e Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, ch := range b.subs {
		select {
		case ch <- e:
		default:
			select {
			case <-ch:
			default:
			}
			select {
			case ch <- e:
			default:
			}
		}
	}
}

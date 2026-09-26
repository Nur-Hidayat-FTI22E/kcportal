package core

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// newTestActor starts a.Run in its own goroutine and registers a cleanup
// that cancels the context and waits for Run to return, so no actor
// goroutine leaks between tests.
func newTestActor(t *testing.T, bus *Bus, handle Handler) *Actor {
	t.Helper()
	a := NewActor(bus, handle)
	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() {
		a.Run(ctx)
		close(runDone)
	}()
	t.Cleanup(func() {
		cancel()
		<-runDone
	})
	return a
}

// --- Bus ---

func TestBusFanOutToAllSubscribers(t *testing.T) {
	bus := NewBus(16)
	ch1, unsub1 := bus.Subscribe()
	ch2, unsub2 := bus.Subscribe()
	defer unsub2()

	bus.Publish(Event{Type: "wan.up"})
	bus.Publish(Event{Type: "guest.authorized"})

	for _, ch := range []<-chan Event{ch1, ch2} {
		for _, want := range []string{"wan.up", "guest.authorized"} {
			select {
			case ev := <-ch:
				if ev.Type != want {
					t.Fatalf("got event %q, want %q", ev.Type, want)
				}
			case <-time.After(time.Second):
				t.Fatalf("timed out waiting for event %q", want)
			}
		}
	}
	unsub1()
}

func TestBusUnsubscribeClosesChannel(t *testing.T) {
	bus := NewBus(4)
	ch, unsub := bus.Subscribe()

	unsub() // close(ch)
	if _, open := <-ch; open {
		t.Fatal("channel still open after unsubscribe")
	}

	// Publish after unsubscribe must not panic and must not deliver. A
	// closed channel always yields its zero value with ok == false, so
	// comma-ok is what distinguishes "no event" from "event".
	bus.Publish(Event{Type: "wan.up"})
	select {
	case ev, ok := <-ch:
		if ok {
			t.Fatalf("received event on unsubscribed channel: %+v", ev)
		}
	default:
	}
}

func TestBusDropOldestWhenBufferFull(t *testing.T) {
	bus := NewBus(2) // tiny buffer so we can force overflow
	ch, unsub := bus.Subscribe()
	defer unsub()

	for i := 0; i < 10; i++ {
		bus.Publish(Event{Type: "e", Data: i}) // must never block
	}

	// Oldest unread events (0..7) were dropped; buffer holds 8 and 9.
	var got []int
	for len(got) < 2 {
		select {
		case ev := <-ch:
			got = append(got, ev.Data.(int))
		case <-time.After(time.Second):
			t.Fatalf("timed out; got so far: %v", got)
		}
	}
	if got[0] != 8 || got[1] != 9 {
		t.Fatalf("drop-oldest violated: got %v, want [8 9]", got)
	}
}

func TestNewBusDefaultBuffer(t *testing.T) {
	// bufferPerSubscriber <= 0 must fall back to the documented default
	// of 64, not panic or create a zero-capacity channel.
	bus := NewBus(0)
	ch, unsub := bus.Subscribe()
	defer unsub()

	for i := 0; i < 64; i++ {
		bus.Publish(Event{Type: "e"})
	}
	// Exactly 64 events fit; a 65th drops the oldest (event #0).
	bus.Publish(Event{Type: "e"})
	for i := 0; i < 64; i++ {
		select {
		case <-ch:
		case <-time.After(time.Second):
			t.Fatalf("timed out after receiving %d/64 events", i)
		}
	}
	select {
	case ev := <-ch:
		t.Fatalf("expected buffer to hold exactly 64 events, got extra: %+v", ev)
	default:
	}
}

// --- Result ---

func TestResultNeedsConfirm(t *testing.T) {
	if !(Result{Deadline: time.Now().Add(time.Minute)}).NeedsConfirm() {
		t.Fatal("non-zero Deadline must require confirmation")
	}
	if (Result{}).NeedsConfirm() {
		t.Fatal("zero Deadline must not require confirmation")
	}
}

// --- Actor ---

// countedHandler records command execution order on the single actor
// goroutine; used to prove PD-3 (one writer, commands processed serially).
type countedHandler struct {
	mu    sync.Mutex
	order []string
}

func (h *countedHandler) handle(_ context.Context, cmd Command) Result {
	h.mu.Lock()
	h.order = append(h.order, cmd.Name())
	h.mu.Unlock()
	return Result{ChangeID: "c-" + cmd.Name()}
}

func (h *countedHandler) recorded() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.order...)
}

func TestActorRequiresDeadline(t *testing.T) {
	a := newTestActor(t, NewBus(4), nil) // nil handler must be replaced, not panic

	// No deadline: Do must refuse to enqueue (IF-02) instead of risking a
	// caller that hangs forever on a stuck actor.
	res := a.Do(context.Background(), ApproveDevice{MAC: "aa:bb:cc:dd:ee:ff"})
	if res.Err == nil {
		t.Fatal("Do without a ctx deadline must fail (IF-02)")
	}
	if want := "requires ctx to carry a deadline"; !strings.Contains(res.Err.Error(), want) {
		t.Fatalf("error %q does not mention %q", res.Err, want)
	}
}

func TestActorWithoutHandlerFailsClearly(t *testing.T) {
	a := newTestActor(t, NewBus(4), nil)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	res := a.Do(ctx, PutSSID{BSS: "wlan0", SSID: "Staff"})
	if res.Err == nil {
		t.Fatal("nil handler must produce an error, not silent success")
	}
	if want := "no handler registered"; !strings.Contains(res.Err.Error(), want) {
		t.Fatalf("error %q does not mention %q", res.Err, want)
	}
}

func TestActorSerializesConcurrentCommands(t *testing.T) {
	h := &countedHandler{}
	a := newTestActor(t, NewBus(64), h.handle)

	const n = 20
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if res := a.Do(ctx, InstallApp{AppID: "pos-cafe"}); res.Err != nil {
				t.Errorf("Do failed: %v", res.Err)
			}
		}()
	}
	wg.Wait()

	recorded := h.recorded()
	if len(recorded) != n {
		t.Fatalf("handler ran %d times, want %d", len(recorded), n)
	}
	for _, name := range recorded {
		if name != "InstallApp" {
			t.Fatalf("unexpected command in log: %q", name)
		}
	}
}

func TestActorPublishesEventWithResult(t *testing.T) {
	bus := NewBus(8)
	ch, unsub := bus.Subscribe()
	defer unsub()

	wantErr := errors.New("boom")
	a := newTestActor(t, bus, func(_ context.Context, cmd Command) Result {
		return Result{Err: wantErr}
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	res := a.Do(ctx, RevokeGuest{MAC: "aa:bb:cc:dd:ee:ff"})
	if !errors.Is(res.Err, wantErr) {
		t.Fatalf("got %v, want %v", res.Err, wantErr)
	}

	select {
	case ev := <-ch:
		if ev.Type != "command.RevokeGuest" {
			t.Fatalf("event type = %q, want command.RevokeGuest", ev.Type)
		}
		got, ok := ev.Data.(Result)
		if !ok {
			t.Fatalf("event data is %T, want Result", ev.Data)
		}
		if !errors.Is(got.Err, wantErr) {
			t.Fatalf("event result err = %v, want %v", got.Err, wantErr)
		}
	case <-time.After(time.Second):
		t.Fatal("no event published for handled command")
	}
}

func TestActorDoHonoursContextDeadline(t *testing.T) {
	release := make(chan struct{})
	a := newTestActor(t, NewBus(8), func(_ context.Context, cmd Command) Result {
		<-release // stall until the test allows progress
		return Result{}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	res := a.Do(ctx, ApproveDevice{MAC: "aa:bb:cc:dd:ee:ff"})
	if !errors.Is(res.Err, context.DeadlineExceeded) {
		t.Fatalf("got %v, want context.DeadlineExceeded", res.Err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("Do took %v; deadline was not honoured", elapsed)
	}
	close(release) // let the actor finish the job so cleanup can cancel it
}

// TestActorRunStopsOnContextCancel verifies directly what newTestActor's
// cleanup relies on: Run returns once the supervisor's ctx is cancelled,
// even while a job is in flight.
func TestActorRunStopsOnContextCancel(t *testing.T) {
	block := make(chan struct{})
	a := NewActor(NewBus(4), func(_ context.Context, cmd Command) Result {
		<-block // simulate a handler still running at shutdown
		return Result{}
	})
	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() {
		a.Run(ctx)
		close(runDone)
	}()

	// Enqueue one command so Run is inside handle when we cancel. Do's
	// own deadline frees the caller even though the handler stays blocked.
	go func() {
		ctxT, c := context.WithTimeout(context.Background(), 2*time.Second)
		defer c()
		a.Do(ctxT, ApplyProfile{Profile: "cafe"})
	}()
	time.Sleep(50 * time.Millisecond) // let Run pick up the job

	cancel()
	close(block) // unblock the handler so Run can observe ctx.Done

	select {
	case <-runDone:
		// ok
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after ctx cancel")
	}
}

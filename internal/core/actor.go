package core

import (
	"context"
	"fmt"
)

// Handler applies a single Command to durable state (state.db) and
// produces whatever the reconciler needs to push down to nft/hostsdir/
// hostapd/dnsmasq (PD-4: "desired state di SQLite, aturan turunan di
// RAM"). M0 ships the actor's concurrency skeleton only; the real
// per-command handler (state mutation + reconciler Plan) arrives with M1.
type Handler func(ctx context.Context, cmd Command) Result

type job struct {
	ctx   context.Context
	cmd   Command
	reply chan Result
}

// Actor is the single goroutine allowed to mutate state.db, and therefore
// the single writer of everything derived from it (PD-3: "Satu penulis").
// HTTP handlers, watchers, and workers never touch nft/dnsmasq/hostapd
// directly — they send a Command and wait for a Result.
type Actor struct {
	handle Handler
	bus    *Bus
	jobs   chan job
}

// NewActor builds an Actor. handle may be nil during M0 bring-up; every
// Command will then fail with a clear "no handler registered" error
// instead of silently doing nothing.
func NewActor(bus *Bus, handle Handler) *Actor {
	if handle == nil {
		handle = func(_ context.Context, cmd Command) Result {
			return Result{Err: fmt.Errorf("core: no handler registered for %s (reconciler lands in M1)", cmd.Name())}
		}
	}
	return &Actor{handle: handle, bus: bus, jobs: make(chan job, 32)}
}

// Run processes commands until ctx is cancelled. Call it exactly once,
// from the supervisor, in its own goroutine — starting a second Run for
// the same Actor would violate PD-3.
func (a *Actor) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case j := <-a.jobs:
			res := a.handle(j.ctx, j.cmd)
			if a.bus != nil {
				a.bus.Publish(Event{Type: "command." + j.cmd.Name(), Data: res})
			}
			j.reply <- res
		}
	}
}

// Do enqueues cmd and blocks for a Result, honouring ctx's deadline.
// IF-02 requires a deadline context ("deadline konteks wajib") so a stuck
// actor can never hang a caller forever.
func (a *Actor) Do(ctx context.Context, cmd Command) Result {
	if _, ok := ctx.Deadline(); !ok {
		return Result{Err: fmt.Errorf("core: Actor.Do requires ctx to carry a deadline (IF-02)")}
	}
	reply := make(chan Result, 1)
	select {
	case a.jobs <- job{ctx: ctx, cmd: cmd, reply: reply}:
	case <-ctx.Done():
		return Result{Err: ctx.Err()}
	}
	select {
	case res := <-reply:
		return res
	case <-ctx.Done():
		return Result{Err: ctx.Err()}
	}
}

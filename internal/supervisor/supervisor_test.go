package supervisor

import (
	"context"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"
)

func newQuietSupervisor() *Supervisor {
	// Panic-recovery tests log on purpose; keep test output clean.
	return New(slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// TestSupervisorRunsAllTasksAndDrainsOnCancel verifies the two halves of
// Run's contract: every registered task starts, and Run blocks until all
// of them have returned after ctx is cancelled.
func TestSupervisorRunsAllTasksAndDrainsOnCancel(t *testing.T) {
	const n = 4
	var started atomic.Int32
	s := newQuietSupervisor()
	for i := 0; i < n; i++ {
		s.Add("task", func(ctx context.Context) {
			started.Add(1)
			<-ctx.Done() // run until the supervisor shuts down
		})
	}

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() {
		s.Run(ctx)
		close(runDone)
	}()

	if !eventually(2*time.Second, func() bool { return started.Load() == n }) {
		t.Fatalf("only %d/%d tasks started", started.Load(), n)
	}

	cancel()
	select {
	case <-runDone:
		// Run returned after cancel — good.
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after ctx cancel")
	}
}

// TestSupervisorRecoversTaskPanic proves a panicking task neither takes
// down the process nor prevents siblings from running or Run from
// draining ("call Add for everything before calling Run" — the recover
// wrapper is what makes a single bad task survivable).
func TestSupervisorRecoversTaskPanic(t *testing.T) {
	s := newQuietSupervisor()
	s.Add("panic-task", func(ctx context.Context) {
		panic("boom — must be recovered")
	})

	var siblingStarted atomic.Bool
	s.Add("sibling", func(ctx context.Context) {
		siblingStarted.Store(true)
		<-ctx.Done()
	})

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() {
		s.Run(ctx)
		close(runDone)
	}()

	if !eventually(2*time.Second, siblingStarted.Load) {
		t.Fatal("sibling task never started after the panicking task died")
	}

	cancel()
	select {
	case <-runDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after ctx cancel")
	}
}

// TestSupervisorWaitsForRunningTasksOnShutdown verifies Run drains the
// WaitGroup: a task that keeps cleaning up after ctx.Done (e.g. flushing
// state) must be allowed to finish before Run returns.
func TestSupervisorWaitsForRunningTasksOnShutdown(t *testing.T) {
	const cleanupDelay = 200 * time.Millisecond

	finished := make(chan struct{})
	s := newQuietSupervisor()
	s.Add("cleanup-task", func(ctx context.Context) {
		<-ctx.Done()
		time.Sleep(cleanupDelay) // simulate post-cancel cleanup work
		close(finished)
	})

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() {
		s.Run(ctx)
		close(runDone)
	}()

	time.Sleep(50 * time.Millisecond) // let the task start
	start := time.Now()
	cancel()

	select {
	case <-runDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return")
	}
	if elapsed := time.Since(start); elapsed < cleanupDelay {
		t.Fatalf("Run returned after %v; task cleanup (%v) was not awaited", elapsed, cleanupDelay)
	}
	select {
	case <-finished:
		// task had finished before Run returned — correct drain
	default:
		t.Fatal("Run returned before the task finished")
	}
}

// TestNewUsesDefaultLogger documents that New(nil) is legal (falls back
// to slog.Default()) — cmd/kcportald always passes a logger, but tests
// and future callers shouldn't crash without one.
func TestNewUsesDefaultLogger(t *testing.T) {
	s := New(nil)
	if s == nil {
		t.Fatal("New(nil) returned nil")
	}
	if s.log == nil {
		t.Fatal("New(nil) did not install a fallback logger")
	}
}

// eventually polls cond until it holds or the timeout elapses — used for
// cross-goroutine state we can't wait on with a plain channel receive.
func eventually(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return cond()
}

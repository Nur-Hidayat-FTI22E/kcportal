// Package supervisor starts and stops the long-running pieces listed in
// §2.5 (state actor, watchers, listeners, workers). This is also where
// the systemd watchdog (sd_notify, WatchdogSec=30 per the base spec's
// Appendix F.2) will eventually be wired in — M0 gives it just enough
// shape to run the state actor; listeners/watchers/workers arrive with
// M1-M3.
package supervisor

import (
	"context"
	"log/slog"
	"sync"
)

type Supervisor struct {
	log   *slog.Logger
	wg    sync.WaitGroup
	tasks []func(ctx context.Context)
}

func New(log *slog.Logger) *Supervisor {
	if log == nil {
		log = slog.Default()
	}
	return &Supervisor{log: log}
}

// Add registers a task to run for the supervisor's lifetime. A panic in
// task is recovered and logged rather than taking the whole process down
// — call Add for everything before calling Run.
func (s *Supervisor) Add(name string, task func(ctx context.Context)) {
	s.tasks = append(s.tasks, func(ctx context.Context) {
		defer func() {
			if r := recover(); r != nil {
				s.log.Error("task panicked", "task", name, "panic", r)
			}
		}()
		task(ctx)
	})
}

// Run starts every registered task and blocks until ctx is cancelled and
// all tasks have returned.
func (s *Supervisor) Run(ctx context.Context) {
	for _, t := range s.tasks {
		t := t
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			t(ctx)
		}()
	}
	<-ctx.Done()
	s.wg.Wait()
}

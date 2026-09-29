// pos-cafe is the PoS App Pack binary (M4, §6.5) running rootless in
// Podman with Network=host, behind the apps proxy (M4.2: TLS :8443 →
// here). M4.1 ships the skeleton: /healthz + an index line — enough
// to validate the container foundation (quadlet / fallback unit,
// volume, restart policy, linger) end-to-end. M4.3 fills in the real
// PoS (auth, shifts, orders, payments, printer) on this same mux.
//
// Env (IF-03): POS_ADDR listen address. Default 0.0.0.0:8444 — the
// container shares the host network (keep-id maps container root to
// the unprivileged kcapps user), and only the M4.2 proxy (local
// process) forwards :8443 → :8444. 8444 is NOT in the ruleset's
// allow-list, so remote clients can only reach it through the proxy.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func newServer(log *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("pos-cafe skeleton (M4.1) — real PoS lands in M4.3\n"))
	})
	log.Info("pos-cafe handler wired", "endpoints", "/healthz,/")
	return mux
}

func main() {
	addr := os.Getenv("POS_ADDR")
	if addr == "" {
		addr = "0.0.0.0:8444"
	}
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))

	srv := &http.Server{
		Addr:              addr,
		Handler:           newServer(log),
		ReadHeaderTimeout: 3 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		close(errCh)
	}()
	log.Info("pos-cafe listening", "addr", addr)

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
		<-errCh
	case err := <-errCh:
		if err != nil {
			log.Error("pos-cafe died", "err", err)
			os.Exit(1)
		}
	}
	log.Info("shutdown complete")
}

// pos-onboard (M4.2, §7.1) — the one-shot onboarding helper for the
// PoS plane: keeps the venue-local CA (T1, DD-09) and the apps-proxy
// server certificate alive in /var/lib/kcportal/pos/pki, and serves
// the CA certificate to cashier browsers so the TLS :8443 plane
// becomes trusted with one tap. Runs as a SYSTEM unit (root) because
// the PKI dir is root-owned; the proxy reads the certs, never writes.
//
// Endpoints (reachable only from the POS/mgmt plane per the ruleset —
// `meta mark 0x02 tcp dport { 8443, 8082 } accept`):
//
//	GET /ca.crt   → the CA certificate (application/x-x509-ca-cert)
//	GET /healthz  → {"status":"ok"}
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"kotacloud-portal/internal/pos/pki"
)

func main() {
	pkiDir := os.Getenv("POS_PKI_DIR")
	if pkiDir == "" {
		pkiDir = "/var/lib/kcportal/pos/pki"
	}
	addr := os.Getenv("POS_ONBOARD_ADDR")
	if addr == "" {
		addr = ":8082"
	}
	hosts := []string{"pos.kcp.internal", "10.20.1.1", "10.20.2.1"}
	if h := os.Getenv("POS_CERT_HOSTS"); h != "" {
		hosts = splitAndTrim(h)
	}
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))

	ca, err := pki.EnsureCA(pkiDir)
	if err != nil {
		log.Error("local CA unavailable", "err", err)
		os.Exit(1)
	}
	if _, err := ca.EnsureServerCert(pkiDir, hosts); err != nil {
		log.Error("server cert issue failed", "err", err)
		os.Exit(1)
	}
	// Hand the PKI files to kcapps: pos-proxy (user unit) must read the
	// CA + leaf including the 0600 keys. Root writes, kcapps owns.
	if err := chownTree(pkiDir, "kcapps"); err != nil {
		log.Warn("cannot hand PKI to kcapps — proxy will fail to read it", "err", err)
	}
	log.Info("pki ready", "dir", pkiDir, "hosts", hosts)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /ca.crt", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-x509-ca-cert")
		w.Header().Set("Content-Disposition", "attachment; filename=kotacloud-local-ca.crt")
		_, _ = w.Write(ca.CaCertPEM())
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 3 * time.Second}
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
	log.Info("pos-onboard listening", "addr", addr)
	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
		<-errCh
	case err := <-errCh:
		if err != nil {
			log.Error("pos-onboard died", "err", err)
			os.Exit(1)
		}
	}
	log.Info("shutdown complete")
}

// chownTree hands every file under dir to the named user (keys stay
// 0600, so the proxy can read them as its own).
func chownTree(dir, username string) error {
	u, err := user.Lookup(username)
	if err != nil {
		return err
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return err
	}
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Chown(path, uid, gid)
	})
}

func splitAndTrim(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			if piece := s[start:i]; piece != "" {
				out = append(out, piece)
			}
			start = i + 1
		}
	}
	return out
}

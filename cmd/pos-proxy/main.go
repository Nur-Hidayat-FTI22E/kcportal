// pos-proxy (M4.2) — the single remote entry point into the App Pack.
// Terminates TLS on :8443 with the venue-local-CA-signed certificate
// (SNI pos.kcp.internal + IPs) and forwards plain HTTP to
// 127.0.0.1:8444 where pos-cafe listens. Runs as a USER unit under
// kcapps: it reads the PKI files (mounted into /data by the container
// contract — on the host they are group/owner-readable by kcapps) and
// reaches the app over loopback, which the DD-14 app_egress chain
// always permits.
//
// The ruleset only exposes 8443 to the mgmt/POS planes
// (`meta mark 0x02 tcp dport { 8443, 8082 } accept`); everything else
// is already dropped upstream of this process.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"kotacloud-portal/internal/pos/pki"
)

func main() {
	pkiDir := os.Getenv("POS_PKI_DIR")
	if pkiDir == "" {
		pkiDir = "/var/lib/kcportal/pos/pki"
	}
	addr := os.Getenv("POS_PROXY_ADDR")
	if addr == "" {
		addr = ":8443"
	}
	backend := os.Getenv("POS_BACKEND")
	if backend == "" {
		backend = "http://127.0.0.1:8444"
	}
	hosts := []string{"pos.kcp.internal", "10.20.1.1", "10.20.2.1"}
	if h := os.Getenv("POS_CERT_HOSTS"); h != "" {
		hosts = splitAndTrim(h)
	}
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// The proxy READS the existing CA + leaf (written by pos-onboard);
	// it must not create PKI state — a permission error here means the
	// onboard unit never ran, which is exactly what we want surfaced.
	ca, err := pki.EnsureCA(pkiDir)
	if err != nil {
		log.Error("cannot load local CA (did pos-onboard run?)", "err", err)
		os.Exit(1)
	}
	pair, err := ca.EnsureServerCert(pkiDir, hosts)
	if err != nil {
		log.Error("cannot load server cert", "err", err)
		os.Exit(1)
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           newProxyHandler(backend, log),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
		// ListenAndServeTLS("", "") with pre-set Certificates: the
		// pair is loaded above so cert rotation only needs a restart.
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}},
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		close(errCh)
	}()
	log.Info("pos-proxy listening", "addr", addr, "backend", backend)
	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
		<-errCh
	case err := <-errCh:
		if err != nil {
			log.Error("pos-proxy died", "err", err)
			os.Exit(1)
		}
	}
	log.Info("shutdown complete")
}

// newProxyHandler builds the reverse proxy turning plain HTTP into
// the pos-cafe backend. Extracted so tests exercise the exact
// production wiring.
func newProxyHandler(backend string, log *slog.Logger) http.Handler {
	backendURL, err := url.Parse(backend)
	if err != nil {
		log.Error("bad POS_BACKEND url", "err", err)
		os.Exit(1)
	}
	return &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(backendURL)
			r.Out.Host = r.In.Host
		},
		Transport: &http.Transport{
			MaxIdleConns:          16,
			IdleConnTimeout:       30 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
		},
		ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelWarn),
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			log.Warn("backend unavailable", "err", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			_, _ = io.WriteString(w, `{"error":"pos backend unavailable"}`+"\n")
		},
	}
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

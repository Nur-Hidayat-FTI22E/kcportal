package main

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"kotacloud-portal/internal/pos/pki"
)

// TestProxyRoundTrip spins the M4.2 chain in-process: local CA →
// server cert → dummy pos-cafe backend → TLS proxy; then fetches
// through it with the CA as the ONLY root, proving a browser that
// installed the onboard CA can reach the app with zero out-of-band
// trust.
func TestProxyRoundTrip(t *testing.T) {
	dir := t.TempDir()
	ca, err := pki.EnsureCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := ca.EnsureServerCert(dir, []string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}

	backendHits := 0
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		backendHits++
		_, _ = io.WriteString(w, "pos-cafe says hi")
	}))
	defer backend.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	srv := &http.Server{
		Handler: newProxyHandler(backend.URL, slog.New(slog.NewTextHandler(os.Stderr, nil))),
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{pair},
		},
	}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca.CaCertPEM()) {
		t.Fatal("CA PEM not parseable")
	}
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}},
		Timeout:   5 * time.Second,
	}
	resp, err := client.Get("https://" + ln.Addr().String())
	if err != nil {
		t.Fatalf("HTTPS roundtrip failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "pos-cafe says hi" {
		t.Fatalf("body = %q", body)
	}
	if backendHits != 1 {
		t.Fatalf("backend hits = %d", backendHits)
	}
}

// Dead backend → the proxy answers 502 JSON itself (controlled error,
// not a hang or a connection reset).
func TestProxyBadGatewayOnDeadBackend(t *testing.T) {
	dir := t.TempDir()
	ca, err := pki.EnsureCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := ca.EnsureServerCert(dir, []string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	srv := &http.Server{
		Handler: newProxyHandler("http://127.0.0.1:1", slog.New(slog.NewTextHandler(io.Discard, nil))),
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{pair},
		},
	}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.CaCertPEM())
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}},
		Timeout:   10 * time.Second,
	}
	resp, err := client.Get("https://" + ln.Addr().String())
	if err != nil {
		t.Fatalf("proxy must answer 502 itself: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
}

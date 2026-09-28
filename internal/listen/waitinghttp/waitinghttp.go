// Package waitinghttp serves the Waiting zone's info page (ERR-01,
// §2.4 listener table: waiting-http on 10.20.99.1:8081, mark 0). The
// ERR-01 DNAT redirects unauthenticated :80 HTTP here; the page shows
// the client's MAC and approval status, and /state is the JSON the page
// polls every 3 s until an admin approves the device (FR-BNC-003).
package waitinghttp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// netip aliases net.IP for the Lookup signature; kept local so the
// package never leaks the alias name.

// DeviceView is what the page knows about the asking client. Lookup is
// the seam to state.db (devices + ip_leases); the portal GUI (M3) will
// read the same rows through the actor.
type DeviceView struct {
	MAC      string `json:"mac"`
	IP       string `json:"ip"`
	State    string `json:"state"` // waiting | approved | blocked | expired | dormant
	Hostname string `json:"hostname,omitempty"`
	Approved bool   `json:"approved"`
	Note     string `json:"note,omitempty"` // shown when approved/blocked
}

// Lookup resolves the asking client by source IP (DD-10: the client is
// never trusted to report its own identity; the kernel neighbor table
// already classified it). Missing rows mean "still waiting".
type Lookup func(clientIP netip) DeviceView

type netip = net.IP // Server is the waiting-http listener.
type Server struct {
	Addr   string // default 10.20.99.1:8081
	Lookup Lookup
	Log    *slog.Logger
	srv    *http.Server

	mu        sync.Mutex
	boundAddr string // written by Run, read via ServeAddr
}

// New builds the listener.
func New(addr string, lookup Lookup, log *slog.Logger) *Server {
	if addr == "" {
		addr = "10.20.99.1:8081"
	}
	s := &Server{Addr: addr, Lookup: lookup, Log: log}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handlePage)
	mux.HandleFunc("/state", s.handleState)
	s.srv = &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 3 * time.Second,
		// The page polls /state every 3 s (§4.5 stub note); generous
		// idle timeout keeps phones happy without pinning conns forever.
		IdleTimeout: 30 * time.Second,
	}
	return s
}

// freebindListenConfig sets IP_FREEBIND(15) so the bind on 10.20.99.1
// succeeds before reconcile has created the bridge address (§2.4:
// "listener memakai IP_FREEBIND dan dijalankan ulang oleh supervisor
// bila bind gagal"). Needs CAP_NET_RAW... actually IP_FREEBIND needs
// no specific capability on Linux; it just marks the socket.
func freebindListenConfig() *net.ListenConfig {
	return &net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var opErr error
			err := c.Control(func(fd uintptr) {
				opErr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_FREEBIND, 1)
			})
			if err != nil {
				return err
			}
			return opErr
		},
	}
}

// Run serves until ctx is cancelled (supervisor task shape). Use
// ":0" in Addr for tests; ServeAddr then reports the bound address.
func (s *Server) Run(ctx context.Context) error {
	ln, err := freebindListenConfig().Listen(ctx, "tcp", s.Addr)
	if err != nil {
		return fmt.Errorf("waitinghttp: listen %s: %w", s.Addr, err)
	}
	s.mu.Lock()
	s.boundAddr = ln.Addr().String()
	s.mu.Unlock()
	errCh := make(chan error, 1)
	go func() {
		if err := s.srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()
	s.Log.Info("waiting-http listening", "addr", s.boundAddr)
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.srv.Shutdown(shutdownCtx)
		<-errCh
		return nil
	case err := <-errCh:
		return err
	}
}

// ServeAddr reports the bound address after Run starts (with ":0" this
// is the kernel-assigned port tests need).
func (s *Server) ServeAddr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.boundAddr
}

func (s *Server) clientIP(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return net.ParseIP(r.RemoteAddr)
	}
	return net.ParseIP(host)
}

// handleState is the 3 s poll endpoint: 200 with state JSON, always —
// pollers treat errors as "keep waiting".
func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	ip := s.clientIP(r)
	if ip == nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	view := DeviceView{IP: ip.String(), State: "waiting"}
	if s.Lookup != nil {
		view = s.Lookup(ip)
	}
	_ = json.NewEncoder(w).Encode(view)
}

// handlePage renders the human page: a minimal, dependency-free HTML
// that polls /state and reloads on approval. The DNAT already brought
// the client here, so plain HTTP is all Waiting clients can do (ERR-01).
func (s *Server) handlePage(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	view := DeviceView{IP: "", State: "waiting"}
	if ip != nil {
		view = DeviceView{IP: ip.String(), State: "waiting"}
		if s.Lookup != nil {
			view = s.Lookup(ip)
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	state := "menunggu persetujuan admin"
	if view.Approved {
		state = "perangkat disetujui — sambungkan ulang Wi-Fi"
	} else if view.State == "blocked" {
		state = "perangkat diblokir — hubungi admin"
	}
	_, _ = w.Write([]byte(`<!doctype html>
<html lang="id"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>KotaCloud — Menunggu Persetujuan</title></head>
<body style="font-family:sans-serif;max-width:32rem;margin:10vh auto;padding:0 1rem">
<h1>Menunggu persetujuan</h1>
<p>MAC: <code>` + view.MAC + `</code></p>
<p>Status: <strong id="st">` + state + `</strong></p>
<p id="hint">Halaman ini memeriksa otomatis setiap 3 detik.</p>
<script>
async function poll(){
  try{
    const r = await fetch('/state',{cache:'no-store'});
    const j = await r.json();
    if(j.approved){ document.getElementById('st').textContent='perangkat disetujui — sambungkan ulang Wi-Fi'; return; }
    if(j.state==='blocked'){ document.getElementById('st').textContent='perangkat diblokir — hubungi admin'; return; }
  }catch(e){}
  setTimeout(poll,3000);
}
poll();
</script>
</body></html>`))
}

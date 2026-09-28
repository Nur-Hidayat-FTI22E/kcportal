// Package dhcphook implements the kcportald side of IF-05b: dnsmasq's
// dhcp-script helper (dhcp-hook) forwards every lease add/old/del as one
// JSON line to our unix socket /run/kcportal/hook.sock; this watcher
// accepts, decodes, and hands each event to the state actor via a
// callback. The socket is local-only (listener table §2.4: `hook | unix
// /run/kcportal/hook.sock | lokal`).
package dhcphook

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Event is one lease transition as forwarded by dhcp-hook:
//
//	add|old|del <mac> <ip> <hostname>   (dnsmasq argv, lease action)
//	DNSMASQ_INTERFACE=br-lan            (env, source interface)
//
// encoded as a single JSON object per line.
type Event struct {
	Action    string `json:"action"` // "add" | "old" | "del"
	MAC       string `json:"mac"`
	IP        string `json:"ip"`
	Hostname  string `json:"hostname,omitempty"`
	Interface string `json:"interface,omitempty"` // DNSMASQ_INTERFACE
}

// Handler processes one accepted lease event. It runs on the watcher's
// accept loop — keep it quick or offload (the state actor's Do is the
// intended sink; it never blocks on slow subscribers).
type Handler func(ev Event)

// Watcher owns the hook.sock listener.
type Watcher struct {
	dir     string // socket directory, PD-4 tmpfs /run/kcportal
	handle  Handler
	log     *slog.Logger
	ln      net.Listener
	mu      sync.Mutex
	started bool
}

// New prepares the watcher; Run binds and serves.
func New(dir string, handle Handler, log *slog.Logger) *Watcher {
	if log == nil {
		log = slog.Default()
	}
	return &Watcher{dir: dir, handle: handle, log: log}
}

// Run binds /run/kcportal/hook.sock and serves until ctx is cancelled.
// It is a supervisor task: it returns only when the context ends or the
// listener fatally fails.
func (w *Watcher) Run(ctx context.Context) error {
	sock := filepath.Join(w.dir, "hook.sock")
	if err := os.MkdirAll(w.dir, 0o750); err != nil {
		return fmt.Errorf("dhcphook: mkdir %s: %w", w.dir, err)
	}
	// A stale socket from a crashed previous run prevents bind.
	if err := os.Remove(sock); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("dhcphook: remove stale socket: %w", err)
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return fmt.Errorf("dhcphook: listen %s: %w", sock, err)
	}
	// dhcp-hook runs as the dnsmasq user; the group-writable socket is
	// how it reaches us without root.
	if err := os.Chmod(sock, 0o660); err != nil {
		ln.Close()
		return fmt.Errorf("dhcphook: chmod socket: %w", err)
	}

	w.mu.Lock()
	w.ln, w.started = ln, true
	w.mu.Unlock()

	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	w.log.Info("dhcp hook listening", "socket", sock)

	// Closing the listener unblocks Accept; that is our shutdown path.
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				w.log.Info("dhcp hook stopped")
				return nil
			default:
				return fmt.Errorf("dhcphook: accept: %w", err)
			}
		}
		go w.serve(conn)
	}
}

// serve reads one JSON event per line from a hook connection. dhcp-hook
// is fire-and-forget (100 ms budget), so a short read deadline and
// per-connection goroutine are the right shape. The watcher normalises
// the MAC to the canonical lower-case form every downstream consumer
// (state.db, nft rendering) expects, and drops anything that is not an
// add/old/del event — dnsmasq only sends those three.
func (w *Watcher) serve(conn net.Conn) {
	defer conn.Close()
	dec := json.NewDecoder(conn)
	for {
		var ev Event
		if err := dec.Decode(&ev); err != nil {
			return // EOF or garbage: either way the connection is done
		}
		switch {
		case ev.Action != "add" && ev.Action != "old" && ev.Action != "del":
			w.log.Warn("unknown lease action dropped", "event", ev)
			continue
		case ev.MAC == "" || ev.IP == "":
			w.log.Warn("malformed lease event dropped", "event", ev)
			continue
		}
		ev.MAC = strings.ToLower(ev.MAC)
		w.handle(ev)
	}
}

// WriteHelper emits the dhcp-hook C helper source. The helper is a tiny
// static binary on the Pi that dnsmasq execs on every lease change; it
// forwards argv + DNSMASQ_INTERFACE as one JSON line and never blocks
// longer than 100 ms. (M1 ships the source; compiling it into the image
// is a packaging task.)
const HelperSource = `// dhcp-hook — forwards dnsmasq lease events to kcportald's hook.sock.
// dnsmasq dhcp-script contract: <action> <mac> <ip> <hostname> argv,
// DNSMASQ_INTERFACE in the environment.
package main

import (
	"encoding/json"
	"net"
	"os"
	"time"
)

func main() {
	if len(os.Args) < 4 {
		return
	}
	ev := struct {
		Action, MAC, IP, Hostname, Interface string
	}{os.Args[1], os.Args[2], os.Args[3], os.Args[4], os.Getenv("DNSMASQ_INTERFACE")}
	if len(os.Args) > 4 {
		ev.Hostname = os.Args[4]
	}
	conn, err := net.DialTimeout("unix", "/run/kcportal/hook.sock", 100*time.Millisecond)
	if err != nil {
		return // portal down: enforcement is nft-side, so silence is fine
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(100 * time.Millisecond))
	json.NewEncoder(conn).Encode(ev)
}
`

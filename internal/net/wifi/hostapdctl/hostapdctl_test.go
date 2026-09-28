package hostapdctl

import (
	"context"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
) // fakeHostapd emulates one hostapd ctrl socket: answers OK to
// ATTACH/PING/commands, records what it received, and can push events.
// unixgram has no Accept — datagrams carry the sender address, so the
// fake replies WriteToUnix to whoever last sent it a command.
type fakeHostapd struct {
	t        *testing.T
	path     string
	ln       *net.UnixConn
	mu       sync.Mutex
	received []string
	clients  []*net.UnixAddr // sender addresses, newest last
	events   []string        // unsolicited lines to push
}

func newFakeHostapd(t *testing.T, dir, bss string) *fakeHostapd {
	t.Helper()
	path := filepath.Join(dir, bss)
	// hostapd binds a filesystem node — do the same.
	ln, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatalf("fake hostapd bind %s: %v", path, err)
	}
	f := &fakeHostapd{t: t, path: path, ln: ln}
	t.Cleanup(func() {
		ln.Close()
		os.Remove(path)
	})
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := ln.ReadFromUnix(buf)
			if err != nil {
				return
			}
			cmd := string(buf[:n])
			f.mu.Lock()
			f.received = append(f.received, cmd)
			if from != nil {
				f.clients = append(f.clients, from)
			}
			push := f.events
			f.events = nil
			f.mu.Unlock()
			// hostapd answers PING with PONG, everything else OK/FAIL.
			var reply string
			switch {
			case cmd == "PING":
				reply = "PONG"
			case strings.HasPrefix(cmd, "FAILME"):
				reply = "FAIL " + cmd
			case strings.HasPrefix(cmd, "STATUS"):
				reply = "ssid=Kafe-Staff\nchannel=36\nfreq=5180\nnum_sta[1]=3\nbss[1]=wlan0"
			default:
				reply = "OK\n"
			}
			if from != nil {
				ln.WriteToUnix([]byte(reply), from)
				for _, ev := range push {
					ln.WriteToUnix([]byte(ev+"\n"), from)
				}
			}
		}
	}()
	return f
}

func (f *fakeHostapd) pushEvents(lines ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, lines...)
	for _, c := range f.clients {
		for _, l := range lines {
			f.ln.WriteToUnix([]byte(l+"\n"), c)
		}
	}
}

func (f *fakeHostapd) got(prefix string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.received {
		if strings.HasPrefix(r, prefix) {
			return true
		}
	}
	return false
}

func newTestClient(t *testing.T, dir string) *Client {
	t.Helper()
	c := NewClient(dir, []string{"wlan0", "wlan0_1"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	c.PingEvery = 50 * time.Millisecond
	return c
}

func TestClientAttachAndCommands(t *testing.T) {
	dir := t.TempDir()
	f1 := newFakeHostapd(t, dir, "wlan0")
	_ = f1
	f2 := newFakeHostapd(t, dir, "wlan0_1")
	_ = f2

	c := newTestClient(t, dir)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	runErr := make(chan error, 1)
	go func() { runErr <- c.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-runErr:
		case <-time.After(2 * time.Second):
			t.Error("Run did not return")
		}
	})

	// Wait for both sockets to register.
	deadline := time.Now().Add(2 * time.Second)
	for !(f1.got("ATTACH") && f2.got("ATTACH")) {
		if time.Now().After(deadline) {
			t.Fatal("ATTACH never reached both fake sockets")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Commands land on the right BSS socket. MAC goes through the
	// client's canonicalisation to lower-case (same rule as state.db).
	if err := c.Deauthenticate("wlan0", "AA:BB:CC:DD:21:01"); err != nil {
		t.Fatalf("Deauthenticate: %v", err)
	}
	if err := c.Disassociate("wlan0_1", "aa:bb:cc:dd:21:02"); err != nil {
		t.Fatalf("Disassociate: %v", err)
	}
	if !f1.got("DEAUTHENTICATE aa:bb:cc:dd:21:01") {
		t.Error("DEAUTHENTICATE missing on wlan0")
	}
	if !f2.got("DISASSOCIATE aa:bb:cc:dd:21:02") {
		t.Error("DISASSOCIATE missing on wlan0_1")
	}

	// STATUS parses the fake's key=value reply.
	st, err := c.Status("wlan0")
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.SSID != "Kafe-Staff" || st.Channel != 36 || st.Frequency != 5180 || st.NumSta != 3 {
		t.Errorf("status = %+v", st)
	}

	// Keepalive: PINGs must arrive without any trigger from us.
	deadline = time.Now().Add(2 * time.Second)
	for !f1.got("PING") {
		if time.Now().After(deadline) {
			t.Fatal("no PING observed")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Close sends DETACH (best-effort) and closes sockets.
	_ = c.Close()
}

func TestClientEventStream(t *testing.T) {
	dir := t.TempDir()
	f1 := newFakeHostapd(t, dir, "wlan0")
	_ = f1

	c := newTestClient(t, dir)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = c.Run(ctx) }()

	deadline := time.Now().Add(2 * time.Second)
	for !f1.got("ATTACH") {
		if time.Now().After(deadline) {
			t.Fatal("no ATTACH")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Push a connect + disconnect event from the fake AP.
	f1.pushEvents(
		"AP-STA-CONNECTED aa:bb:cc:dd:21:0a",
		"AP-STA-DISCONNECTED aa:bb:cc:dd:21:0a",
	)

	want := []Event{
		{Kind: StaConnected, BSS: "wlan0", MAC: "aa:bb:cc:dd:21:0a"},
		{Kind: StaDisconnected, BSS: "wlan0", MAC: "aa:bb:cc:dd:21:0a"},
	}
	for _, w := range want {
		select {
		case got := <-c.Events():
			if got != w {
				t.Fatalf("event = %+v, want %+v", got, w)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for event")
		}
	}
}

func TestClientReattachesAfterHostapdRestart(t *testing.T) {
	dir := t.TempDir()
	f1 := newFakeHostapd(t, dir, "wlan0")
	_ = f1

	c := newTestClient(t, dir)
	c.PingEvery = 30 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = c.Run(ctx) }()

	deadline := time.Now().Add(2 * time.Second)
	for !f1.got("ATTACH") {
		if time.Now().After(deadline) {
			t.Fatal("no initial ATTACH")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// "Restart": kill the listener (hostapd died) — the client must
	// notice via PING failure and re-dial once the socket is back.
	f1.ln.Close()
	os.Remove(f1.path)
	time.Sleep(100 * time.Millisecond)

	f2 := newFakeHostapd(t, dir, "wlan0") // fresh socket, same path
	deadline = time.Now().Add(3 * time.Second)
	for !f2.got("ATTACH") {
		if time.Now().After(deadline) {
			t.Fatal("client never re-attached after hostapd restart")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestParseEvent(t *testing.T) {
	if ev, ok := parseEvent("wlan0", "AP-STA-CONNECTED AA:BB:CC:DD:21:0B"); !ok ||
		ev.MAC != "aa:bb:cc:dd:21:0b" || ev.Kind != StaConnected || ev.BSS != "wlan0" {
		t.Fatalf("connected parse = %+v %v", ev, ok)
	}
	if ev, ok := parseEvent("wlan0_1", "AP-STA-DISCONNECTED aa:bb:cc:dd:21:0c"); !ok ||
		ev.Kind != StaDisconnected {
		t.Fatalf("disconnected parse = %+v %v", ev, ok)
	}
	if _, ok := parseEvent("wlan0", "PONG"); ok {
		t.Fatal("PONG must not become an event")
	}
	if _, ok := parseEvent("wlan0", "AP-STA-CONNECTED"); ok {
		t.Fatal("event without MAC must be rejected")
	}
}

func TestCommandWithoutSocketFails(t *testing.T) {
	dir := t.TempDir() // no fake hostapd at all
	c := newTestClient(t, dir)
	// Direct send (not via Run) must surface the dial error, not block.
	if err := c.Disassociate("wlan0", "aa:bb:cc:dd:21:0d"); err == nil {
		t.Fatal("command to a missing hostapd must fail")
	}
}

func TestRequestRejectsFailReply(t *testing.T) {
	dir := t.TempDir()
	f := newFakeHostapd(t, dir, "wlan0")
	_ = f
	c := newTestClient(t, dir)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = c.Run(ctx) }()
	deadline := time.Now().Add(2 * time.Second)
	for !f.got("ATTACH") {
		if time.Now().After(deadline) {
			t.Fatal("no ATTACH")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// FAILME gets a "FAIL ..." reply → error, not silent success.
	err := c.send("wlan0", "FAILME test")
	if err == nil || !strings.Contains(err.Error(), "FAIL") {
		t.Fatalf("FAIL reply must surface: %v", err)
	}
}

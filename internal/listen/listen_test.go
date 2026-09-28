// Package-level tests for the two Waiting listeners. They run the real
// servers on 127.0.0.1 with kernel-chosen ports, so no root, no fixed
// ports, no interference between `go test` packages.
package listen_test

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"kotacloud-portal/internal/listen/waitingdns"
	"kotacloud-portal/internal/listen/waitinghttp"
)

// --- waiting-http ---

func TestWaitingHTTPPageAndState(t *testing.T) {
	lookup := func(ip string) waitinghttp.DeviceView {
		if strings.HasSuffix(ip, ".7") { // pretend this client is approved
			return waitinghttp.DeviceView{MAC: "aa:bb:cc:dd:20:01", IP: ip, State: "approved", Approved: true}
		}
		return waitinghttp.DeviceView{IP: ip, State: "waiting"}
	}
	s := waitinghttp.New("127.0.0.1:0", func(ip net.IP) waitinghttp.DeviceView { return lookup(ip.String()) },
		slog.New(slog.NewTextHandler(io.Discard, nil)))

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()

	// Run binds synchronously, so ServeAddr is valid right away.
	deadline := time.Now().Add(2 * time.Second)
	for s.ServeAddr() == "" {
		if time.Now().After(deadline) {
			t.Fatal("listener never bound")
		}
		time.Sleep(5 * time.Millisecond)
	}
	base := "http://" + s.ServeAddr()
	for !dialableTCP(s.ServeAddr()) {
		if time.Now().After(deadline) {
			t.Fatal("listener never became reachable")
		}
		time.Sleep(5 * time.Millisecond)
	}

	t.Run("page renders and shows status", func(t *testing.T) {
		resp, err := http.Get(base + "/")
		if err != nil {
			t.Fatalf("GET /: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 200 {
			t.Fatalf("status = %d", resp.StatusCode)
		}
		if !strings.Contains(string(body), "Menunggu persetujuan") {
			t.Errorf("page missing title:\n%.120s", body)
		}
		if !strings.Contains(string(body), `setTimeout(poll,3000)`) {
			t.Error("page must poll /state every 3 s (design contract)")
		}
	})

	t.Run("state json", func(t *testing.T) {
		resp, err := http.Get(base + "/state")
		if err != nil {
			t.Fatalf("GET /state: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(body), `"state":"waiting"`) {
			t.Errorf("state body = %.120s", body)
		}
	})

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

func dialableTCP(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// --- waiting-dns ---

func newTestDNS(t *testing.T) *waitingdns.Server {
	t.Helper()
	s := waitingdns.New("127.0.0.1:0", "waiting.kcp.internal", "10.20.99.1",
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- s.Run(ctx) }()
	t.Cleanup(func() {
		cancel() // unblocks Run
		select {
		case err := <-runErr:
			if err != nil {
				t.Errorf("dns Run: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("dns Run did not return after cancel")
		}
	})

	// Run binds synchronously; poll ServeAddr until it stops being :0.
	deadline := time.Now().Add(2 * time.Second)
	for s.ServeAddr() == "127.0.0.1:0" || !dialableUDP(s.ServeAddr()) {
		if time.Now().After(deadline) {
			t.Fatal("udp listener never became ready")
		}
		time.Sleep(5 * time.Millisecond)
	}
	return s
}

func dialableUDP(addr string) bool {
	c, err := net.DialTimeout("udp", addr, 100*time.Millisecond)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// buildQuery encodes a minimal DNS query for name/qtype.
func buildQuery(id uint16, name string, qtype uint16) []byte {
	var out []byte
	out = binary.BigEndian.AppendUint16(out, id)
	out = binary.BigEndian.AppendUint16(out, 0x0100) // RD=1
	out = binary.BigEndian.AppendUint16(out, 1)      // qdcount
	out = binary.BigEndian.AppendUint16(out, 0)
	out = binary.BigEndian.AppendUint16(out, 0)
	out = binary.BigEndian.AppendUint16(out, 0)
	for _, label := range strings.Split(name, ".") {
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	out = append(out, 0)
	out = binary.BigEndian.AppendUint16(out, qtype)
	out = binary.BigEndian.AppendUint16(out, 1) // IN
	return out
}

func udpQuery(t *testing.T, addr string, q []byte) []byte {
	t.Helper()
	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	defer c.Close()
	if _, err := c.Write(q); err != nil {
		t.Fatalf("write: %v", err)
	}
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 512)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return buf[:n]
}

func TestWaitingDNSRefusedForEverything(t *testing.T) {
	s := newTestDNS(t)

	for _, tc := range []struct {
		name  string
		qtype uint16
	}{
		{"example.com", 1},           // A
		{"example.com", 28},          // AAAA
		{"example.com", 65},          // HTTPS
		{"waiting.kcp.internal", 28}, // AAAA of our own name: still refused
	} {
		resp := udpQuery(t, s.ServeAddr(), buildQuery(0x1234, tc.name, tc.qtype))
		if len(resp) < 12 {
			t.Fatalf("%s: short response %d bytes", tc.name, len(resp))
		}
		rcode := binary.BigEndian.Uint16(resp[2:4]) & 0x000F
		ancount := binary.BigEndian.Uint16(resp[6:8])
		if rcode != 5 {
			t.Errorf("%s type %d: rcode = %d, want 5 (REFUSED, ERR-01)", tc.name, tc.qtype, rcode)
		}
		if ancount != 0 {
			t.Errorf("%s: answers = %d, want 0", tc.name, ancount)
		}
	}
	if got := s.Stats(); got != 4 {
		t.Errorf("REFUSED counter = %d, want 4", got)
	}
}

func TestWaitingDNSAnswersInfoNameA(t *testing.T) {
	s := newTestDNS(t)

	resp := udpQuery(t, s.ServeAddr(), buildQuery(0x4242, "waiting.kcp.internal", 1))
	if len(resp) < 12+5 {
		t.Fatalf("short response: %d bytes", len(resp))
	}
	rcode := binary.BigEndian.Uint16(resp[2:4]) & 0x000F
	ancount := binary.BigEndian.Uint16(resp[6:8])
	if rcode != 0 {
		t.Fatalf("rcode = %d, want NOERROR", rcode)
	}
	if ancount != 1 {
		t.Fatalf("answers = %d, want 1", ancount)
	}
	// The answer section: pointer to qname (0xC00C), A, IN, TTL, 4-byte IP.
	ans := resp[len(resp)-16:]
	if binary.BigEndian.Uint16(ans[0:2]) != 0xC00C {
		t.Errorf("name pointer = %#x, want 0xC00C", binary.BigEndian.Uint16(ans[0:2]))
	}
	if binary.BigEndian.Uint16(ans[2:4]) != 1 {
		t.Error("answer type != A")
	}
	ip := net.IP(ans[len(ans)-4:]).String()
	if ip != "10.20.99.1" {
		t.Fatalf("A record = %s, want 10.20.99.1", ip)
	}
}

func TestWaitingDNSTCP(t *testing.T) {
	s := newTestDNS(t)
	conn, err := net.Dial("tcp", s.ServeAddr())
	if err != nil {
		t.Fatalf("dial tcp: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))

	q := buildQuery(0x0007, "example.com", 1)
	frame := make([]byte, 2+len(q))
	binary.BigEndian.PutUint16(frame, uint16(len(q)))
	copy(frame[2:], q)
	if _, err := conn.Write(frame); err != nil {
		t.Fatalf("write: %v", err)
	}
	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		t.Fatalf("read len: %v", err)
	}
	n := int(binary.BigEndian.Uint16(lenBuf[:]))
	resp := make([]byte, n)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("read body: %v", err)
	}
	rcode := binary.BigEndian.Uint16(resp[2:4]) & 0x000F
	if rcode != 5 {
		t.Fatalf("tcp rcode = %d, want REFUSED", rcode)
	}
}

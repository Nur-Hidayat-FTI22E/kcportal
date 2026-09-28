// Package hostapdctl implements IF-05a: a native Go client for
// hostapd's per-BSS ctrl sockets (/run/hostapd/<iface>, UNIX
// SOCK_DGRAM) — no hostapd_cli, no shelling out. The Bouncer consumes
// the AP-STA-CONNECTED/DISCONNECTED event stream (Staff Wi-Fi is a
// detection source, §4.6) and the reconciler issues
// DISASSOCIATE/DEAUTHENTICATE on revoke (§4.6 effect ordering).
//
// Session protocol (per socket): ATTACH to receive unsolicited events,
// periodic PING to detect a dead or restarted hostapd, re-ATTACH when a
// PING fails — a hostapd restart drops our registration but keeps the
// socket file.
package hostapdctl

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"
)

// EventKind mirrors the IF-05a contract.
type EventKind int

const (
	StaConnected EventKind = iota + 1
	StaDisconnected
)

// Event is one hostapd station transition.
type Event struct {
	Kind EventKind
	BSS  string
	MAC  string
}

// Status is the parsed `STATUS` response (FR-WIF-009, /metrics).
type Status struct {
	BSS       string
	SSID      string
	Channel   int
	Frequency int // MHz
	NumSta    int
}

// Ctl is the IF-05a contract.
type Ctl interface {
	Events() <-chan Event
	Disassociate(bss, mac string) error
	Deauthenticate(bss, mac string) error
	Status(bss string) (Status, error)
	Close() error
}

// Client implements Ctl across the given BSS socket paths.
type Client struct {
	SocketDir string // /run/hostapd; socket file = dir + "/" + bss
	BSSList   []string
	Log       *slog.Logger
	// PingEvery is the keepalive cadence (design: periodic PING).
	PingEvery time.Duration

	mu       sync.Mutex
	socks    map[string]*net.UnixConn
	waiters  map[string]chan string // per-BSS reply routing (single reader invariant)
	events   chan Event
	closed   bool
	attached map[string]bool
}

// NewClient builds a client over the listed BSS names.
func NewClient(socketDir string, bssList []string, log *slog.Logger) *Client {
	if log == nil {
		log = slog.Default()
	}
	return &Client{
		SocketDir: socketDir,
		BSSList:   bssList,
		Log:       log,
		PingEvery: 5 * time.Second,
		socks:     make(map[string]*net.UnixConn),
		waiters:   make(map[string]chan string),
		events:    make(chan Event, 32),
		attached:  make(map[string]bool),
	}
}

// Events implements Ctl. The channel is shared across all BSS sockets
// and carries each event's BSS.
func (c *Client) Events() <-chan Event { return c.events }

// dial opens one datagram socket for bss and registers with hostapd.
// Our side binds an abstract-namespace address so replies/events have a
// return path; hostapd addresses us via the cookie in our ATTACH ACK.
// unixgram "connect" = net.DialUnix with a remote address.
func (c *Client) dial(bss string) (*net.UnixConn, error) {
	path := c.socketPath(bss)
	local := fmt.Sprintf("@kcportald-hapd-%s-%d", bss, time.Now().UnixNano())
	remote := &net.UnixAddr{Name: path, Net: "unixgram"}
	ours, err := net.DialUnix("unixgram", &net.UnixAddr{Name: local, Net: "unixgram"}, remote)
	if err != nil {
		return nil, fmt.Errorf("hostapdctl: connect %s: %w", path, err)
	}
	// ATTACH registers us for unsolicited events. Inline read: the
	// readEvents pump for this socket is not running yet (maintain calls
	// dial before starting it), so requestInline is the single reader.
	if err := requestInline(ours, "ATTACH"); err != nil {
		ours.Close()
		return nil, fmt.Errorf("hostapdctl: ATTACH %s: %w", bss, err)
	}
	return ours, nil
}

func (c *Client) socketPath(bss string) string {
	if c.SocketDir == "" {
		return "/run/hostapd/" + bss
	}
	return c.SocketDir + "/" + bss
}

// requestInline sends a command and reads the reply directly on the
// socket. Only valid when NO other goroutine is reading this socket —
// i.e. during dial/ATTACH, before maintain's readEvents pump starts.
func requestInline(conn *net.UnixConn, cmd string) error {
	if _, err := conn.Write([]byte(cmd)); err != nil {
		return err
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	conn.SetReadDeadline(time.Time{})
	if err != nil {
		return err
	}
	reply := strings.TrimRight(string(buf[:n]), "\n")
	if reply != "OK" && reply != "PONG" {
		return fmt.Errorf("hostapd replied %q to %s", reply, cmd)
	}
	return nil
}

// requestViaPump sends a command while readEvents is pumping the
// socket: the reply is routed back through the waiter channel by the
// pump's single reader. Returns the raw reply (STATUS needs the
// multi-line body). hostapd replies "OK" to commands, "PONG" to PING.
func (c *Client) requestViaPump(bss, cmd string, conn *net.UnixConn) (string, error) {
	pending := make(chan string, 1)
	c.mu.Lock()
	c.waiters[bss] = pending
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.waiters, bss)
		c.mu.Unlock()
	}()
	if _, err := conn.Write([]byte(cmd)); err != nil {
		return "", err
	}
	select {
	case reply := <-pending:
		return reply, nil
	case <-time.After(2 * time.Second):
		return "", fmt.Errorf("hostapdctl: %s: no reply to %s within 2s", bss, cmd)
	}
}

// request routes a command via the pump when readEvents owns the
// socket; reply semantics: OK passes, anything else fails (PONG is
// filtered out by the pump before routing — it is a keepalive echo,
// never a command reply).
func (c *Client) request(bss string, conn *net.UnixConn, cmd string) error {
	reply, err := c.requestViaPump(bss, cmd, conn)
	if err != nil {
		return err
	}
	if reply != "OK" {
		return fmt.Errorf("hostapd replied %q to %s", reply, cmd)
	}
	return nil
}

// Run manages all sockets: connect, read events, keepalive PING,
// re-dial on failure. It is the supervisor task shape.
func (c *Client) Run(ctx context.Context) error {
	for _, bss := range c.BSSList {
		b := bss
		go func() { c.maintain(ctx, b) }()
	}
	<-ctx.Done()
	return c.Close()
}

// maintain owns one BSS socket for the process lifetime: dial, read
// events, ping, re-attach on failure.
func (c *Client) maintain(ctx context.Context, bss string) {
	for {
		if ctx.Err() != nil {
			return
		}
		conn, err := c.dial(bss)
		if err != nil {
			c.Log.Warn("hostapd socket unavailable, retrying", "bss", bss, "err", err)
			sleepCtx(ctx, time.Second)
			continue
		}
		c.mu.Lock()
		c.socks[bss] = conn
		c.attached[bss] = true
		c.mu.Unlock()
		c.Log.Info("hostapd attached", "bss", bss)

		c.readEvents(ctx, bss, conn)

		c.mu.Lock()
		delete(c.socks, bss)
		c.mu.Unlock()
		// Socket died: loop and re-attach (hostapd restart scenario).
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
}

// readEvents consumes the socket until it errors: it forwards AP-STA-*
// events, routes command replies to waiting requests, and runs the PING
// keepalive. The keepalive is fire-and-forget on purpose: this loop owns
// the socket as its ONLY reader, so a PING must never block waiting for
// its PONG (hostapd v2.10 answers promptly — but a blocking request
// here would wait for a reply nobody reads: self-deadlock, observed on
// the Pi as an ATTACH/PING-timeout cycle every few seconds). A PONG is
// just data the loop consumes; liveness is judged by data actually
// arriving — a write error (ECONNREFUSED once the peer is gone) or a
// stretch of several intervals with zero datagrams triggers re-attach.
func (c *Client) readEvents(ctx context.Context, bss string, conn *net.UnixConn) {
	buf := make([]byte, 512)
	ping := time.NewTicker(c.pingEvery())
	defer ping.Stop()
	window := c.pingEvery() // read deadline; PONG normally lands in ms
	var lastData time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-ping.C:
			if _, err := conn.Write([]byte("PING")); err != nil {
				c.Log.Warn("hostapd keepalive write failed — will re-attach", "bss", bss, "err", err)
				return
			}
		default:
		}
		conn.SetReadDeadline(time.Now().Add(window))
		n, err := conn.Read(buf)
		if err != nil {
			if isTimeout(err) {
				if !lastData.IsZero() && time.Since(lastData) > 3*c.pingEvery() {
					c.Log.Warn("hostapd silent — re-attach", "bss", bss, "quiet_for", time.Since(lastData).String())
					return
				}
				continue
			}
			return // socket dead → maintain() re-dials
		}
		lastData = time.Now()
		line := strings.TrimRight(string(buf[:n]), "\n")
		if line == "PONG" {
			continue // keepalive echo: never a command reply, never an event
		}
		// A datagram is either a command reply (routed to the waiting
		// request) or an unsolicited event.
		c.mu.Lock()
		waiter, had := c.waiters[bss]
		if had {
			delete(c.waiters, bss)
		}
		c.mu.Unlock()
		if had {
			select {
			case waiter <- line:
			default:
			}
			continue
		}
		if ev, ok := parseEvent(bss, line); ok {
			select {
			case c.events <- ev:
			default:
				c.Log.Warn("event backlog full, dropping", "bss", bss)
			}
		}
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func (c *Client) pingEvery() time.Duration {
	if c.PingEvery <= 0 {
		return 5 * time.Second
	}
	return c.PingEvery
}

// parseEvent decodes the two unsolicited messages the Bouncer needs.
func parseEvent(bss, line string) (Event, bool) {
	line = strings.TrimRight(line, "\n")
	// hostapd ctrl: "AP-STA-CONNECTED aa:bb:cc:dd:ee:ff" (plus params).
	for _, kind := range []struct {
		prefix string
		k      EventKind
	}{
		{"AP-STA-CONNECTED", StaConnected},
		{"AP-STA-DISCONNECTED", StaDisconnected},
	} {
		if strings.HasPrefix(line, kind.prefix) {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				return Event{Kind: kind.k, BSS: bss, MAC: strings.ToLower(fields[1])}, true
			}
		}
	}
	return Event{}, false
}

// send issues a per-BSS command. If the maintain goroutine currently
// holds the socket, it routes the reply; if not (hostapd down), dial a
// fresh socket and handle the reply inline — but never both readers at
// once: dial+request here happens only when maintain has no socket.
func (c *Client) send(bss, cmd string) error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return fmt.Errorf("hostapdctl: %s: client closed", bss)
	}
	conn, ok := c.socks[bss]
	_, waiting := c.waiters[bss]
	c.mu.Unlock()
	if !ok && !waiting {
		// No active session: dial, ATTACH, send inline.
		var err error
		conn, err = c.dial(bss) // dial registers a waiter for ATTACH itself
		if err != nil {
			return fmt.Errorf("hostapdctl: %s unavailable: %w", bss, err)
		}
		c.mu.Lock()
		c.socks[bss] = conn
		c.mu.Unlock()
	} else if waiting {
		return fmt.Errorf("hostapdctl: %s: another request in flight", bss)
	}
	if err := c.request(bss, conn, cmd); err != nil {
		return fmt.Errorf("hostapdctl: %s: %w", bss, err)
	}
	return nil
}

// Disassociate implements Ctl: polite "leave" (client can rejoin).
func (c *Client) Disassociate(bss, mac string) error {
	return c.send(bss, "DISASSOCIATE "+strings.ToLower(mac))
}

// Deauthenticate implements Ctl: hard kick (client must re-auth).
func (c *Client) Deauthenticate(bss, mac string) error {
	return c.send(bss, "DEAUTHENTICATE "+strings.ToLower(mac))
}

// Status implements Ctl: parse the `key=value` STATUS reply (FR-WIF-009).
// The reply is routed through the same pending channel as other
// commands (single reader invariant) — multi-line data rides it fine.
func (c *Client) Status(bss string) (Status, error) {
	c.mu.Lock()
	conn, ok := c.socks[bss]
	c.mu.Unlock()
	if !ok {
		return Status{}, fmt.Errorf("hostapdctl: %s not attached", bss)
	}
	pending := make(chan string, 1)
	c.mu.Lock()
	c.waiters[bss] = pending
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.waiters, bss)
		c.mu.Unlock()
	}()
	if _, err := conn.Write([]byte("STATUS")); err != nil {
		return Status{}, err
	}
	var reply string
	select {
	case reply = <-pending:
	case <-time.After(2 * time.Second):
		return Status{}, fmt.Errorf("hostapdctl: %s: STATUS timed out", bss)
	}
	st := Status{BSS: bss}
	for _, line := range strings.Split(reply, "\n") {
		k, v, found := strings.Cut(strings.TrimSpace(line), "=")
		if !found {
			continue
		}
		switch k {
		case "ssid":
			st.SSID = v
		case "channel":
			st.Channel = parseInt(v)
		case "freq":
			st.Frequency = parseInt(v)
		case "num_sta[1]", "num_sta":
			st.NumSta = parseInt(v)
		}
	}
	return st, nil
}

func parseInt(v string) int {
	n := 0
	for _, r := range v {
		if r < '0' || r > '9' {
			break
		}
		n = n*10 + int(r-'0')
	}
	return n
}

// Close releases every socket.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	for bss, conn := range c.socks {
		// Best-effort DETACH so hostapd stops buffering events for us.
		_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
		_, _ = conn.Write([]byte("DETACH"))
		_ = conn.Close()
		delete(c.socks, bss)
	}
	return nil
}

func sleepCtx(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}

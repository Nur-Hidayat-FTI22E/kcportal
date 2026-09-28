// Package netlink is the rtnetlink neighbor watcher for DD-03: it speaks
// NETLINK_ROUTE directly (no `ip` subprocess, no new module deps —
// golang.org/x/sys/unix already carries every constant we need). It
// replaces the `ip neigh` dump inside netctl.Real with a kernel socket:
// a one-shot Dump for the neighbors.Provider seam, and a Subscribe
// stream of RTM_NEWNEIGH updates (RTNLGRP_NEIGH multicast group) for the
// near-instant revision bump the Bouncer's ≤2 s detection budget wants.
//
// Scope discipline: parse exactly what the kernel sends for the neighbor
// table and nothing else. Messages we do not understand are skipped;
// malformed rows never fail the whole dump.
//
// Privileges: reading the tables needs CAP_NET_ADMIN on the Pi. Opening
// the netlink socket itself does not. Where the capability is missing
// (dev sandboxes, non-root tests) construction still succeeds and the
// first Dump reports the EPERM — netctl.Real keeps its `ip neigh`
// ExecRunner path as the documented fallback.
package netlink

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Neigh is one kernel neighbor-table row (DD-03's live view).
type Neigh struct {
	IP    netip.Addr
	MAC   string // canonical lowercase (net.HardwareAddr.String)
	Iface string // interface NAME (resolved from the link table)
	State uint16 // NUD_* constant (unix.NUD_REACHABLE, ...)
	Seen  time.Time
}

// Failed reports whether the entry is a kernel resolution attempt rather
// than a usable binding (NUD_NONE/INCOMPLETE/FAILED — no lladdr).
func (n Neigh) Failed() bool {
	switch n.State {
	case unix.NUD_NONE, unix.NUD_INCOMPLETE, unix.NUD_FAILED:
		return true
	}
	return false
}

// Client is a rtnetlink client. The zero value is usable (2 s timeout).
type Client struct {
	// Timeout bounds a single Dump round trip (the Bouncer's ≤2 s budget
	// shape).
	Timeout time.Duration
}

// New builds a Client with the package defaults.
func New() *Client { return &Client{Timeout: 2 * time.Second} }

func (c *Client) timeout() time.Duration {
	if c.Timeout <= 0 {
		return 2 * time.Second
	}
	return c.Timeout
}

// Dump performs RTM_GETNEIGH with NLM_F_DUMP and returns every usable
// entry the kernel currently holds. Netlink delivers ifindexes only, so
// the cost of name resolution is one RTM_GETLINK dump per call — the
// neighbors cache and the Bouncer logs both want `br-guest`, not `4`.
func (c *Client) Dump() ([]Neigh, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout())
	defer cancel()

	links, err := c.linkNames()
	if err != nil {
		return nil, fmt.Errorf("netlink: link dump: %w", err)
	}
	rows, err := c.dumpNeigh(ctx)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	for i := range rows {
		if name, ok := links[rows[i].Iface]; ok {
			rows[i].Iface = name
		}
		if rows[i].Seen.IsZero() {
			rows[i].Seen = now
		}
	}
	return rows, nil
}

// Subscribe joins RTNLGRP_NEIGH and streams RTM_NEWNEIGH updates on the
// returned channel until ctx is done or the caller runs the returned
// stop func. This is the near-instant path: no polling round trip at
// all. Updates the kernel sends without an lladdr (resolution probes)
// are not forwarded. The channel is bounded; under a storm the oldest
// read wins and drops are acceptable — the next Dump resynchronizes.
func (c *Client) Subscribe(ctx context.Context) (<-chan Neigh, func(), error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, nil, err
	}
	sa := &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: unix.RTNLGRP_NEIGH}
	if err := unix.Bind(fd, sa); err != nil {
		unix.Close(fd)
		return nil, nil, fmt.Errorf("netlink: bind RTNLGRP_NEIGH: %w", err)
	}

	stop := make(chan struct{})
	var once sync.Once
	cancelFn := func() { once.Do(func() { close(stop); unix.Close(fd) }) }
	ch := make(chan Neigh, 32)

	go func() {
		defer close(ch)
		defer cancelFn()

		tv := unix.NsecToTimeval(int64(time.Second))
		_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)

		links := make(map[string]string) // ifindex (decimal) -> name
		var linksMu sync.Mutex
		resolve := func(idx string) string {
			linksMu.Lock()
			name, ok := links[idx]
			linksMu.Unlock()
			if ok {
				return name
			}
			t, err := c.linkNames()
			if err != nil {
				return idx // unresolved: report the number, never stall
			}
			linksMu.Lock()
			links = t
			name, ok = links[idx]
			linksMu.Unlock()
			if !ok {
				return idx
			}
			return name
		}

		buf := make([]byte, 1<<16)
		for {
			n, _, err := unix.Recvfrom(fd, buf, 0)
			select {
			case <-ctx.Done():
				return
			case <-stop:
				return
			default:
			}
			if err != nil {
				if errors.Is(err, syscall.EINTR) || errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
					continue // recv timeout tick: re-check ctx/stop
				}
				return // socket gone; the Dump path still works
			}
			walkNeighMsgs(buf[:n], func(msg []byte) {
				ne, err := parseNeighMsg(msg)
				if err != nil || ne.Failed() {
					return
				}
				ne.Iface = resolve(ne.Iface)
				ne.Seen = time.Now()
				select {
				case ch <- ne:
				default: // subscriber slow: drop, Dump resynchronizes
				}
			})
		}
	}()
	return ch, cancelFn, nil
}

// --- one-shot dumps ---

// linkNames returns the ifindex (decimal string) → name table via an
// RTM_GETLINK dump.
func (c *Client) linkNames() (map[string]string, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}
	// Header + ifinfomsg{Family: AF_UNSPEC} request payload (16 bytes).
	// NLM_F_REQUEST is mandatory — without it the kernel silently drops
	// the request and the dump times out.
	req := newRequest(unix.RTM_GETLINK, unix.NLM_F_REQUEST|unix.NLM_F_DUMP, make([]byte, unix.SizeofIfInfomsg))
	if err := netlinkSend(fd, req); err != nil {
		return nil, err
	}
	out := make(map[string]string, 8)
	err = c.receive(fd, func(payload []byte, msgType uint16) bool {
		if msgType != unix.RTM_NEWLINK || len(payload) < unix.SizeofIfInfomsg {
			return true
		}
		idx := int32(native.Uint32(payload[4:8])) // ifinfomsg.ifi_index
		attrs, err := parseAttrs(payload[unix.SizeofIfInfomsg:])
		if err != nil {
			return true
		}
		if name, ok := attrs[unix.IFLA_IFNAME]; ok {
			out[fmt.Sprint(idx)] = nullTerm(name)
		}
		return true
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// dumpNeigh performs the RTM_GETNEIGH dump; ifindexes stay encoded as
// their decimal string in Iface until Dump resolves them.
func (c *Client) dumpNeigh(ctx context.Context) ([]Neigh, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}
	// Header + ndmsg{Family: AF_UNSPEC} request payload (12 bytes).
	req := newRequest(unix.RTM_GETNEIGH, unix.NLM_F_REQUEST|unix.NLM_F_DUMP, make([]byte, 12))
	if err := netlinkSend(fd, req); err != nil {
		return nil, err
	}
	var rows []Neigh
	err = c.receive(fd, func(payload []byte, msgType uint16) bool {
		if msgType != unix.RTM_NEWNEIGH {
			return true
		}
		if ctx.Err() != nil {
			return false
		}
		n, err := parseNeighMsg(payload)
		if err != nil || n.Failed() {
			return true // skip probes/malformed rows; never fail the dump
		}
		rows = append(rows, n)
		return true
	})
	if err != nil {
		return nil, err
	}
	return rows, nil
}

// --- wire format ---

// nativeEndian is the host byte order (netlink uses it for headers).
var native binary.ByteOrder = func() binary.ByteOrder {
	var x uint32 = 0x01020304
	if (*[4]byte)(unsafe.Pointer(&x))[0] == 1 {
		return binary.BigEndian
	}
	return binary.LittleEndian
}()

const nlMsgHdrLen = 16

// newRequest builds header + payload for one dump request.
func newRequest(msgType, flags uint16, payload []byte) []byte {
	b := make([]byte, nlMsgHdrLen+len(payload))
	native.PutUint32(b[0:4], uint32(len(b))) // nlmsg_len
	native.PutUint16(b[4:6], msgType)
	native.PutUint16(b[6:8], flags)
	native.PutUint32(b[8:12], 1) // seq (one request per socket)
	native.PutUint32(b[12:16], 0)
	copy(b[nlMsgHdrLen:], payload)
	return b
}

func netlinkSend(fd int, req []byte) error {
	return unix.Sendto(fd, req, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK})
}

// receive drains response messages until NLMSG_DONE (dump end) or the
// callback returns false. Each datagram may carry several netlink
// messages; a truncated/garbled one aborts with an error.
func (c *Client) receive(fd int, fn func(payload []byte, msgType uint16) bool) error {
	deadline := time.Now().Add(c.timeout())
	buf := make([]byte, 1<<16)
	for {
		tv := unix.NsecToTimeval(int64(time.Until(deadline)))
		_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
				return fmt.Errorf("netlink: reply timeout")
			}
			return err
		}
		b := buf[:n]
		for len(b) >= nlMsgHdrLen {
			msgLen := int(native.Uint32(b[0:4]))
			msgType := native.Uint16(b[4:6])
			if msgLen < nlMsgHdrLen || msgLen > len(b) {
				return fmt.Errorf("netlink: truncated message (len=%d, have=%d)", msgLen, len(b))
			}
			payload := b[nlMsgHdrLen:msgLen]
			switch msgType {
			case unix.NLMSG_DONE:
				return nil
			case unix.NLMSG_ERROR:
				if len(payload) >= 4 {
					if e := int32(native.Uint32(payload[0:4])); e != 0 {
						return syscall.Errno(-e)
					}
				}
				return nil // ACK
			default:
				if !fn(payload, msgType) {
					return nil
				}
			}
			b = b[align4(msgLen):]
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("netlink: reply timeout")
		}
	}
}

// walkNeighMsgs extracts RTM_NEWNEIGH payloads from one datagram; used
// by the Subscribe loop where errors are silently dropped.
func walkNeighMsgs(b []byte, fn func(payload []byte)) {
	for len(b) >= nlMsgHdrLen {
		msgLen := int(native.Uint32(b[0:4]))
		msgType := native.Uint16(b[4:6])
		if msgLen < nlMsgHdrLen || msgLen > len(b) {
			return
		}
		if msgType == unix.RTM_NEWNEIGH {
			fn(b[nlMsgHdrLen:msgLen])
		}
		if msgType == unix.NLMSG_DONE {
			return
		}
		b = b[align4(msgLen):]
	}
}

func align4(n int) int { return (n + 3) &^ 3 }

// nullTerm trims a trailing NUL from a string attribute (IFLA_IFNAME).
func nullTerm(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// parseNeighMsg decodes one RTM_NEWNEIGH payload: struct ndmsg (12
// bytes: family u8, pad x3, ifindex s32, state u16, flags u8, type u8),
// then rtattrs (NDA_DST, NDA_LLADDR). Ifindex is kept as its decimal
// string — Dump/Subscribe resolve names afterward.
func parseNeighMsg(b []byte) (Neigh, error) {
	const ndmsgLen = 12
	if len(b) < ndmsgLen {
		return Neigh{}, fmt.Errorf("netlink: ndmsg too short: %d", len(b))
	}
	n := Neigh{
		Iface: fmt.Sprint(int32(native.Uint32(b[4:8]))),
		State: native.Uint16(b[8:10]),
	}
	attrs, err := parseAttrs(b[ndmsgLen:])
	if err != nil {
		return Neigh{}, err
	}
	dst, ok := attrs[unix.NDA_DST]
	if !ok {
		return Neigh{}, fmt.Errorf("netlink: neighbor without NDA_DST")
	}
	ip, ok := netip.AddrFromSlice(dst)
	if !ok {
		return Neigh{}, fmt.Errorf("netlink: bad NDA_DST len %d", len(dst))
	}
	n.IP = ip.Unmap()
	ll, ok := attrs[unix.NDA_LLADDR]
	if !ok {
		return Neigh{}, fmt.Errorf("netlink: neighbor %s without NDA_LLADDR", n.IP)
	}
	// NDA_LLADDR carries RAW link-layer bytes (6 for Ethernet/Wi-Fi, 20
	// for infiniband) — not text. HardwareAddr.String() renders the
	// canonical lowercase form the rest of the codebase uses.
	if len(ll) != 6 && len(ll) != 20 {
		return Neigh{}, fmt.Errorf("netlink: neighbor %s: unsupported lladdr len %d", n.IP, len(ll))
	}
	n.MAC = net.HardwareAddr(ll).String()
	return n, nil
}

// parseAttrs walks the rtattr stream: { u16 rta_len; u16 rta_type; data }.
func parseAttrs(b []byte) (map[uint16][]byte, error) {
	out := make(map[uint16][]byte, 4)
	for len(b) >= 4 {
		l := int(native.Uint16(b[0:2]))
		if l < 4 || l > len(b) {
			return nil, fmt.Errorf("netlink: bad rtattr len %d", l)
		}
		out[native.Uint16(b[2:4])] = b[4:l]
		b = b[align4(l):]
	}
	return out, nil
}

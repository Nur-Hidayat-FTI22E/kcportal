package netlink

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// appendAttr builds one rtattr { u16 len; u16 type; data; padding }.
func appendAttr(b []byte, typ uint16, data []byte) []byte {
	l := 4 + len(data)
	hdr := make([]byte, 4)
	native.PutUint16(hdr[0:2], uint16(l))
	native.PutUint16(hdr[2:4], typ)
	b = append(b, hdr...)
	b = append(b, data...)
	for pad := align4(l) - l; pad > 0; pad-- {
		b = append(b, 0)
	}
	return b
}

// buildNeighMsg crafts an RTM_NEWNEIGH payload the way the kernel does.
func buildNeighMsg(ifindex int32, state uint16, ip []byte, mac []byte) []byte {
	b := make([]byte, 0, 12+4+16+4+8)
	b = append(b, 0, 0, 0, 0) // family AF_UNSPEC + 3 pad
	var u32 [4]byte
	native.PutUint32(u32[:], uint32(ifindex))
	b = append(b, u32[:]...)
	var u16 [2]byte
	native.PutUint16(u16[:], state)
	b = append(b, u16[:]...)
	b = append(b, 0, 0) // flags, type
	b = appendAttr(b, unix.NDA_DST, ip)
	if mac != nil {
		b = appendAttr(b, unix.NDA_LLADDR, mac)
	}
	return b
}

func TestParseNeighMsgIPv4(t *testing.T) {
	ip := []byte{10, 20, 3, 44}
	mac, _ := macBytes("AA:BB:CC:DD:EE:FF")
	msg := buildNeighMsg(4, unix.NUD_REACHABLE, ip, mac)

	n, err := parseNeighMsg(msg)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := n.IP.String(); got != "10.20.3.44" {
		t.Errorf("IP = %s, want 10.20.3.44", got)
	}
	if n.MAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("MAC = %s, want canonical lowercase", n.MAC)
	}
	if n.Iface != "4" {
		t.Errorf("Iface = %s, want \"4\" (ifindex until resolved)", n.Iface)
	}
	if n.State != unix.NUD_REACHABLE {
		t.Errorf("State = %d, want NUD_REACHABLE", n.State)
	}
	if n.Failed() {
		t.Error("NUD_REACHABLE must not be Failed()")
	}
}

func TestParseNeighMsgIPv6(t *testing.T) {
	ip := make([]byte, 16)
	ip[15] = 9
	mac, _ := macBytes("11:22:33:44:55:66")
	n, err := parseNeighMsg(buildNeighMsg(3, unix.NUD_STALE, ip, mac))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := n.IP.String(); got != "::9" {
		t.Errorf("IP = %s, want ::9", got)
	}
}

func TestParseNeighMsgFailedStates(t *testing.T) {
	mac, _ := macBytes("11:22:33:44:55:66")
	for _, st := range []uint16{unix.NUD_NONE, unix.NUD_INCOMPLETE, unix.NUD_FAILED} {
		n, err := parseNeighMsg(buildNeighMsg(1, st, []byte{10, 0, 0, 1}, mac))
		if err != nil {
			t.Fatalf("state %d: parse: %v", st, err)
		}
		if !n.Failed() {
			t.Errorf("state %d: Failed() = false, want true", st)
		}
	}
}

func TestParseNeighMsgErrors(t *testing.T) {
	mac, _ := macBytes("11:22:33:44:55:66")
	if _, err := parseNeighMsg([]byte{0, 0, 0, 0}); err == nil {
		t.Error("short ndmsg: want error")
	}
	// No NDA_DST.
	if _, err := parseNeighMsg(appendAttr(make([]byte, 12), unix.NDA_LLADDR, mac)); err == nil {
		t.Error("missing NDA_DST: want error")
	}
	// No NDA_LLADDR.
	if _, err := parseNeighMsg(appendAttr(make([]byte, 12), unix.NDA_DST, []byte{10, 0, 0, 1})); err == nil {
		t.Error("missing NDA_LLADDR: want error")
	}
	// Bad NDA_LLADDR length.
	if _, err := parseNeighMsg(buildNeighMsg(1, unix.NUD_REACHABLE, []byte{10, 0, 0, 1}, []byte{1, 2, 3})); err == nil {
		t.Error("3-byte lladdr: want error")
	}
	// Bad NDA_DST length.
	if _, err := parseNeighMsg(buildNeighMsg(1, unix.NUD_REACHABLE, []byte{10, 0, 0}, mac)); err == nil {
		t.Error("3-byte dst: want error")
	}
}

func TestParseAttrsBadLengths(t *testing.T) {
	// rta_len = 3 (< 4) inside an otherwise long buffer.
	bad := []byte{3, 0, 0, 0, 9, 9, 9, 9}
	if _, err := parseAttrs(bad); err == nil {
		t.Error("rta_len 3: want error")
	}
	// rta_len beyond the buffer.
	if _, err := parseAttrs([]byte{0xff, 0xff, 0, 0}); err == nil {
		t.Error("rta_len 65535: want error")
	}
	// Short tail (< 4 bytes) is just ignored, not an error.
	if _, err := parseAttrs([]byte{1, 2}); err != nil {
		t.Errorf("2-byte tail: want nil error, got %v", err)
	}
}

func TestNullTermAndAlign(t *testing.T) {
	if got := nullTerm([]byte("br-lan\x00")); got != "br-lan" {
		t.Errorf("nullTerm = %q", got)
	}
	if got := nullTerm([]byte("br-lan")); got != "br-lan" {
		t.Errorf("nullTerm no-NUL = %q", got)
	}
	for in, want := range map[int]int{1: 4, 4: 4, 5: 8, 12: 12, 13: 16} {
		if got := align4(in); got != want {
			t.Errorf("align4(%d) = %d, want %d", in, got, want)
		}
	}
}

func TestNewRequest(t *testing.T) {
	payload := make([]byte, 12)
	req := newRequest(unix.RTM_GETNEIGH, unix.NLM_F_DUMP, payload)
	if len(req) != nlMsgHdrLen+12 {
		t.Fatalf("request len = %d, want %d", len(req), nlMsgHdrLen+12)
	}
	if got := int(native.Uint32(req[0:4])); got != len(req) {
		t.Errorf("nlmsg_len = %d, want %d", got, len(req))
	}
	if got := native.Uint16(req[4:6]); got != unix.RTM_GETNEIGH {
		t.Errorf("type = %d", got)
	}
	if got := native.Uint16(req[6:8]); got != unix.NLM_F_DUMP {
		t.Errorf("flags = %d", got)
	}
	if got := native.Uint32(req[8:12]); got != 1 {
		t.Errorf("seq = %d", got)
	}
}

// TestReceiveAgainstUserNetlinkPeer exercises receive()'s message walk —
// DONE, ERROR, multi-message datagrams, truncation — using a second
// userspace netlink socket as the "kernel". The pair runs over
// NETLINK_USERSOCK because the kernel refuses userspace-to-userspace
// sends on NETLINK_ROUTE; receive() only parses bytes, so the framing
// logic under test is protocol-independent.
func TestReceiveAgainstUserNetlinkPeer(t *testing.T) {
	rx, tx, cleanup := netlinkPair(t)
	defer cleanup()

	mac, _ := macBytes("aa:bb:cc:dd:ee:ff")
	neigh := buildNeighMsg(4, unix.NUD_REACHABLE, []byte{10, 20, 3, 44}, mac)

	// One datagram: valid NEWNEIGH, garbage-typed (skipped), then DONE.
	done := make([]byte, nlMsgHdrLen)
	native.PutUint32(done[0:4], nlMsgHdrLen)
	native.PutUint16(done[4:6], unix.NLMSG_DONE)
	dgram := append(frame(unix.RTM_NEWNEIGH, neigh), frame(0xFFFE, []byte{1, 2, 3, 4})...)
	dgram = append(dgram, done...)
	if err := unix.Sendto(tx, dgram, 0, rxAddr(t, rx)); err != nil {
		t.Fatalf("send: %v", err)
	}

	// receive() hands every non-DONE/non-ERROR message to the callback;
	// filtering by type is the caller's job (dumpNeigh, linkNames).
	var types []uint16
	err := new(Client).receive(rx, func(p []byte, typ uint16) bool {
		types = append(types, typ)
		return true
	})
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	if len(types) != 2 || types[0] != unix.RTM_NEWNEIGH || types[1] != 0xFFFE {
		t.Fatalf("types = %v, want [RTM_NEWNEIGH 0xFFFE] (multi-message datagram, DONE ends)", types)
	}

	// NLMSG_ERROR with a negative errno surfaces as syscall.Errno.
	eno := make([]byte, 4)
	eperm := -int32(unix.EPERM) // errno field is host-order int32
	binary.LittleEndian.PutUint32(eno[0:4], uint32(eperm))
	errFrame := frame(unix.NLMSG_ERROR, eno)
	if err := unix.Sendto(tx, errFrame, 0, rxAddr(t, rx)); err != nil {
		t.Fatalf("send errno: %v", err)
	}
	err = new(Client).receive(rx, func([]byte, uint16) bool { return true })
	if !errors.Is(err, syscall.EPERM) {
		t.Fatalf("NLMSG_ERROR: want EPERM, got %v", err)
	}

	// Truncated header length aborts with an error, not a panic.
	bad := frame(unix.RTM_NEWNEIGH, neigh)
	native.PutUint32(bad[0:4], 0xFFFF) // len beyond datagram
	if err := unix.Sendto(tx, bad, 0, rxAddr(t, rx)); err != nil {
		t.Fatalf("send bad: %v", err)
	}
	err = new(Client).receive(rx, func([]byte, uint16) bool { return true })
	if err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("truncated msg: want error, got %v", err)
	}
}

// frame wraps a payload in a netlink header of the given type.
func frame(typ uint16, payload []byte) []byte {
	b := make([]byte, nlMsgHdrLen+len(payload))
	native.PutUint32(b[0:4], uint32(len(b)))
	native.PutUint16(b[4:6], typ)
	native.PutUint16(b[6:8], 2) // NLM_F_MULTI shape
	native.PutUint32(b[8:12], 7)
	copy(b[nlMsgHdrLen:], payload)
	return b
}

func netlinkPair(t *testing.T) (rx, tx int, cleanup func()) {
	t.Helper()
	rx, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_USERSOCK)
	if err != nil {
		t.Skipf("netlink sockets unavailable: %v", err)
	}
	tx, err = unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_USERSOCK)
	if err != nil {
		unix.Close(rx)
		t.Skipf("netlink sockets unavailable: %v", err)
	}
	if err := unix.Bind(rx, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		unix.Close(rx)
		unix.Close(tx)
		t.Skipf("bind: %v", err)
	}
	return rx, tx, func() { unix.Close(rx); unix.Close(tx) }
}

func rxAddr(t *testing.T, fd int) *unix.SockaddrNetlink {
	t.Helper()
	sa, err := unix.Getsockname(fd)
	if err != nil {
		t.Fatalf("getsockname: %v", err)
	}
	nl, ok := sa.(*unix.SockaddrNetlink)
	if !ok {
		t.Fatalf("getsockname: not a netlink addr")
	}
	return &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Pid: nl.Pid}
}

func macBytes(s string) ([]byte, error) {
	var b []byte
	for _, part := range strings.Split(s, ":") {
		var v int
		if _, err := fmt.Sscanf(part, "%02x", &v); err != nil {
			return nil, fmt.Errorf("bad mac %q: %w", s, err)
		}
		b = append(b, byte(v))
	}
	if len(b) != 6 {
		return nil, fmt.Errorf("bad mac %q", s)
	}
	return b, nil
}

// TestDumpSmoke runs a real RTM_GETNEIGH dump. Environments without
// CAP_NET_ADMIN (CI, sandboxes) fail the reply with EPERM — skip there;
// a Pi must not skip.
func TestDumpSmoke(t *testing.T) {
	rows, err := New().Dump()
	if err != nil {
		if errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.EPERM) {
			t.Skipf("no CAP_NET_ADMIN here: %v", err)
		}
		t.Fatalf("dump: %v", err)
	}
	for _, r := range rows {
		if r.MAC == "" || !r.IP.IsValid() {
			t.Errorf("row %v failed sanity: %+v", r.IP, r)
		}
	}
	t.Logf("kernel neighbor rows: %d", len(rows))
}

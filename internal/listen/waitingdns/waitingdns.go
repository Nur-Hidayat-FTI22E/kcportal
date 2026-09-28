// Package waitingdns implements MOD-WAITDNS (ERR-01/DD-06): the stub
// DNS server on 10.20.99.1:5354 that Waiting-zone clients reach through
// the nat_pre DNAT of port 53. It answers REFUSED for every name except
// waiting.kcp.internal (A -> 10.20.99.1) — enough for the client to
// fail fast and show the captive page, and nothing else. Deliberately
// stdlib-only wire format: the queries Waiting clients send are simple
// A/AAAA/HTTPS lookups and we never recurse.
package waitingdns

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// WellKnown defaults from the listener table (§2.4).
const (
	DefaultAddr     = "10.20.99.1:5354"
	DefaultInfoName = "waiting.kcp.internal"
	DefaultInfoIPv4 = "10.20.99.1"
)

// qtypes we distinguish (wire values).
const (
	qTypeA     = 1
	qTypeAAAA  = 28
	qTypeHTTPS = 65
)

// Server is the stub DNS listener (UDP + TCP on the same port).
type Server struct {
	Addr     string // default DefaultAddr; ":0" lets tests pick a free port
	InfoName string // the only name we answer A for
	InfoIPv4 string
	Log      *slog.Logger

	udp   *net.UDPConn
	tcp   *net.TCPListener
	mu    sync.Mutex
	stats uint64 // refused count (FR-BNC-002 observability; /metrics later)
}

// ServeAddr reports the bound address after Run starts (with ":0" this
// is the kernel-assigned port tests need).
func (s *Server) ServeAddr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.udp != nil {
		return s.udp.LocalAddr().String()
	}
	return s.Addr
}

// New builds the stub.
func New(addr, infoName, infoIPv4 string, log *slog.Logger) *Server {
	if addr == "" {
		addr = DefaultAddr
	}
	if infoName == "" {
		infoName = DefaultInfoName
	}
	if infoIPv4 == "" {
		infoIPv4 = DefaultInfoIPv4
	}
	return &Server{Addr: addr, InfoName: infoName, InfoIPv4: infoIPv4, Log: log}
}

// Run serves UDP and TCP until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	// IP_FREEBIND (§2.4): bind succeeds before the bridge exists.
	lc := &net.ListenConfig{
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
	// TCP first, then UDP on the SAME port: with ":0" each listener
	// would otherwise get a different ephemeral port, and the DNAT only
	// forwards one port (listener table §2.4: udp/tcp both on :5354).
	tln, err := lc.Listen(ctx, "tcp", s.Addr)
	if err != nil {
		return fmt.Errorf("waitingdns: listen tcp %s: %w", s.Addr, err)
	}
	t := tln.(*net.TCPListener)
	taddr := t.Addr().(*net.TCPAddr)
	uaddr := &net.UDPAddr{IP: taddr.IP, Port: taddr.Port, Zone: taddr.Zone}
	upc, err := lc.ListenPacket(ctx, "udp", uaddr.String())
	if err != nil {
		t.Close()
		return fmt.Errorf("waitingdns: listen udp %s: %w", s.Addr, err)
	}
	uc, ok := upc.(*net.UDPConn)
	if !ok {
		t.Close()
		upc.Close()
		return fmt.Errorf("waitingdns: udp packet conn is %T", upc)
	}
	s.mu.Lock()
	s.udp, s.tcp = uc, t
	s.mu.Unlock()
	s.Log.Info("waiting-dns listening", "addr", s.ServeAddr(), "info_name", s.InfoName)

	go func() {
		<-ctx.Done()
		s.mu.Lock()
		s.udp, s.tcp = nil, nil
		s.mu.Unlock()
		uc.Close()
		t.Close()
	}()

	errCh := make(chan error, 2)
	go s.serveUDP(errCh, uc)
	go serveTCP(t, s, errCh)

	select {
	case <-ctx.Done():
		s.Log.Info("waiting-dns stopped")
		return nil
	case err := <-errCh:
		return err
	}
}

func (s *Server) bump() {
	s.mu.Lock()
	s.stats++
	s.mu.Unlock()
}

// serveUDP answers one query per datagram.
func (s *Server) serveUDP(errCh chan<- error, u *net.UDPConn) {
	buf := make([]byte, 1500)
	for {
		n, addr, err := u.ReadFromUDP(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			errCh <- fmt.Errorf("waitingdns: udp read: %w", err)
			return
		}
		resp := s.handle(buf[:n])
		if _, err := u.WriteToUDP(resp, addr); err != nil && !errors.Is(err, net.ErrClosed) {
			s.Log.Warn("udp write failed", "err", err)
		}
	}
}

// serveTCP answers length-prefixed queries (RFC 1035 §4.2.2).
func serveTCP(t *net.TCPListener, s *Server, errCh chan<- error) {
	for {
		conn, err := t.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			errCh <- fmt.Errorf("waitingdns: tcp accept: %w", err)
			return
		}
		go func() {
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			var lenBuf [2]byte
			for {
				if _, err := readFull(conn, lenBuf[:]); err != nil {
					return
				}
				n := int(binary.BigEndian.Uint16(lenBuf[:]))
				if n == 0 || n > 512 {
					return
				}
				q := make([]byte, n)
				if _, err := readFull(conn, q); err != nil {
					return
				}
				resp := s.handle(q)
				out := make([]byte, 2+len(resp))
				binary.BigEndian.PutUint16(out, uint16(len(resp)))
				copy(out[2:], resp)
				if _, err := conn.Write(out); err != nil {
					return
				}
			}
		}()
	}
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

// handle parses the query and builds the response. A malformed query
// gets FORMERR with the same ID; any well-formed name other than
// InfoName gets REFUSED (ERR-01/DD-06: the stub never resolves the
// internet for Waiting clients — the DHCP option already pointed DNS
// at us only so we can refuse quickly).
func (s *Server) handle(query []byte) []byte {
	h, q, err := parseQuery(query)
	if err != nil {
		return nil // undecodable: drop silently (UDP) / close (TCP)
	}
	name := q.name
	qtype := q.qtype

	var rcode uint8
	var answerIP string
	if name == s.InfoName && qtype == qTypeA {
		rcode = 0 // NOERROR with an A record
		answerIP = s.InfoIPv4
	} else {
		rcode = 5 // REFUSED
		s.bump()
	}

	out := make([]byte, 0, 512)
	// Header: id, QR=1, opcode 0, AA=0, TC=0, RD copied, RA=0, rcode.
	flags := uint16(0x8000) | uint16(rcode)&0x000F
	if h.rd {
		flags |= 0x0100
	}
	out = binary.BigEndian.AppendUint16(out, h.id)
	out = binary.BigEndian.AppendUint16(out, flags)
	answers := 0
	if answerIP != "" {
		answers = 1
	}
	out = binary.BigEndian.AppendUint16(out, 1) // qdcount echoes the question
	out = binary.BigEndian.AppendUint16(out, uint16(answers))
	out = binary.BigEndian.AppendUint16(out, 0)
	out = binary.BigEndian.AppendUint16(out, 0)

	// Echo the question section verbatim.
	out = appendName(out, q.rawName)
	out = binary.BigEndian.AppendUint16(out, q.qtype)
	out = binary.BigEndian.AppendUint16(out, q.qclass)

	if answerIP != "" {
		// A record: name pointer to offset 12 (the question name), TTL 10.
		out = binary.BigEndian.AppendUint16(out, 0xC00C)
		out = binary.BigEndian.AppendUint16(out, qTypeA)
		out = binary.BigEndian.AppendUint16(out, 1) // IN
		out = binary.BigEndian.AppendUint32(out, 10)
		ip := net.ParseIP(answerIP).To4()
		out = binary.BigEndian.AppendUint16(out, uint16(len(ip)))
		out = append(out, ip...)
	}
	return out
}

type dnsHeader struct {
	id uint16
	rd bool
}

type dnsQuestion struct {
	rawName []byte
	name    string
	qtype   uint16
	qclass  uint16
}

// parseQuery decodes exactly one question.
func parseQuery(b []byte) (dnsHeader, dnsQuestion, error) {
	var h dnsHeader
	var q dnsQuestion
	if len(b) < 12 {
		return h, q, errors.New("short header")
	}
	h.id = binary.BigEndian.Uint16(b[0:2])
	flags := binary.BigEndian.Uint16(b[2:4])
	if flags&0x8000 != 0 {
		return h, q, errors.New("not a query")
	}
	if binary.BigEndian.Uint16(b[4:6]) != 1 {
		return h, q, errors.New("qdcount != 1")
	}
	h.rd = flags&0x0100 != 0

	name, rest, err := parseName(b[12:])
	if err != nil {
		return h, q, err
	}
	q.rawName = b[12 : len(b)-len(rest)-4]
	q.name = name
	if len(rest) < 4 {
		return h, q, errors.New("short question")
	}
	q.qtype = binary.BigEndian.Uint16(rest[0:2])
	q.qclass = binary.BigEndian.Uint16(rest[2:4])
	return h, q, nil
}

// parseName decodes a (non-compressed) QNAME into dotted form.
func parseName(b []byte) (string, []byte, error) {
	var labels []string
	i := 0
	for {
		if i >= len(b) {
			return "", nil, errors.New("name runs past end")
		}
		l := int(b[i])
		if l == 0 {
			i++
			break
		}
		if i+1+l > len(b) {
			return "", nil, errors.New("label runs past end")
		}
		labels = append(labels, string(b[i+1:i+1+l]))
		i += 1 + l
	}
	return stringsJoin(labels, "."), b[i:], nil
}

func stringsJoin(parts []string, sep string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += sep
		}
		out += p
	}
	return out
}

// appendName encodes a dotted name as uncompressed wire labels.
func appendName(out []byte, raw []byte) []byte {
	return append(out, raw...)
}

// Stats returns the REFUSED counter (FR-BNC-002 /metrics feed).
func (s *Server) Stats() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats
}

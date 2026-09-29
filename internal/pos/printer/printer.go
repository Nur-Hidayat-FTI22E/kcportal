// Package printer renders ESC/POS receipts (58 mm, FR-POS-007) and
// ships them to a USB character device (/dev/usb/lp*) or a raw-tcp
// 9100 port — the two IF-03 modes. Rendering is pure and testable;
// the drivers only move bytes.
package printer

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"kotacloud-portal/internal/pos/store"
)

// Driver moves a rendered receipt to the hardware.
type Driver interface {
	Write(p []byte) error
	Close() error
}

// USBDriver writes to a character device (kernel lp driver owns the
// protocol; udev uaccess grants the container user the open).
type USBDriver struct{ Path string }

func (d USBDriver) Write(p []byte) error {
	f, err := os.OpenFile(d.Path, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("printer: open %s: %w", d.Path, err)
	}
	defer f.Close()
	// The lp device takes one write per job; a short write is retried
	// by the kernel driver.
	if _, err := f.Write(p); err != nil {
		return fmt.Errorf("printer: write %s: %w", d.Path, err)
	}
	return nil
}

func (d USBDriver) Close() error { return nil }

// TCPDriver speaks raw jetdirect/9100 (bytes in = page out).
type TCPDriver struct{ Addr string }

func (d TCPDriver) Write(p []byte) error {
	c, err := net.DialTimeout("tcp", d.Addr, 3*time.Second)
	if err != nil {
		return fmt.Errorf("printer: dial %s: %w", d.Addr, err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write(p); err != nil {
		return fmt.Errorf("printer: write %s: %w", d.Addr, err)
	}
	return nil
}

func (d TCPDriver) Close() error { return nil }

// FromEnv picks the driver from IF-03 env (POS_PRINTER=usb|tcp,
// POS_PRINTER_ADDR). Returns nil when unconfigured — the worker then
// leaves jobs queued instead of failing them.
func FromEnv(mode, addr string) Driver {
	switch mode {
	case "usb":
		p := addr
		if p == "" {
			p = "/dev/usb/lp0"
		}
		return USBDriver{Path: p}
	case "tcp":
		if addr == "" {
			return nil
		}
		return TCPDriver{Addr: addr}
	}
	return nil
}

// esc/pos control bytes
const (
	escInit  = "\x1b@"         // initialize
	escCut   = "\x1dV\x41\x32" // partial cut
	escAlign = "\x1ba\x01"     // center
	escLeft  = "\x1ba\x00"
	escBig   = "\x1b!\x30" // double size
	escNorm  = "\x1b!\x00"
)

// Render58 turns a receipt into ESC/POS bytes for a 58 mm head
// (32 columns). Non-ASCII (product names) folds to '?': ESC/POS
// codepage selection is a printer-firmware minefield, and a '?' beats
// mojibake — the UI already limits names to ASCII in practice.
func Render58(r store.ReceiptData) []byte {
	var b strings.Builder
	b.WriteString(escInit)
	b.WriteString(escAlign + escBig + "KOTACLOUD\n" + escNorm + escLeft)
	b.WriteString(fmt.Sprintf("Struk : %s\n", r.OrderNo))
	b.WriteString(fmt.Sprintf("Waktu : %s\n", r.ClosedAt.Format("02-01-2006 15:04")))
	b.WriteString(strings.Repeat("-", 32) + "\n")
	for _, l := range r.Lines {
		name := foldASCII(l.Name)
		line := fmt.Sprintf("%s", name)
		right := fmt.Sprintf("%dx%d %d", l.Qty, l.Unit, l.Qty*l.Unit)
		pad := 32 - len([]rune(line)) - len(right)
		if pad < 1 {
			line = line[:max(1, 32-len(right)-1)]
			pad = 1
		}
		b.WriteString(line + strings.Repeat(" ", pad) + right + "\n")
	}
	b.WriteString(strings.Repeat("-", 32) + "\n")
	writeRight(&b, "TOTAL", r.Total)
	if r.Method == "cash" {
		writeRight(&b, "TUNAI", r.Tendered)
		writeRight(&b, "KEMBALI", r.Change)
	} else {
		b.WriteString(fmt.Sprintf("Metode: %s\n", strings.ToUpper(r.Method)))
	}
	b.WriteString("\n  Terima kasih!\n\n\n")
	b.WriteString(escCut)
	return []byte(b.String())
}

func writeRight(b *strings.Builder, label string, v int64) {
	right := fmt.Sprintf("%d", v)
	pad := 32 - len(label) - 1 - len(right)
	if pad < 1 {
		pad = 1
	}
	b.WriteString(label + strings.Repeat(" ", pad) + right + "\n")
}

func foldASCII(s string) string {
	r := strings.Map(func(r rune) rune {
		if r < 32 || r > 126 {
			return '?'
		}
		return r
	}, s)
	if len(r) > 24 {
		r = r[:24]
	}
	return r
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// Worker drains print_jobs: pop → render → write → mark. On failure
// the job stays queued with attempts+1; the worker backs off and keeps
// the venue selling even when the printer is out of paper. A nil
// driver (unconfigured printer) parks the worker silently. log is
// slog.Info-style: msg first, then key-value pairs.
func Worker(db *store.DB, drv Driver, log func(msg string, args ...any)) func(stop <-chan struct{}) {
	return func(stop <-chan struct{}) {
		if drv == nil {
			<-stop
			return
		}
		for {
			select {
			case <-stop:
				return
			default:
			}
			jobID, orderID, err := db.NextQueuedReceipt()
			if err != nil {
				log("printer: pop job failed", "err", err)
				sleepOr(stop, 5*time.Second)
				continue
			}
			if jobID == 0 {
				sleepOr(stop, 2*time.Second)
				continue
			}
			r, err := db.Receipt(orderID)
			if err != nil {
				log("printer: read receipt failed", "order", orderID, "err", err)
				sleepOr(stop, 5*time.Second)
				continue
			}
			if err := drv.Write(Render58(r)); err != nil {
				_ = db.MarkPrintFailed(jobID, err.Error())
				log("printer: write failed", "job", jobID, "err", err)
				sleepOr(stop, 10*time.Second) // paper out / cable — back off
				continue
			}
			if err := db.MarkPrinted(jobID); err != nil {
				log("printer: mark printed failed", "job", jobID, "err", err)
			}
		}
	}
}

func sleepOr(stop <-chan struct{}, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-stop:
	case <-t.C:
	}
}

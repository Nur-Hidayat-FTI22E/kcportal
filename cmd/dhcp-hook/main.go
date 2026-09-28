// dhcp-hook is the tiny helper dnsmasq execs on every lease change
// (dhcp-script=, IF-05b). It forwards the event as one JSON line to
// kcportald's unix socket (/run/kcportal/hook.sock). A compiled binary
// is the production shape (deploy/pi/kcp-tag.sh exists as the no-Go
// fallback for environments without socat/timeout constraints — same
// wire format).
//
// dnsmasq contract: argv = <action> <mac> <ip> <hostname>; env
// DNSMASQ_INTERFACE = source bridge. Never fails dnsmasq's lease path:
// any problem exits 0 — a lost event is only a lost refresh, the next
// lease event or neighbor update resynchronizes.
package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

func main() {
	if len(os.Args) < 4 {
		os.Exit(0) // not a lease action (dnsmasq also calls for tftp events)
	}
	action, mac, ip := os.Args[1], os.Args[2], os.Args[3]
	hostname := ""
	if len(os.Args) > 4 {
		hostname = os.Args[4]
	}
	switch action {
	case "add", "old", "del":
	default:
		os.Exit(0)
	}
	sock := os.Getenv("KCPORTAL_HOOK_SOCK")
	if sock == "" {
		sock = "/run/kcportal/hook.sock"
	}

	ev := map[string]string{
		"action":    action,
		"mac":       strings.ToLower(mac), // canonical at the boundary
		"ip":        ip,
		"hostname":  hostname,
		"interface": os.Getenv("DNSMASQ_INTERFACE"),
	}
	line, err := json.Marshal(ev)
	if err != nil {
		os.Exit(0)
	}

	c, err := net.Dial("unix", sock)
	if err != nil {
		os.Exit(0) // daemon down: lease bookkeeping retries on next event
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	fmt.Fprintf(c, "%s\n", line)
}

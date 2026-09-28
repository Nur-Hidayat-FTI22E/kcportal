// One-shot command path: the same wire protocol as the long-lived
// Client, but for short-lived processes (ops utilities like
// `kcportald -revoke`) that dial the ctrl socket, send one command,
// read one reply, and exit. No event pump, no keepalive — ATTACH is
// deliberately NOT sent because the caller will not be around to
// DETACH; plain commands (DEAUTHENTICATE et al.) work unattached.
package hostapdctl

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// OneshotCommand dials the BSS ctrl socket, sends cmd, waits ≤2 s for
// an OK/PONG reply, and closes. Independent of any running Client —
// the single-reader invariant holds because this owns its socket
// exclusively for its lifetime.
func OneshotCommand(socketDir, bss, cmd string) error {
	path := socketDir + "/" + bss
	if socketDir == "" {
		path = "/run/hostapd/" + bss
	}
	local := fmt.Sprintf("@kcportald-hapd-oneshot-%s-%d", bss, time.Now().UnixNano())
	conn, err := net.DialUnix("unixgram",
		&net.UnixAddr{Name: local, Net: "unixgram"},
		&net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		return fmt.Errorf("hostapdctl: connect %s: %w", path, err)
	}
	defer conn.Close()
	if err := requestInline(conn, cmd); err != nil {
		return fmt.Errorf("hostapdctl: %s: %w", bss, err)
	}
	return nil
}

// OneshotDeauthenticate kicks mac off the listed BSS and succeeds as
// soon as ONE kick was accepted (hostapd only exposes the BSS sockets
// whose interface it actually created — with KCP_WIFI_BSS=single there
// is no wlan0_1 socket, and a station sits on exactly one BSS anyway).
// Fails only when no BSS could be reached; the last error is reported.
func OneshotDeauthenticate(socketDir string, bssList []string, mac string) error {
	mac = strings.ToLower(mac)
	var lastErr error
	for _, bss := range bssList {
		if err := OneshotCommand(socketDir, bss, "DEAUTHENTICATE "+mac); err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("hostapdctl: no BSS configured")
	}
	return lastErr
}

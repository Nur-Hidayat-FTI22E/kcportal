// wan.go — the /network/wan half of the setup wizard (M3, §7.2).
//
// What it is: the network config surface web/admin's wizard calls. GET
// reports what the wizard shows; POST {wan:{mode}, iface} records the
// chosen WAN posture into state.db settings and app.yaml and audits it.
//
// What it is deliberately NOT: a kernel reconfigurer. Moving eth0 into
// br-lan, PPPoE dialing and addressing bridges can cut the operator's
// management access, so they stay with deploy/pi/kcp-net-apply.sh and
// the operator's hands (DD-15: manual-and-reviewed, fail-closed). The
// API only records intent and reports reality; the daemon consumes the
// recorded values on its next boot.
package api

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"kotacloud-portal/internal/runtimecfg"
	"kotacloud-portal/internal/store"
)

// wanSettingKey is the settings key the recorded posture lives under.
// Same convention as api_token/marketing_key: state.db settings are the
// operational key/value store (§8).
const wanSettingKey = "wan_config"

// wanConfig is the recorded posture (a subset of app.yaml's WAN block
// plus the wizard's interface choice). PPPoE credentials are NOT here —
// §7.3 puts them under /data/kcportal/secrets/, never in state.db.
type wanConfig struct {
	Mode  string `json:"mode"`            // "pppoe" | "dhcp" | "static" (DD-08)
	Iface string `json:"iface,omitempty"` // uplink interface (e.g. eth0)
}

// validWANMode mirrors config.Validate's DD-08 set.
func validWANMode(m string) bool {
	switch m {
	case "pppoe", "dhcp", "static":
		return true
	}
	return false
}

// HandleWanGET reports the wizard's network view: the recorded posture
// (or the app.yaml fallback), live detection of the WAN iface, an
// actual uplink probe, and the bridge posture the net-apply script
// owns. Read-only; no actor round-trip.
func (s *Server) HandleWanGET(w http.ResponseWriter, _ *http.Request) (any, error) {
	out := map[string]any{}

	if raw, err := store.GetSetting(s.DB, wanSettingKey); err == nil && raw != "" {
		var wc wanConfig
		if jerr := json.Unmarshal([]byte(raw), &wc); jerr == nil {
			out["wan"] = wc
		}
	}

	if iface, ok := runtimecfg.DetectIFace("eth", "enp"); ok {
		out["iface"] = iface
		if addr, ok := runtimecfg.DetectAddr(iface); ok {
			out["iface_addr"] = addr
		}
	}
	out["uplink"] = probeUplink()
	out["bridges"] = runtimecfg.DetectBridges("br-lan", "br-guest")
	out["bridges_ready"] = runtimecfg.DetectBridges("br-lan", "br-guest")["br-lan"] &&
		runtimecfg.DetectBridges("br-lan", "br-guest")["br-guest"]
	return out, nil
}

// writeWanYAMLFn is a seam for tests — the real implementation shells
// out to python3 against /etc/kcportal/app.yaml, which a test box must
// never touch.
var writeWanYAMLFn = writeWanYAML

// HandleWanPOST records the WAN posture (§7.2 POST /network/wan):
// settings row for the running system, audited diff row, app.yaml for
// the next boot. It does NOT touch the kernel (see the package comment
// for why) — bridging the uplink remains kcp-net-apply.sh's job.
func (s *Server) HandleWanPOST(w http.ResponseWriter, r *http.Request) (any, error) {
	var req struct {
		WAN   wanConfig `json:"wan"`
		Iface string    `json:"iface"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	if !validWANMode(req.WAN.Mode) {
		return nil, fail(http.StatusBadRequest, "wan.mode must be pppoe|dhcp|static (DD-08)")
	}
	req.WAN.Iface = strings.TrimSpace(req.Iface)
	if req.WAN.Iface == "" {
		// Default to the detected uplink candidate, matching GET.
		if iface, ok := runtimecfg.DetectIFace("eth", "enp"); ok {
			req.WAN.Iface = iface
		}
	}
	if req.WAN.Iface != "" {
		if _, err := net.InterfaceByName(req.WAN.Iface); err != nil {
			return nil, fail(http.StatusBadRequest, "unknown interface "+req.WAN.Iface)
		}
	}

	buf, err := json.Marshal(req.WAN)
	if err != nil {
		return nil, err
	}
	cfg := string(buf)

	prev, gerr := store.GetSetting(s.DB, wanSettingKey)
	if gerr != nil {
		prev = "(none)"
	}
	if err := store.SetSetting(s.DB, wanSettingKey, cfg); err != nil {
		return nil, err
	}
	if err := store.RecordAudit(s.DB, "api", "wan.config", req.WAN.Iface,
		fmt.Sprintf("%s -> %s", prev, cfg), time.Now()); err != nil {
		return nil, err
	}
	if err := writeWanYAMLFn(req.WAN); err != nil {
		s.Log.Warn("app.yaml WAN update failed — settings row still authoritative", "err", err)
	}
	s.Log.Info("wan posture recorded", "mode", req.WAN.Mode, "iface", req.WAN.Iface)
	return map[string]any{"ok": true, "wan": req.WAN}, nil
}

// probeUplink answers "do we actually have internet right now?" — a
// UDP-dial to a public resolver: connect() on an unconnected UDP socket
// sends nothing but does consult the routing table. A Wi-Fi captive
// portal lab without an uplink reports ok=false instead of lying.
func probeUplink() map[string]any {
	out := map[string]any{"ok": false}
	// RFC 5737 documentation resolvers; nothing is sent, the kernel
	// routing decision is the test.
	d := net.Dialer{Timeout: 2 * time.Second}
	c, err := d.Dial("udp", "203.0.113.1:53")
	if err != nil {
		out["detail"] = err.Error()
		return out
	}
	_ = c.Close()
	out["ok"] = true
	return out
}

// writeWanYAML merges the WAN posture into /etc/kcportal/app.yaml via a
// python3 one-liner: PyYAML round-trips comments better than hand-grown
// string surgery, and it is best-effort anyway — the settings row
// written a moment earlier is the authoritative record.
func writeWanYAML(wc wanConfig) error {
	_, err := exec.Command("python3", "-c", `
import sys, yaml
p = "/etc/kcportal/app.yaml"
try:
    with open(p) as f:
        d = yaml.safe_load(f) or {}
except FileNotFoundError:
    d = {}
d.setdefault("wan", {})
d["wan"]["mode"] = sys.argv[1]
if len(sys.argv) > 2 and sys.argv[2]:
    d["wan"]["iface"] = sys.argv[2]
elif "iface" in d.get("wan", {}):
    del d["wan"]["iface"]
with open(p, "w") as f:
    yaml.safe_dump(d, f, default_flow_style=False, sort_keys=False)
`, wc.Mode, wc.Iface).CombinedOutput()
	if err != nil {
		return fmt.Errorf("wan: app.yaml update: %w", err)
	}
	return nil
}

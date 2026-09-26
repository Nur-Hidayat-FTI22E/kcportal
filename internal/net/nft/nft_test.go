package nft

import (
	"context"
	"errors"
	"flag"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
)

// -update regenerates the golden files; CI never passes it.
var update = flag.Bool("update", false, "rewrite golden files")

func mustIP(s string) netip.Addr { return netip.MustParseAddr(s) }

// cafePlan is the Café MVP plan matching config.Default() (marks §2.4,
// portals §2.4/ERR-01, FR-CPT-004 rate).
func cafePlan() *Plan {
	return &Plan{
		Uplinks:        Uplinks{WAN: []string{"ppp0"}, Tunnels: []string{"wg0"}},
		GuestBridge:    "br-guest",
		LANBridge:      "br-lan",
		GuestPortal:    "10.20.3.1:8080",
		WaitingDNSStub: "10.20.99.1:5354",
		WaitingHTTP:    "10.20.99.1:8081",
		GuestUpKbps:    5000,
		GuestDownKbps:  5000,
		Zones: []Zone{
			{ID: 0, Name: "waiting", Mark: 0x00},
			{ID: 1, Name: "admin", Mark: 0x01, Internet: true},
			{ID: 2, Name: "pos", Mark: 0x02, Internet: true, LANAllow: []LANAllow{
				{DstIP: "10.20.2.20", Proto: "tcp", Port: 9100}, // §4.3 POS -> printer
			}},
			{ID: 3, Name: "guest", Mark: 0x03, Internet: true},
		},
	}
}

func mustRender(t *testing.T, p *Plan) string {
	t.Helper()
	b, err := Render(p)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	return string(b)
}

// --- golden files ---

// TestRenderGolden pins the full output against a golden file. On first
// run (or after updating intentionally with -update) the golden file is
// (re)written; CI runs without -update and diffs. The output must stay
// deterministic — the 30s drift check compares generator hashes.
func TestRenderGolden(t *testing.T) {
	golden := filepath.Join("testdata", "kcp.nft.golden")
	got := mustRender(t, cafePlan())

	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatalf("mkdir testdata: %v", err)
		}
		if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
			t.Fatalf("update golden: %v", err)
		}
		return
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden (run once with -update to create): %v", err)
	}
	if got != string(want) {
		t.Fatalf("rendered ruleset drifted from golden file.\nRun: go test ./internal/net/nft -run TestRenderGolden -update\n--- diff hint: check semantically (comments/blank lines) before regenerating.")
	}
}

func TestRenderGoldenSetupMode(t *testing.T) {
	p := cafePlan()
	p.SetupMode = true
	golden := filepath.Join("testdata", "kcp-setup.nft.golden")
	got := mustRender(t, p)

	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatalf("mkdir testdata: %v", err)
		}
		if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
			t.Fatalf("update golden: %v", err)
		}
		return
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	if got != string(want) {
		t.Fatalf("setup-mode ruleset drifted from golden file (re-run with -update only for intentional changes)")
	}
}

// TestRenderDeterministic: same plan twice -> byte-identical output,
// even with map-iteration-order-sensitive content (element lists are
// precomputed in plan order).
func TestRenderDeterministic(t *testing.T) {
	a := mustRender(t, cafePlan())
	b := mustRender(t, cafePlan())
	if a != b {
		t.Fatal("Render is not deterministic — the drift check would false-positive every 30s")
	}
}

// --- invariants §4.3 demands ---

func TestRenderOmitsEmptyElements(t *testing.T) {
	p := cafePlan()
	p.Uplinks.Tunnels = nil // no VPN configured
	out := mustRender(t, p)

	for _, banned := range []string{"{ }", "{,}", "elements = {  }"} {
		if strings.Contains(out, banned) {
			t.Errorf("output contains nft-invalid %q (§4.3: empty elements must be omitted)", banned)
		}
	}
	// The tunnel set itself must still exist, just without elements.
	if !strings.Contains(out, "set tunnel_if { type ifname; }") {
		t.Error("tunnel_if set missing after dropping its elements")
	}
	if strings.Contains(out, `tunnel_if { type ifname; elements`) {
		t.Error("tunnel_if still carries an elements clause with no tunnels")
	}
}

func TestRenderNoFlushRuleset(t *testing.T) {
	// Strip comment lines first: the header comment *mentions* the banned
	// command; only actual rules may not contain it.
	var rules strings.Builder
	for _, line := range strings.Split(mustRender(t, cafePlan()), "\n") {
		if t := strings.TrimSpace(line); !strings.HasPrefix(t, "#") {
			rules.WriteString(line + "\n")
		}
	}
	out := rules.String()
	if strings.Contains(out, "flush ruleset") {
		t.Fatal("generated ruleset contains `flush ruleset` — forbidden by DD-04 (wipes other software's tables)")
	}
	// DD-04's mechanism: add+delete pairs per table make the install one
	// atomic transaction.
	for _, table := range []string{"kcp_zones", "kcp_portal", "kcp_filter", "kcp_nat", "kcp_l2"} {
		if !strings.Contains(out, "add table "+tableType(table)+" "+table) ||
			!strings.Contains(out, "delete table "+tableType(table)+" "+table) {
			t.Errorf("table %s missing its add/delete replace pair (DD-04 atomicity)", table)
		}
	}
}

func tableType(table string) string {
	if table == "kcp_nat" {
		return "ip"
	}
	if table == "kcp_l2" {
		return "bridge"
	}
	return "inet"
}

func TestRenderLanAllowAndRateLimit(t *testing.T) {
	out := mustRender(t, cafePlan())

	// §4.3's worked example, verbatim semantics.
	if !strings.Contains(out, "meta mark 0x02 ip daddr 10.20.2.20 tcp dport 9100 accept") {
		t.Error("POS->printer lan_allow rule missing or wrong")
	}
	// FR-CPT-004: 5000 kbps = 625 kbytes/s.
	if !strings.Contains(out, "limit rate over 625 kbytes/second") {
		t.Error("guest rate limit missing or wrong (5000 kbps must render 625 kbytes/second)")
	}
}

func TestRenderZeroRateOmitsLimit(t *testing.T) {
	p := cafePlan()
	p.GuestUpKbps = 0
	p.GuestDownKbps = 0
	out := mustRender(t, p)
	if strings.Contains(out, "limit rate over") {
		t.Error("rate limit rendered although both limits are 0")
	}
	if strings.Contains(out, "@g_up") || strings.Contains(out, "@g_down") {
		// the sets are declared but never used as targets
		t.Error("rate-limit sets referenced although limits are 0")
	}
}

func TestRenderSetupModeClassify(t *testing.T) {
	p := cafePlan()
	p.SetupMode = true
	out := mustRender(t, p)

	if !strings.Contains(out, `iifname "br-lan" meta mark set 0x01`) {
		t.Error("setup mode must mark br-lan 0x01 (DD-15)")
	}
	if strings.Contains(out, "ether saddr map @mac_zone") {
		t.Error("setup mode must not consult mac_zone (no state.db yet)")
	}
	if !strings.Contains(out, `iifname "br-guest" meta mark set 0x03`) {
		t.Error("guest classification must survive setup mode so the portal stays reachable")
	}
}

func TestRenderNormalClassify(t *testing.T) {
	out := mustRender(t, cafePlan())
	if !strings.Contains(out, `iifname "br-lan" meta mark set ether saddr map @mac_zone`) {
		t.Error("normal mode classify must map MAC->zone via mac_zone (§4.2 rule 4)")
	}
}

// --- timeout elements ---

func TestTimeoutElemRoundsUp(t *testing.T) {
	now := time.Now()
	expires := now.Add(90 * time.Second)
	elem := timeoutElem(expires, now)
	// §4.3: `timeout 2h expires 1h10m` shape; we render whole seconds.
	if !regexp.MustCompile(`^timeout \d+s expires \d+s$`).MatchString(elem) {
		t.Fatalf("timeout element %q has unexpected shape", elem)
	}
	secs := regexp.MustCompile(`expires (\d+)s`).FindStringSubmatch(elem)
	if secs == nil {
		t.Fatalf("no expires field in %q", elem)
	}
	if strings.HasPrefix(secs[1], "0") || secs[1] == "89" {
		t.Fatalf("expiry %q not rounded up past 90s", elem)
	}
}

func TestRenderSkipsExpiredEntries(t *testing.T) {
	p := cafePlan()
	p.Guests = []Guest{
		{MAC: "aa:bb:cc:dd:ee:01", Expires: time.Now().Add(2 * time.Hour)},
		{MAC: "aa:bb:cc:dd:ee:dead", Expires: time.Now().Add(-time.Minute)}, // expired
	}
	p.Bindings = []Binding{
		{MAC: "aa:bb:cc:dd:ee:01", IP: mustIP("10.20.3.44"), Expires: time.Now().Add(2 * time.Hour)},
		{MAC: "aa:bb:cc:dd:ee:dead", IP: mustIP("10.20.3.45"), Expires: time.Now().Add(-time.Minute)},
		{MAC: "aa:bb:cc:dd:ee:02", IP: mustIP("fd00:20::44"), Expires: time.Now().Add(time.Hour)},
	}
	out := mustRender(t, p)

	if strings.Contains(out, "ee:dead") {
		t.Error("expired entry rendered into the ruleset")
	}
	if !strings.Contains(out, "aa:bb:cc:dd:ee:01 . 10.20.3.44") {
		t.Error("live v4 binding missing from mac_ip4")
	}
	if !strings.Contains(out, "aa:bb:cc:dd:ee:02 . fd00:20::44") {
		t.Error("live v6 binding missing from mac_ip6")
	}
	if !strings.Contains(out, "aa:bb:cc:dd:ee:01 timeout ") {
		t.Error("guest element missing its timeout suffix")
	}
}

// mustIP is used by TestRenderSkipsExpiredEntries; see netip.MustParseAddr.
// --- plan validation ---

func TestPlanValidate(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		if err := cafePlan().Validate(); err != nil {
			t.Fatalf("valid cafe plan rejected: %v", err)
		}
	})
	t.Run("same bridges", func(t *testing.T) {
		p := cafePlan()
		p.GuestBridge = p.LANBridge
		if err := p.Validate(); err == nil {
			t.Fatal("identical guest/lan bridges accepted (DD-01 violation)")
		}
	})
	t.Run("no uplink", func(t *testing.T) {
		p := cafePlan()
		p.Uplinks = Uplinks{}
		if err := p.Validate(); err == nil {
			t.Fatal("plan without any uplink accepted — egress would be unreachable")
		}
	})
	t.Run("duplicate marks", func(t *testing.T) {
		p := cafePlan()
		p.Zones[3].Mark = 0x02
		if err := p.Validate(); err == nil {
			t.Fatal("duplicate zone marks accepted")
		}
	})
	t.Run("bad lan_allow proto", func(t *testing.T) {
		p := cafePlan()
		p.Zones[2].LANAllow[0].Proto = "sctp"
		if err := p.Validate(); err == nil {
			t.Fatal("lan_allow proto \"sctp\" accepted")
		}
	})
	t.Run("bad lan_allow ip", func(t *testing.T) {
		p := cafePlan()
		p.Zones[2].LANAllow[0].DstIP = "not-an-ip"
		if err := p.Validate(); err == nil {
			t.Fatal("lan_allow dst_ip \"not-an-ip\" accepted")
		}
	})
	t.Run("missing bridges", func(t *testing.T) {
		p := cafePlan()
		p.GuestBridge = ""
		if err := p.Validate(); err == nil {
			t.Fatal("plan without GuestBridge accepted")
		}
	})
}

// --- element list helpers ---

func TestEgressIfs(t *testing.T) {
	p := cafePlan()
	if got := p.egressIfs(); !reflect.DeepEqual(got, []string{"ppp0", "wg0"}) {
		t.Fatalf("egressIfs = %v, want [ppp0 wg0]", got)
	}
	p.Uplinks.Tunnels = nil
	if got := p.egressIfs(); !reflect.DeepEqual(got, []string{"ppp0"}) {
		t.Fatalf("egressIfs without tunnels = %v, want [ppp0]", got)
	}
}

func TestInternetAndVpnMarks(t *testing.T) {
	p := cafePlan()
	if got := p.internetMarks(); !reflect.DeepEqual(got, []string{"0x01", "0x02", "0x03"}) {
		t.Fatalf("internetMarks = %v, want [0x01 0x02 0x03]", got)
	}
	if got := p.vpnMarks(); len(got) != 0 {
		t.Fatalf("vpnMarks = %v, want empty (cafe has no VPN-required zones)", got)
	}
	p.Zones[1].VPN = true
	if got := p.vpnMarks(); !reflect.DeepEqual(got, []string{"0x01"}) {
		t.Fatalf("vpnMarks after toggle = %v, want [0x01]", got)
	}
}

// --- applier (fail-closed) ---

// fakeNft writes a shell script that emulates nft's exit codes for the
// flags we use. The script logs its own path plus ".log" — a separate
// file next to it, not inside Applier.Dir, so assertions on "$0.log"
// can't collide with kcp.nft bookkeeping.
func fakeNft(t *testing.T, script string) string {
	t.Helper()
	fakeDir := t.TempDir()
	path := filepath.Join(fakeDir, "nft")
	body := strings.ReplaceAll(script, "$0.log", filepath.Join(fakeDir, "nft.log"))
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil {
		t.Fatalf("write fake nft: %v", err)
	}
	return path
}

func TestApplierHappyPath(t *testing.T) {
	dir := t.TempDir()
	fakeDir := t.TempDir()
	logPath := filepath.Join(fakeDir, "nft.log")
	a := &Applier{
		NftBin: fakeNft(t, `case "$1" in -c) exit 0;; -f) echo installed >> "`+logPath+`"; exit 0;; esac; exit 99`),
		Dir:    dir,
	}
	path, err := a.Apply(context.Background(), []byte(BootRuleset))
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if path != filepath.Join(dir, "kcp.nft") {
		t.Fatalf("Apply returned %q", path)
	}
	if _, err := os.Stat(logPath); err != nil {
		t.Error("nft -f was never invoked")
	}
}

func TestApplierCheckFailureIsFailClosed(t *testing.T) {
	dir := t.TempDir()
	a := &Applier{
		// -c (check) fails: nothing may be installed, error is *CheckError.
		NftBin: fakeNft(t, `if [ "$1" = "-c" ]; then echo "syntax error line 42" >&2; exit 1; fi; exit 0`),
		Dir:    dir,
	}
	_, err := a.Apply(context.Background(), []byte("bogus"))
	var ce *CheckError
	if !errors.As(err, &ce) {
		t.Fatalf("expected *CheckError, got %T: %v", err, err)
	}
	if !strings.Contains(ce.Error(), "config.rejected") {
		t.Errorf("CheckError should mention the config.rejected mapping, got: %v", ce)
	}
	if _, err := os.Stat(filepath.Join(dir, "kcp.nft.log")); err == nil {
		t.Error("nft -f ran although nft -c rejected the ruleset — not fail-closed")
	}
}

func TestApplierInstallFailureReportsRollback(t *testing.T) {
	a := &Applier{
		NftBin: fakeNft(t, `if [ "$1" = "-c" ]; then exit 0; fi; echo "kernel oops" >&2; exit 1`),
		Dir:    t.TempDir(),
	}
	_, err := a.Apply(context.Background(), []byte(BootRuleset))
	if err == nil || errors.As(err, new(*CheckError)) {
		t.Fatalf("install failure must surface as a plain error, got %v", err)
	}
	if !strings.Contains(err.Error(), "rolled the transaction back") {
		t.Errorf("install error should explain kernel rollback semantics, got: %v", err)
	}
}

func TestApplierDryRunSkipsInstall(t *testing.T) {
	a := &Applier{
		NftBin: fakeNft(t, `exit 0`),
		Dir:    t.TempDir(),
		DryRun: true,
	}
	if _, err := a.Apply(context.Background(), []byte(BootRuleset)); err != nil {
		t.Fatalf("Apply dry-run: %v", err)
	}
}

func TestApplyBoot(t *testing.T) {
	dir := t.TempDir()
	a := &Applier{
		NftBin: fakeNft(t, `exit 0`),
		Dir:    dir,
		DryRun: true,
	}
	path, err := a.ApplyBoot(context.Background())
	if err != nil {
		t.Fatalf("ApplyBoot: %v", err)
	}
	if filepath.Base(path) != "kcp-boot.nft" {
		t.Fatalf("boot ruleset path = %q, want kcp-boot.nft", path)
	}
	got, _ := os.ReadFile(path)
	if string(got) != BootRuleset {
		t.Error("kcp-boot.nft on disk differs from the BootRuleset constant")
	}
}

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
		DohShield: DoHShield{
			BootstrapIPs: DefaultDohBootstrapIPs(),
			BlockDoT:     true,
		},
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

// --- DoH/DoT shield ---

// The shield set must carry the default bootstrap IPs and the gate_fwd
// drops must sit BEFORE the authed_guests exception: the venue's DNS
// policy applies to the whole guest session, not only pre-auth.
func TestDohShieldRendersDropsBeforeAuthException(t *testing.T) {
	ruleset := mustRender(t, cafePlan())

	if !strings.Contains(ruleset, `set doh_block4 { type ipv4_addr; elements = { "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220", "94.140.14.14", "94.140.15.15" } }`) {
		t.Fatal("doh_block4 set missing the default bootstrap IPs")
	}
	if strings.Count(ruleset, "tcp dport 853 counter drop") != 1 || strings.Count(ruleset, "udp dport 853 counter drop") != 1 {
		t.Fatal("DoT/DoQ :853 drops missing")
	}

	// Order guard: the shield drops come first.
	doh := strings.Index(ruleset, "ip daddr @doh_block4 counter drop")
	dot := strings.Index(ruleset, "tcp dport 853 counter drop")
	gate := strings.Index(ruleset, "ether saddr != @authed_guests meta l4proto tcp reject")
	if doh == -1 || dot == -1 || gate == -1 {
		t.Fatal("shield lines not found")
	}
	if !(doh < dot && dot < gate) {
		t.Fatal("shield drops must precede the authed_guests exception in gate_fwd")
	}

	// Guest bridge binding only — br-lan traffic must not be touched.
	if !strings.Contains(ruleset, `iifname "br-guest" ip daddr @doh_block4 counter drop`) {
		t.Fatal("shield must be scoped to the guest bridge")
	}
}

// A zero-value shield renders an EMPTY set element clause and no drops:
// opt-out stays a pure plan choice, and the template never emits `{ }`
// (nft-invalid) when the IP list is empty.
func TestDohShieldZeroValueOmitsDrops(t *testing.T) {
	p := cafePlan()
	p.DohShield = DoHShield{} // explicit opt-out
	ruleset := mustRender(t, p)

	if strings.Contains(ruleset, "doh_block4") {
		t.Fatal("empty shield must not render the set at all")
	}
	if strings.Contains(ruleset, "dport 853") {
		t.Fatal("empty shield must not render :853 drops")
	}
}

// --- DD-14 app egress ---

// With AppEgressUID set, output jumps to a default-deny app_egress
// chain: loopback and established pass first, explicit allows next,
// drop last.
func TestAppEgressRendersDenyChain(t *testing.T) {
	p := cafePlan()
	p.AppEgressUID = 1001
	p.AppAllows = []LANAllow{{DstIP: "10.20.2.20", Proto: "tcp", Port: 9100}}
	ruleset := mustRender(t, p)

	if !strings.Contains(ruleset, "meta skuid 1001 jump app_egress") {
		t.Fatal("output chain missing the skuid jump")
	}
	// Order matters only WITHIN the app_egress chain — `counter drop`
	// also appears in earlier chains (gate_in), so scope the search to
	// the chain body.
	chainStart := strings.Index(ruleset, "chain app_egress")
	if chainStart < 0 {
		t.Fatal("app_egress chain missing")
	}
	body := ruleset[chainStart:]
	lo := strings.Index(body, `oifname "lo" return`)
	stab := strings.Index(body, "ct state established,related return")
	allow := strings.Index(body, "ip daddr 10.20.2.20 tcp dport 9100 accept")
	drop := strings.Index(body, "counter drop")
	for i, pos := range []int{lo, stab, allow, drop} {
		if pos < 0 {
			t.Fatalf("app_egress piece %d missing", i)
		}
	}
	if !(lo < stab && stab < allow && allow < drop) {
		t.Fatal("app_egress order wrong: lo+established+allows must precede the drop")
	}
}

// Zero/negative uid renders nothing at all (opt-out; dev boxes).
func TestAppEgressZeroUIDOmitsChain(t *testing.T) {
	p := cafePlan()
	p.AppEgressUID = 0
	p.AppAllows = []LANAllow{{DstIP: "10.20.2.20", Proto: "tcp", Port: 9100}}
	ruleset := mustRender(t, p)
	if strings.Contains(ruleset, "app_egress") || strings.Contains(ruleset, "skuid") {
		t.Fatal("uid 0 must not render the egress chain")
	}

	// Validation guards the allows even when active.
	p2 := cafePlan()
	p2.AppEgressUID = 1001
	p2.AppAllows = []LANAllow{{DstIP: "nope", Proto: "tcp", Port: 9100}}
	if _, err := Render(p2); err == nil {
		t.Fatal("non-IP allow dst must fail validation")
	}
}

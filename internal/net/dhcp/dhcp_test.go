package dhcp

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "rewrite golden files")

func TestRenderGolden(t *testing.T) {
	golden := filepath.Join("testdata", "dnsmasq.conf.golden")
	got, err := Render(Default())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatalf("update golden: %v", err)
		}
		return
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden (run once with -update): %v", err)
	}
	if string(got) != string(want) {
		t.Fatal("dnsmasq.conf drifted from golden (re-run -update only for intentional changes)")
	}
}

func TestRenderIsDeterministic(t *testing.T) {
	a, _ := Render(Default())
	b, _ := Render(Default())
	if string(a) != string(b) {
		t.Fatal("render not deterministic")
	}
}

func TestWaitingIsOnlyDynamicPoolOnBRLAN(t *testing.T) {
	out, err := Render(Default())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	s := string(out)

	// Waiting: dynamic 120 s pool (FR-NET-003).
	if !strings.Contains(s, "dhcp-range=set:waiting,10.20.99.10,10.20.99.250,255.255.255.0,120s") {
		t.Error("waiting dynamic pool missing or wrong")
	}
	// Approved zones: static — unknown devices can only get Waiting
	// addresses, no negative tags needed (TV-02).
	if !strings.Contains(s, "dhcp-range=set:z1,192.168.50.0,static,255.255.255.0,12h") {
		t.Error("z1 static pool missing")
	}
	if !strings.Contains(s, "dhcp-range=set:z2,10.20.2.0,static,255.255.255.0,12h") {
		t.Error("z2 static pool missing")
	}
	// Guest: dynamic 2 h.
	if !strings.Contains(s, "dhcp-range=set:guest,10.20.3.20,10.20.3.250,255.255.255.0,2h") {
		t.Error("guest pool missing or wrong")
	}
	// Captive option 114 stays commented until T2 (DD-09, ERR-07).
	if strings.Contains(s, "\ndhcp-option=tag:guest,114,") {
		t.Error("option 114 must be commented out under T1 local CA (ERR-07)")
	}
	if !strings.Contains(s, "# dhcp-option=tag:guest,114,") {
		t.Error("the commented 114 template line should document the T2 path")
	}
}

func TestRenderSecurityDirectives(t *testing.T) {
	out, err := Render(Default())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	s := string(out)
	for _, want := range []string{
		"no-resolv", "server=1.1.1.1", "server=9.9.9.9",
		"stop-dns-rebind", "rebind-localhost-ok", // SEC-011
		"local=/kcp.internal/",
		"address=/admin.kcp.internal/192.168.50.1",
		"address=/pos.kcp.internal/10.20.2.1",
		"address=/portal.kcp.internal/10.20.3.1",
		"address=/waiting.kcp.internal/10.20.99.1",
		"dhcp-hostsdir=/run/kcportal/dnsmasq/hosts.d",
		"dhcp-script=/usr/lib/kcportal/dhcp-hook",
		"dhcp-leasefile=/run/kcportal/dnsmasq/leases",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("dnsmasq.conf missing %q", want)
		}
	}
}

func TestRenderRequiresUpstreamDNS(t *testing.T) {
	c := Default()
	c.UpstreamDNS = nil
	if _, err := Render(c); err == nil {
		t.Fatal("no upstream DNS must fail")
	}
}

func TestRenderPoolWithoutSubnetFails(t *testing.T) {
	c := Default()
	c.Pools[0].RangeStart = ""
	c.Pools[0].RangeEnd = ""
	c.Pools[0].Subnet = ""
	if _, err := Render(c); err == nil {
		t.Fatal("pool without any addressing must fail")
	}
}

func TestReservationLine(t *testing.T) {
	r := Reservation{MAC: "AA:BB:CC:00:00:01", ZoneTag: "z2", IP: "10.20.2.11", Hostname: "tablet-kasir", LeaseTime: "12h"}
	if got, want := r.Line(), "aa:bb:cc:00:00:01,set:z2,10.20.2.11,tablet-kasir,12h"; got != want {
		t.Fatalf("line = %q, want %q (§4.5 verbatim)", got, want)
	}
	if got, want := r.Filename(), "aabbcc000001.conf"; got != want {
		t.Fatalf("filename = %q, want %q", got, want)
	}
	// No hostname: MAC,tag,ip,lease still valid dnsmasq syntax.
	r.Hostname = ""
	if got := r.Line(); got != "aa:bb:cc:00:00:01,set:z2,10.20.2.11,12h" {
		t.Fatalf("line without hostname = %q", got)
	}
}

func TestWriteReservationsSyncs(t *testing.T) {
	dir := t.TempDir()
	rs := []Reservation{
		{MAC: "aa:bb:cc:00:00:01", ZoneTag: "z2", IP: "10.20.2.11", Hostname: "tablet-kasir", LeaseTime: "12h"},
		{MAC: "aa:bb:cc:00:00:02", ZoneTag: "z1", IP: "192.168.50.20", LeaseTime: "12h"},
	}
	if _, err := WriteReservations(dir, rs); err != nil {
		t.Fatalf("write: %v", err)
	}
	for _, r := range rs {
		b, err := os.ReadFile(filepath.Join(dir, r.Filename()))
		if err != nil {
			t.Fatalf("read %s: %v", r.Filename(), err)
		}
		if strings.TrimSpace(string(b)) != r.Line() {
			t.Fatalf("%s = %q, want %q", r.Filename(), b, r.Line())
		}
		// No temp files left behind.
		if strings.HasSuffix(r.Filename(), ".tmp") {
			t.Fatal("tmp file leaked")
		}
	}

	// Removing a device from the list must remove its file (revocation).
	if n, err := WriteReservations(dir, rs[:1]); err != nil {
		t.Fatalf("resync: %v", err)
	} else if n != 1 {
		t.Fatalf("resync changed = %d, want 1 (the removed file)", n)
	}
	if _, err := os.Stat(filepath.Join(dir, rs[1].Filename())); !os.IsNotExist(err) {
		t.Fatal("stale reservation file survived the sync")
	}
}

func TestWriteReservationsRejectsIncomplete(t *testing.T) {
	dir := t.TempDir()
	_, err := WriteReservations(dir, []Reservation{{MAC: "aa:bb:cc:00:00:03", IP: ""}})
	if err == nil {
		t.Fatal("reservation without IP must be rejected")
	}
	if _, err := os.Stat(filepath.Join(dir, "aabbcc000003.conf")); err == nil {
		t.Fatal("incomplete reservation must not be written")
	}
}

func TestWriteReservationsSkipsUnchangedFiles(t *testing.T) {
	// Unchanged files must not be rewritten: churning hosts.d would make
	// dnsmasq re-read its whole config for nothing (inotify spam).
	dir := t.TempDir()
	r := Reservation{MAC: "aa:bb:cc:00:00:04", ZoneTag: "z2", IP: "10.20.2.12", LeaseTime: "12h"}
	if n, err := WriteReservations(dir, []Reservation{r}); err != nil {
		t.Fatalf("first write: %v", err)
	} else if n != 1 {
		t.Fatalf("first write changed = %d, want 1", n)
	}
	path := filepath.Join(dir, r.Filename())
	first, _ := os.Stat(path)
	time.Sleep(20 * time.Millisecond) // ensure mtime could differ if rewritten
	if n, err := WriteReservations(dir, []Reservation{r}); err != nil || n != 0 {
		t.Fatalf("second write: changed=%d err=%v, want 0/nil (no churn)", n, err)
	}
	second, _ := os.Stat(path)
	if !first.ModTime().Equal(second.ModTime()) {
		t.Fatal("unchanged reservation was rewritten (inotify churn)")
	}
}

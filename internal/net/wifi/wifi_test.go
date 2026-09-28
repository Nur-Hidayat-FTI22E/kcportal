package wifi

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite golden files")

func staffConfig() *Config {
	c := Default("Kafe", "secrets-injected-psk")
	c.BSS[1].Hidden = true
	return c
}

func TestRenderGolden(t *testing.T) {
	golden := filepath.Join("testdata", "hostapd.conf.golden")
	got, err := Render(staffConfig())
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
		t.Fatal("hostapd.conf drifted from golden (re-run -update only for intentional changes)")
	}
}

func TestRenderIsDeterministic(t *testing.T) {
	a, _ := Render(staffConfig())
	b, _ := Render(staffConfig())
	if string(a) != string(b) {
		t.Fatal("render not deterministic")
	}
}

// The PSK is injected from secrets at render time and the file lives on
// tmpfs (0600) — but the plan/config struct must never serialize it, so
// a config built WITHOUT a passphrase must refuse to render.
func TestRenderRefusesEmptyPSK(t *testing.T) {
	c := Default("Kafe", "")
	if _, err := Render(c); err == nil {
		t.Fatal("empty staff PSK must fail validation (secrets injection missing)")
	}
}

func TestDD01BridgePairingEnforced(t *testing.T) {
	c := staffConfig()
	c.BSS[1].Bridge = "br-lan" // both on the same bridge
	if err := c.Validate(); err == nil {
		t.Fatal("both BSS on one bridge must be rejected (DD-01)")
	}
}

func TestGuestBSSMustBeOpen(t *testing.T) {
	c := staffConfig()
	c.BSS[1].Open = false
	if err := c.Validate(); err == nil {
		t.Fatal("guest portal BSS must be open (FR-WIF-010)")
	}
	c2 := staffConfig()
	c2.BSS[1].Passphrase = "oops"
	if err := c2.Validate(); err == nil {
		t.Fatal("open BSS carrying a passphrase is a config bug")
	}
}

func TestStaffBSSMustBeWPA2(t *testing.T) {
	c := staffConfig()
	c.BSS[0].Open = true
	if err := c.Validate(); err == nil {
		t.Fatal("staff BSS must not be open")
	}
}

func TestRenderTwoBSSBlocks(t *testing.T) {
	out, err := Render(staffConfig())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	s := string(out)
	for _, want := range []string{
		"interface=wlan0",
		"bss=wlan0_1",
		"bridge=br-lan",
		"bridge=br-guest",
		"wpa=2",
		"rsn_pairwise=CCMP",
		"wpa_passphrase=secrets-injected-psk",
		"wpa=0",
		"country_code=ID",
		"ap_isolate=1",
		"ignore_broadcast_ssid=1",
		"vht_oper_chwidth=1",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("hostapd.conf missing %q", want)
		}
	}
	// 5 GHz + 80 MHz: seg0 index derives from the channel (36 -> 42, §4.4).
	if !strings.Contains(s, "vht_oper_centr_freq_seg0_idx=42") {
		t.Error("vht seg0 index wrong for channel 36")
	}
}

func TestValidateTwoBSSRequired(t *testing.T) {
	c := staffConfig()
	c.BSS = c.BSS[:1]
	if err := c.Validate(); err == nil {
		t.Fatal("single-BSS config must be rejected (DD-01 needs both)")
	}
}

func TestBandGNoVHT(t *testing.T) {
	c := staffConfig()
	c.Radio.HWMode = "g"
	c.Radio.VHT80 = false
	out, err := Render(c)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if strings.Contains(string(out), "ieee80211ac") {
		t.Error("2.4 GHz config must not emit 802.11ac lines")
	}
}

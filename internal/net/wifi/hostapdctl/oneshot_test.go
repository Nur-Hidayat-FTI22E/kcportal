package hostapdctl

import (
	"testing"
)

// The one-shot path dials, sends the lowercased MAC, accepts OK, and
// stops at the first accepting BSS (a station sits on exactly one BSS).
func TestOneshotDeauthenticateOK(t *testing.T) {
	dir := t.TempDir()
	f0 := newFakeHostapd(t, dir, "wlan0")

	if err := OneshotDeauthenticate(dir, []string{"wlan0", "wlan0_1"}, "AA:BB:CC:DD:11:01"); err != nil {
		t.Fatalf("OneshotDeauthenticate: %v", err)
	}
	if !f0.got("DEAUTHENTICATE aa:bb:cc:dd:11:01") {
		t.Error("BSS0 never received the DEAUTHENTICATE (MAC must be lowercased)")
	}
}

// When the first BSS socket is missing, the kick must land on the next
// one — the dual-BSS deployment keeps working with only BSS1 exposed.
func TestOneshotFallsThroughToSecondBSS(t *testing.T) {
	dir := t.TempDir()
	f1 := newFakeHostapd(t, dir, "wlan0_1") // wlan0 intentionally absent

	if err := OneshotDeauthenticate(dir, []string{"wlan0", "wlan0_1"}, "aa:bb:cc:dd:11:02"); err != nil {
		t.Fatalf("OneshotDeauthenticate: %v", err)
	}
	if !f1.got("DEAUTHENTICATE aa:bb:cc:dd:11:02") {
		t.Error("BSS1 never received the DEAUTHENTICATE after BSS0 was unreachable")
	}
}

// A missing/down hostapd socket fails cleanly (ops prints a warning;
// nft enforcement stands alone).
func TestOneshotUnreachableSocket(t *testing.T) {
	dir := t.TempDir() // no fake bound
	if err := OneshotDeauthenticate(dir, []string{"wlan0"}, "aa:bb:cc:dd:11:01"); err == nil {
		t.Fatal("dial to a missing socket must fail")
	}
}

// hostapd only exposes sockets for BSS it actually created — in
// KCP_WIFI_BSS=single there is no wlan0_1. A kick that lands on the one
// live BSS must count as success (first-ok-wins), not surface the
// missing-socket error as a false alarm.
func TestOneshotPartialFailureContinues(t *testing.T) {
	dir := t.TempDir()
	newFakeHostapd(t, dir, "wlan0") // reachable
	// wlan0_1 intentionally absent.

	if err := OneshotDeauthenticate(dir, []string{"wlan0", "wlan0_1"}, "aa:bb:cc:dd:11:01"); err != nil {
		t.Fatalf("kick on the live BSS must succeed, got: %v", err)
	}
}

// All BSS unreachable = real failure (hostapd down).
func TestOneshotAllDown(t *testing.T) {
	dir := t.TempDir()
	if err := OneshotDeauthenticate(dir, []string{"wlan0", "wlan0_1"}, "aa:bb:cc:dd:11:01"); err == nil {
		t.Fatal("all-BSS-down must surface an error")
	}
}

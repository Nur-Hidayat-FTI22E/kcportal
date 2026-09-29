package nft

import (
	"context"
	"strings"
	"testing"
)

// TestReadShieldStatsParsesLiveOutput uses the exact text shape `nft
// list chain inet kcp_portal gate_fwd` printed on the Pi (2026-09-29).
func TestReadShieldStatsParsesLiveOutput(t *testing.T) {
	bin := fakeNft(t, `cat <<'EOF'
table inet kcp_portal {
	chain gate_fwd {
		type filter hook forward priority filter - 10; policy accept;
		iifname "br-guest" ip daddr @doh_block4 counter packets 12 bytes 768 drop
		iifname "br-guest" tcp dport 853 counter packets 3 bytes 192 drop
		iifname "br-guest" udp dport 853 counter packets 0 bytes 0 drop
		iifname "br-guest" ether saddr != @authed_guests meta l4proto tcp reject with tcp reset
	}
}
EOF
exit 0`)
	st, err := ReadShieldStats(context.Background(), bin)
	if err != nil {
		t.Fatalf("ReadShieldStats: %v", err)
	}
	if !st.Installed {
		t.Fatal("shield must report installed when the rules are present")
	}
	if st.DoHPackets != 12 || st.DoTPackets != 3 || st.DoQPackets != 0 {
		t.Fatalf("stats = %+v", st)
	}
}

// A chain without shield rules (opted-out plan) reads as not installed
// — the GUI then shows "tidak terpasang" instead of fake zeros.
func TestReadShieldStatsAbsentRules(t *testing.T) {
	bin := fakeNft(t, `cat <<'EOF'
table inet kcp_portal {
	chain gate_fwd {
		type filter hook forward priority filter - 10; policy accept;
		iifname "br-guest" ether saddr != @authed_guests reject
	}
}
EOF
exit 0`)
	st, err := ReadShieldStats(context.Background(), bin)
	if err != nil {
		t.Fatalf("ReadShieldStats: %v", err)
	}
	if st.Installed {
		t.Fatalf("no shield rules present, stats = %+v", st)
	}
}

func TestReadShieldStatsNftFailure(t *testing.T) {
	bin := fakeNft(t, `echo "no such chain" >&2; exit 1`)
	_, err := ReadShieldStats(context.Background(), bin)
	if err == nil || !strings.Contains(err.Error(), "read gate_fwd") {
		t.Fatalf("err = %v, want a read failure", err)
	}
}

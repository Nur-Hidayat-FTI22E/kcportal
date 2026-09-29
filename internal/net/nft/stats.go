package nft

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// ShieldStats carries the live drop counters of the DoH/DoT shield rules
// in kcp_portal.gate_fwd, for the admin GUI's monitoring view. Packets
// > 0 means a guest is actively trying encrypted DNS and the shield is
// doing its job (Private DNS bootstrap failures are expected noise).
type ShieldStats struct {
	// Installed reports whether any shield rule was found in the live
	// chain — false on dev boxes, -dev dry runs, and opted-out plans.
	Installed  bool
	DoHPackets uint64 // bootstrap-IP drops (DoH over 443 / plain DNS to resolvers)
	DoTPackets uint64 // tcp/853 drops
	DoQPackets uint64 // udp/853 drops
}

// counterLine matches the way nft renders a counter expression:
// `... counter packets 12 bytes 3456 drop`. The text format has been
// stable across nft 1.0.x; JSON parsing would be stricter but adds a
// dependency on the -j schema shape for little gain in a monitoring
// path that fails soft.
var counterLine = regexp.MustCompile(`counter packets (\d+) bytes (\d+)`)

// ReadShieldStats reads the counters from the LIVE ruleset via
// `nft list chain inet kcp_portal gate_fwd`. nftBin is the binary to
// invoke ("" = "nft"). It never mutates anything; a failed read returns
// an error and the caller decides how to display it (GUI shows
// "shield tidak terpasang" instead of a hard failure).
func ReadShieldStats(ctx context.Context, nftBin string) (ShieldStats, error) {
	if nftBin == "" {
		nftBin = "nft"
	}
	out, err := exec.CommandContext(ctx, nftBin, "list", "chain", "inet", "kcp_portal", "gate_fwd").Output()
	if err != nil {
		return ShieldStats{}, fmt.Errorf("nft: read gate_fwd counters: %w", err)
	}
	var st ShieldStats
	for _, line := range strings.Split(string(out), "\n") {
		m := counterLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		packets, perr := strconv.ParseUint(m[1], 10, 64)
		if perr != nil {
			continue
		}
		switch {
		case strings.Contains(line, "daddr @doh_block4"):
			st.Installed = true
			st.DoHPackets += packets
		case strings.Contains(line, "tcp dport 853"):
			st.Installed = true
			st.DoTPackets += packets
		case strings.Contains(line, "udp dport 853"):
			st.Installed = true
			st.DoQPackets += packets
		}
	}
	return st, nil
}

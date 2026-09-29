package api

import (
	"context"
	"net/http"
	"time"

	"kotacloud-portal/internal/net/nft"
)

// HandleShieldGET serves GET /api/v1/network/doh: the live DoH/DoT
// shield drop counters from the running ruleset. This is a monitoring
// read straight from the kernel, deliberately OUTSIDE the state actor
// (PD-3 governs writes, not reads) — a failed read fails soft: the GUI
// shows "shield tidak terpasang" rather than an error page, because a
// missing shield is exactly what the operator needs to know about.
//
// The 2s timeout keeps the API handler bounded: nft is a local kernel
// read, but a wedged binary must not hang the admin GUI's poll loop.
func (s *Server) HandleShieldGET(w http.ResponseWriter, _ *http.Request) (any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	st, err := nft.ReadShieldStats(ctx, "")
	if err != nil {
		// Fail soft: counters unavailable ≠ outage. The GUI renders the
		// not-installed state from Installed=false.
		s.Log.Warn("shield stats read failed", "err", err)
		return nft.ShieldStats{}, nil
	}
	return st, nil
}

// Package webadmin embeds the built web/admin React GUI (§7.2) into
// kcportald. The dist/ bundle is committed and embedded at compile
// time, so CI and `go build ./...` stay Go-only — no Node toolchain is
// needed to build or serve the daemon. The GUI rides the same
// 127.0.0.1:8083 listener as the REST API (loopback / mgmt plane only;
// reachability beyond that is the operator's tunnel, never 0.0.0.0).
//
// Static files are served without the bearer token on purpose: the
// browser must be able to load the login page before a token exists.
// Everything under /api/ stays authenticated (the api package's auth
// middleware skips only non-API paths); the unauthenticated surface is
// just the static bundle, which holds no secrets and talks to the
// token-gated API from the browser.
package webadmin

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed all:dist
var distFS embed.FS

// Handler serves the SPA: real files (index.html, hashed /assets/*)
// as-is, every other GET path falls back to index.html so client-side
// routing keeps working after a deep link.
func Handler() http.Handler {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		// Compile-time embed; unreachable, but fail loudly if the
		// layout ever changes under us.
		panic("webadmin: dist subtree missing: " + err.Error())
	}
	files := http.FileServerFS(sub)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		p := r.URL.Path
		if _, serr := fs.Stat(sub, p); serr != nil {
			// Not a real file → SPA fallback (root index.html).
			r.URL.Path = "/"
		}
		// index.html must not be cached: a stale shell would reference
		// hashed asset names that no longer exist after an upgrade.
		if p == "/" {
			w.Header().Set("Cache-Control", "no-store")
		}
		files.ServeHTTP(w, r)
	})
}

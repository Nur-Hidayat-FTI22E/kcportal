// Package web embeds the web/portal React captive page (§5) into
// portaledge. Same discipline as internal/api/webadmin: the committed
// dist/ bundle is compiled in, so CI and `go build ./...` stay
// Go-only. The guest SPA renders the consent form and talks to the
// same wire contract the Go template used (GET /state JSON, POST /
// form-encoded, catch-all 302 for OS probes) — identity still comes
// only from the kernel neighbor table (DD-10), never from the client.
package web

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed all:dist
var distFS embed.FS

// Handler serves the guest portal SPA: real files as-is, any other GET
// path falls back to index.html, non-GET is rejected.
func Handler() http.Handler {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		panic("portalweb: dist subtree missing: " + err.Error())
	}
	files := http.FileServerFS(sub)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		p := r.URL.Path
		if _, serr := fs.Stat(sub, p); serr != nil {
			r.URL.Path = "/" // SPA fallback
		}
		// The shell must not be cached: a stale index.html would
		// reference hashed asset names that no longer exist.
		if p == "/" {
			w.Header().Set("Cache-Control", "no-store")
		}
		files.ServeHTTP(w, r)
	})
}

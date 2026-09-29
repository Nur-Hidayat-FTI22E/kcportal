// Package web embeds the cashier UI (web/pos, React + Vite + TS) into
// the pos-cafe binary — same pattern as the other kotacloud UIs: the
// built dist/ bundle is committed, so CI stays Go-only. The UI talks
// to the same-origin JSON API (/api/*) with its HttpOnly session
// cookie; identity never enters the client beyond the display name.
package web

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed all:dist
var distFS embed.FS

// Handler serves the cashier SPA: real files as-is, any other GET
// falls back to index.html, non-GET is rejected.
func Handler() http.Handler {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		panic("posweb: dist subtree missing: " + err.Error())
	}
	files := http.FileServerFS(sub)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		p := r.URL.Path
		// io/fs paths are unrooted — a leading "/" would fail every
		// stat and push real assets into the SPA fallback (regression
		// guarded by tests in the other embeds).
		if _, serr := fs.Stat(sub, strings.TrimPrefix(p, "/")); serr != nil {
			r.URL.Path = "/" // SPA fallback
		}
		if p == "/" {
			w.Header().Set("Cache-Control", "no-store")
		}
		files.ServeHTTP(w, r)
	})
}

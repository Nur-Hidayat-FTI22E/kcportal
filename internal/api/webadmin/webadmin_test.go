package webadmin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestServesIndexAndAssets(t *testing.T) {
	h := Handler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET / -> %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `id="root"`) {
		t.Fatal("index.html shell missing #root")
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("index cache-control = %q, want no-store", cc)
	}

	// The hashed bundle must be reachable at its real embedded name.
	entries, err := distFS.ReadDir("dist/assets")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) < 2 {
		t.Fatalf("dist/assets too empty: %d entries", len(entries))
	}
	served := 0
	for _, e := range entries {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", "/assets/"+e.Name(), nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /assets/%s -> %d", e.Name(), rec.Code)
		}
		// Guard against the fs.Stat-unrooted-path regression: a real
		// asset falling into the SPA fallback would come back as the
		// HTML shell instead of the bundle.
		if strings.Contains(rec.Body.String(), `id="root"`) {
			t.Fatalf("asset %s came back as the HTML shell (content-type %q)",
				e.Name(), rec.Header().Get("Content-Type"))
		}
		served++
	}
	if served < 2 {
		t.Fatal("expected js+css assets")
	}
}

func TestUnknownPathFallsBackToShell(t *testing.T) {
	h := Handler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/some/deep/route", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `id="root"`) {
		t.Fatalf("SPA fallback broken: %d %s", rec.Code, rec.Body.String())
	}
}

func TestNonGETRejected(t *testing.T) {
	h := Handler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/", strings.NewReader("x")))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST / -> %d, want 405", rec.Code)
	}
}

package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestServesShellAndAssets(t *testing.T) {
	h := Handler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET / -> %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `id="root"`) {
		t.Fatal("portal shell missing #root")
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("shell cache-control = %q, want no-store", cc)
	}

	entries, err := distFS.ReadDir("dist/assets")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", "/assets/"+e.Name(), nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /assets/%s -> %d", e.Name(), rec.Code)
		}
	}
}

func TestFallbackAndMethodGate(t *testing.T) {
	h := Handler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/whatever", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `id="root"`) {
		t.Fatalf("SPA fallback broken: %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/", strings.NewReader("x")))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST / -> %d, want 405", rec.Code)
	}
}

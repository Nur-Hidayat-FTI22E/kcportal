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
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `id="root"`) {
		t.Fatalf("GET / -> %d", rec.Code)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("shell cache-control = %q", cc)
	}
	entries, err := distFS.ReadDir("dist/assets")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", "/assets/"+e.Name(), nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("asset %s -> %d", e.Name(), rec.Code)
		}
		if strings.Contains(rec.Body.String(), `id="root"`) {
			t.Fatalf("asset %s came back as the HTML shell (fs.Stat regression)", e.Name())
		}
	}
}

func TestFallbackAndMethodGate(t *testing.T) {
	h := Handler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/deep/route", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("fallback -> %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/", strings.NewReader("x")))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST / -> %d, want 405", rec.Code)
	}
}

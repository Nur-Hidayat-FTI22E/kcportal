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
		// Guard against the fs.Stat-unrooted-path regression: a real
		// asset falling into the SPA fallback would come back as the
		// ~450-byte HTML shell with a text/html content type.
		ct := rec.Header().Get("Content-Type")
		body := rec.Body.String()
		if strings.HasSuffix(e.Name(), ".js") && !strings.Contains(ct, "javascript") {
			t.Fatalf("asset %s content-type = %q (SPA fallback leak?): body head %.60q", e.Name(), ct, body)
		}
		if strings.HasSuffix(e.Name(), ".css") && !strings.Contains(ct, "text/css") {
			t.Fatalf("asset %s content-type = %q", e.Name(), ct)
		}
		if strings.Contains(body, `id="root"`) {
			t.Fatalf("asset %s came back as the HTML shell", e.Name())
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

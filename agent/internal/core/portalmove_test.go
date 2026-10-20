package core

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCheckPortalURL(t *testing.T) {
	good := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/health" {
			_, _ = w.Write([]byte(`{"ok":true}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer good.Close()
	bad := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html>parked domain</html>"))
	}))
	defer bad.Close()
	hc := good.Client()
	ctx := context.Background()
	if got, err := checkPortalURL(ctx, hc, good.URL+"/"); err != nil || got != good.URL {
		t.Fatalf("good: %q %v", got, err)
	}
	if _, err := checkPortalURL(ctx, bad.Client(), bad.URL); err == nil || !strings.Contains(err.Error(), "does not answer as") {
		t.Fatalf("bad: %v", err)
	}
	for _, u := range []string{"ftp://x", "https://user:pw@example.com", "https://example.com/?x=1", "not a url", "https://127.0.0.1:1"} {
		if _, err := checkPortalURL(ctx, hc, u); err == nil {
			t.Fatalf("accepted %q", u)
		}
	}
}

// Audit A1 F3: a move never goes to http, and a redirect to a portal does
// not make an address a portal.
func TestCheckPortalURLRefusesHTTPAndRedirects(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer plain.Close()
	ctx := context.Background()
	if _, err := checkPortalURL(ctx, http.DefaultClient, plain.URL); err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("http accepted: %v", err)
	}
	good := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer good.Close()
	moved := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, good.URL+r.URL.Path, http.StatusMovedPermanently)
	}))
	defer moved.Close()
	if _, err := checkPortalURL(ctx, moved.Client(), moved.URL); err == nil {
		t.Fatal("followed a redirect")
	}
}

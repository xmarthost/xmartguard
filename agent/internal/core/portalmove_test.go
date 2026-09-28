package core

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCheckPortalURL(t *testing.T) {
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/health" {
			_, _ = w.Write([]byte(`{"ok":true}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer good.Close()
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html>parked domain</html>"))
	}))
	defer bad.Close()
	ctx := context.Background()
	if got, err := checkPortalURL(ctx, http.DefaultClient, good.URL+"/"); err != nil || got != good.URL {
		t.Fatalf("good: %q %v", got, err)
	}
	if _, err := checkPortalURL(ctx, http.DefaultClient, bad.URL); err == nil || !strings.Contains(err.Error(), "does not answer as") {
		t.Fatalf("bad: %v", err)
	}
	for _, u := range []string{"ftp://x", "https://user:pw@example.com", "https://example.com/?x=1", "not a url", "http://127.0.0.1:1"} {
		if _, err := checkPortalURL(ctx, http.DefaultClient, u); err == nil {
			t.Fatalf("accepted %q", u)
		}
	}
}

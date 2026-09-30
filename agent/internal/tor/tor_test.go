package tor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestRefreshAndCache(t *testing.T) {
	body := "185.220.101.1\n# comment\n10.0.0.1\n185.220.101.1\n2001:db8::1\nbad\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if body == "" {
			w.WriteHeader(500)
			return
		}
		w.Write([]byte(body))
	}))
	defer srv.Close()
	old := URL
	URL = srv.URL
	defer func() { URL = old }()
	path := filepath.Join(t.TempDir(), "tor.json")
	l := New(path)
	if !l.Due(time.Hour) {
		t.Fatal("empty list not due")
	}
	changed, err := l.Refresh(context.Background())
	if err != nil || !changed {
		t.Fatal(changed, err)
	}
	if a := l.Addrs(); len(a) != 2 || a[0] != "185.220.101.1" || a[1] != "2001:db8::1" {
		t.Fatalf("addrs %v", a)
	}
	if changed, _ := l.Refresh(context.Background()); changed {
		t.Fatal("same list reported as changed")
	}
	// A failed download keeps the list; the cache survives a restart.
	body = ""
	if _, err := l.Refresh(context.Background()); err == nil {
		t.Fatal("error not reported")
	}
	if len(New(path).Addrs()) != 2 || l.Status()["error"] == "" {
		t.Fatal("list lost after a failed download")
	}
}

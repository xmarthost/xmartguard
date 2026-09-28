package trusted

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestRefreshAndMatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, ".json"):
			w.Write([]byte(`{"creationTime":"x","prefixes":[{"ipv4Prefix":"66.249.66.0/27"},{"ipv6Prefix":"2001:4860:4801:10::/64"},{"ipv4Prefix":"0.0.0.0/0"}]}`))
		default:
			w.Write([]byte("# list\n216.144.250.150\n69.162.124.226, 2607:ff68:107::3\nnot-an-ip\n"))
		}
	}))
	defer srv.Close()
	saved := Services
	defer func() { Services = saved }()
	Services = []Service{
		{ID: "g", Name: "Googlebot", URL: srv.URL + "/g.json", Format: "prefixes", Builtin: []string{"66.249.64.0/19"}},
		{ID: "u", Name: "UptimeRobot", URL: srv.URL + "/u.txt", Format: "lines"},
		{ID: "p", Name: "PayPal", Hosts: []string{"ipn.example"}},
		{ID: "down", Name: "Down", URL: "http://127.0.0.1:1/x.txt", Format: "lines", Builtin: []string{"198.51.100.0/24"}},
	}
	path := filepath.Join(t.TempDir(), "trusted.json")
	s := New(path)
	s.Resolve = func(context.Context, string) ([]string, error) { return []string{"173.0.84.8"}, nil }
	if s.Match("66.249.70.1", nil) != "Googlebot" || s.Match("216.144.250.150", nil) != "" {
		t.Fatal("builtin list not used before refresh")
	}
	if !s.Refresh(context.Background()) {
		t.Fatal("refresh should report a change")
	}
	got := strings.Join(s.CIDRs(nil), ",")
	for _, want := range []string{"66.249.66.0/27", "2001:4860:4801:10::/64", "216.144.250.150", "2607:ff68:107::3", "173.0.84.8", "198.51.100.0/24"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %s in %s", want, got)
		}
	}
	if strings.Contains(got, "0.0.0.0/0") {
		t.Fatal("a /0 range was accepted")
	}
	if s.Match("69.162.124.226", nil) != "UptimeRobot" || s.Match("69.162.124.226", []string{"u"}) != "" {
		t.Fatal("match / disabled service")
	}
	// Cache survives a restart.
	s2 := New(path)
	if s2.Match("216.144.250.150", nil) != "UptimeRobot" {
		t.Fatal("cache not loaded")
	}
}

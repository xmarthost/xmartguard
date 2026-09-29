package trusted

import (
	"context"
	"io"
	"net"
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

func TestScanRADBAndGroups(t *testing.T) {
	// Fastly / Bunny / CloudFront style documents.
	got := clean(scanAddrs([]byte(`{"addresses":["23.235.32.0/20","43.249.72.0/22"],"ipv6_addresses":["2a04:4e40::/32"],"note":"12:30:45 v1.2"}`)))
	if strings.Join(got, ",") != "23.235.32.0/20,2a04:4e40::/32,43.249.72.0/22" {
		t.Fatalf("scan: %v", got)
	}
	// A RADb whois answer.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		buf := make([]byte, 64)
		n, _ := c.Read(buf)
		if strings.TrimSpace(string(buf[:n])) == "-i origin AS32934" {
			io.WriteString(c, "route:          157.240.0.0/16\ndescr: Facebook\nroute6:         2a03:2880::/29\norigin: AS32934\n")
		}
		c.Close()
	}()
	old := RADBAddr
	RADBAddr = ln.Addr().String()
	defer func() { RADBAddr = old }()
	r, err := radbRoutes(context.Background(), "AS32934")
	if err != nil || strings.Join(r, ",") != "157.240.0.0/16,2a03:2880::/29" {
		t.Fatalf("radb: %v %v", r, err)
	}

	s := New(filepath.Join(t.TempDir(), "c.json"))
	s.SetCustom([]string{"198.51.100.7", "bad value", "203.0.113.0/24"})
	all, waf := s.CIDRs(nil), s.WAFCIDRs(nil)
	has := func(l []string, x string) bool {
		for _, v := range l {
			if v == x {
				return true
			}
		}
		return false
	}
	// Cloudflare and Claude are never banned, but only crawlers, monitors,
	// payments, vendors and your own list skip the WAF's bot rules.
	if !has(all, "104.16.0.0/13") || has(waf, "104.16.0.0/13") || !has(all, "160.79.104.0/21") || has(waf, "160.79.104.0/21") {
		t.Fatal("cdn/ai groups")
	}
	if !has(waf, "66.249.64.0/19") || !has(waf, "198.51.100.7") || !has(all, "203.0.113.0/24") {
		t.Fatal("waf/custom")
	}
	if s.Match("203.0.113.9", nil) != "your trusted list" || s.Match("203.0.113.9", []string{CustomID}) != "" {
		t.Fatal("custom match")
	}
	ids := map[string]bool{}
	for _, svc := range Services {
		if ids[svc.ID] {
			t.Fatalf("duplicate id %s", svc.ID)
		}
		ids[svc.ID] = true
		if svc.URL == "" && len(svc.Hosts) == 0 && len(svc.Builtin) == 0 {
			t.Fatalf("%s has no source", svc.ID)
		}
		if len(clean(svc.Builtin)) != len(svc.Builtin) {
			t.Fatalf("%s: invalid built-in address", svc.ID)
		}
	}
}

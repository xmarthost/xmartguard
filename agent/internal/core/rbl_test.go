package core

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/xmarthost/xmartguard/agent/internal/firewall"
	"github.com/xmarthost/xmartguard/agent/internal/tor"
)

func TestTorCaptchaAndExempt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("198.51.100.66\n")) }))
	defer srv.Close()
	old := tor.URL
	tor.URL = srv.URL
	defer func() { tor.URL = old }()
	a := newTestAgent(t, `{"waf":{"enabled":true,"tor_action":"captcha"}}`)
	a.Cfg.ServerID = "15d69a72-653a-47b6-90f6-fde737bce061"
	if _, err := a.Tor.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Without the portal's CAPTCHA page, Tor visitors cannot post.
	if m := a.torMode(); m != "post" {
		t.Fatalf("mode %s", m)
	}
	cfg, _ := json.Marshal(centralConfig{Version: 1, Enabled: true, URL: "https://captcha.xpguard.org/v", Minutes: 30})
	if _, err := a.Handlers()["captcha.central"](context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if m := a.torMode(); m != "captcha" {
		t.Fatalf("mode %s", m)
	}
	found := false
	for _, ip := range a.centralSuspects() {
		found = found || ip == "198.51.100.66"
	}
	if !found {
		t.Fatal("Tor exit not sent to the CAPTCHA page")
	}
	// Allowed addresses and solved CAPTCHAs are never blocked by the IPDB/Tor rules.
	a.Firewall.Add(firewall.KindAllow, "192.0.2.10", "office", 0)
	a.centralPass("203.0.113.8")
	ex := map[string]bool{}
	for _, e := range a.rblExempt() {
		ex[e] = true
	}
	if !ex["192.0.2.10"] && !ex["192.0.2.10/32"] || !ex["203.0.113.8"] {
		t.Fatalf("exempt %v", a.rblExempt())
	}
}

package core

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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

// A real search crawler on an IPDB-listed network (Bingbot from Microsoft's
// cloud) is never blocked: the WAF's IPDB POST rule exempts the trusted
// services as the kernel firewall does, and the lookup says so.
func TestTrustedServicesNotIPDBBlocked(t *testing.T) {
	a := newTestAgent(t, `{"firewall":{"trusted_services":true},"ipdb":{"enabled":true}}`)
	has := func(l []string, v string) bool {
		for _, x := range l {
			if x == v {
				return true
			}
		}
		return false
	}
	if !has(a.rblExempt(), "40.77.167.0/24") {
		t.Fatal("Bingbot's network is not exempt from the IPDB POST rule")
	}
	if has(a.rblExempt(), "104.16.0.0/13") {
		t.Fatal("a CDN carries every visitor and must not be exempt")
	}
	if _, err := a.Firewall.ApplyIPDB("v1", []string{"40.77.167.72 US", "203.0.113.9 ZZ"}); err != nil {
		t.Logf("kernel: %v", err)
	}
	if r, _ := a.Firewall.Check("40.77.167.72"); r.Trusted == "" || r.Status != "allowed" {
		t.Fatalf("trusted crawler on the IPDB: %s %q", r.Status, r.Trusted)
	}
	if r, _ := a.Firewall.Check("203.0.113.9"); !strings.HasPrefix(r.Status, "ipdb-blocked") {
		t.Fatalf("listed address: %s", r.Status)
	}
	a.Settings.Patch([]byte(`{"firewall":{"trusted_disabled":["bingbot"]}}`))
	if has(a.rblExempt(), "40.77.167.0/24") {
		t.Fatal("a switched-off service is still exempt")
	}
}

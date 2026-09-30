package core

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/xmarthost/xmartguard/agent/internal/store"
)

func TestHostedHere(t *testing.T) {
	d := map[string]string{"shop.example.com": "shop", "blog.example.org": "blog"}
	for host, want := range map[string]bool{
		"shop.example.com": true, "www.shop.example.com": true, "SHOP.example.com:443": true, "blog.example.org.": true,
		"evil.com": false, "shop.example.com@evil.com": false, "": false, "evil.com/shop.example.com": false,
	} {
		if got := hostedHere(host, d); got != want {
			t.Errorf("%q: %v", host, got)
		}
	}
	if !hostedHere("any.example.net", nil) || hostedHere("a b", nil) {
		t.Error("without a domain list")
	}
}

func TestCentralCaptchaAgent(t *testing.T) {
	a := newTestAgent(t, `{}`)
	a.Cfg.ServerID = "15d69a72-653a-47b6-90f6-fde737bce061"
	old := UserDomainsPath
	UserDomainsPath = filepath.Join(t.TempDir(), "userdomains")
	defer func() { UserDomainsPath = old }()
	os.WriteFile(UserDomainsPath, []byte("shop.example.com: shop\n*: nobody\n"), 0o644)
	h := a.Handlers()
	ctx := context.Background()

	if a.centralWAF() != nil {
		t.Fatal("central CAPTCHA on before the portal turned it on")
	}
	// Portal turns it on (Overview » CAPTCHA page).
	cfg, _ := json.Marshal(centralConfig{Version: 3, Enabled: true, URL: "https://captcha.xpguard.org/v", Minutes: 30})
	if _, err := h["captcha.central"](ctx, cfg); err != nil {
		t.Fatal(err)
	}
	c := a.Settings.Get().Captcha
	if !c.Central || c.CentralURL != "https://captcha.xpguard.org/v" || c.CentralMinutes != 30 || store.GetKV(a.DB, kvCentralVersion) != "3" {
		t.Fatalf("settings %+v", c)
	}
	bad, _ := json.Marshal(centralConfig{Version: 4, Enabled: true, URL: "javascript:alert(1)"})
	if _, err := h["captcha.central"](ctx, bad); err == nil {
		t.Fatal("bad CAPTCHA page address accepted")
	}

	// Suspects: banned here recently, or blocked by the WAF 3 times today.
	now := store.Now()
	a.DB.Exec(`INSERT INTO fw_events (ip, reason, source, created_at, status) VALUES ('198.51.100.7','x','bruteforce',?,'expired')`, now-3600)
	a.DB.Exec(`INSERT INTO fw_events (ip, reason, source, created_at, status) VALUES ('198.51.100.8','x','bruteforce',?,'expired')`, now-30*86400)
	for i := 0; i < 3; i++ {
		a.DB.Exec(`INSERT INTO waf_events (at, ip, rule_id, action) VALUES (?, '203.0.113.5', 7700601, 'Access denied with code 403')`, now-60)
		a.DB.Exec(`INSERT INTO waf_events (at, ip, rule_id, action) VALUES (?, '203.0.113.6', 7700904, 'Access denied with code 302')`, now-60)
	}
	a.DB.Exec(`INSERT INTO waf_events (at, ip, rule_id, action) VALUES (?, '203.0.113.9', 7700601, 'Access denied with code 403')`, now-60)
	w := a.centralWAF()
	if w == nil || w.ServerID != a.Cfg.ServerID {
		t.Fatalf("central %+v", w)
	}
	got := map[string]bool{}
	for _, ip := range w.Suspects {
		got[ip] = true
	}
	if !got["198.51.100.7"] || !got["203.0.113.5"] || got["198.51.100.8"] || got["203.0.113.6"] || got["203.0.113.9"] {
		t.Fatalf("suspects %v", w.Suspects)
	}

	// A pass for a site of this server; not for another site.
	pass := func(ip, host string) error {
		p, _ := json.Marshal(map[string]string{"ip": ip, "host": host})
		_, err := h["captcha.pass"](ctx, p)
		return err
	}
	if err := pass("198.51.100.7", "www.shop.example.com"); err != nil {
		t.Fatal(err)
	}
	if err := pass("198.51.100.7", "evil.com"); err == nil {
		t.Fatal("pass for a site that is not on this server")
	}
	if err := pass("not-an-ip", "shop.example.com"); err == nil {
		t.Fatal("pass for an invalid address")
	}
	if l := a.centralPassList(); len(l) != 1 || l[0] != "198.51.100.7" {
		t.Fatalf("pass list %v", l)
	}
	// Expired passes drop out.
	store.SetKV(a.DB, kvCentralPass, `{"198.51.100.7":1}`)
	if l := a.centralPassList(); len(l) != 0 {
		t.Fatalf("expired pass kept: %v", l)
	}

	// The login-page CAPTCHA for everyone replaces it.
	h["settings.set"](ctx, []byte(`{"captcha":{"login_gate":true}}`))
	if a.centralWAF() != nil {
		t.Fatal("central CAPTCHA together with the gate")
	}
}

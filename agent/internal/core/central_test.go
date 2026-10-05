package core

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/store"
	"github.com/xmarthost/xmartguard/agent/internal/waf"
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
	if hostedHere("any.example.net", nil) || hostedHere("a b", nil) {
		t.Error("without a domain list, no site is on the list")
	}
}

// Without cPanel's domain list a solved CAPTCHA is only accepted for a site
// the WAF sent the visitor from, or one that points at this server: the
// CAPTCHA domain must never send people on to any other site.
func TestSiteHereWithoutDomainList(t *testing.T) {
	a := newTestAgent(t, `{}`)
	old, oldLookup, oldLocal := UserDomainsPath, lookupIP, localAddrs
	UserDomainsPath = filepath.Join(t.TempDir(), "none")
	defer func() { UserDomainsPath, lookupIP, localAddrs = old, oldLookup, oldLocal }()
	localAddrs = func() []net.IP { return []net.IP{net.ParseIP("203.0.113.10"), net.ParseIP("127.0.0.1")} }
	lookupIP = func(_ context.Context, host string) ([]net.IP, error) {
		switch host {
		case "mine.example.com":
			return []net.IP{net.ParseIP("203.0.113.10")}, nil
		case "localhost.example.com":
			return []net.IP{net.ParseIP("127.0.0.1")}, nil
		}
		return []net.IP{net.ParseIP("198.51.100.99")}, nil
	}
	if !a.siteHere("192.0.2.5", "mine.example.com") {
		t.Error("a site that points at this server")
	}
	for _, h := range []string{"evil.com", "localhost.example.com", "203.0.113.10", "", "a b"} {
		if a.siteHere("192.0.2.5", h) {
			t.Errorf("%q accepted", h)
		}
	}
	// Behind a CDN (other address): accepted once the WAF sent the visitor.
	if a.siteHere("192.0.2.5", "cdn.example.com") {
		t.Fatal("cdn site accepted before a redirect")
	}
	waf.NoteCaptchaSent("192.0.2.5", "www.cdn.example.com", time.Now())
	if !a.siteHere("192.0.2.5", "cdn.example.com:443") || a.siteHere("192.0.2.6", "cdn.example.com") {
		t.Error("redirect record not matched to visitor and site")
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

	// The login-page CAPTCHA for everyone uses the portal's page too, for
	// every visitor, and the server's own gate is not rendered.
	h["settings.set"](ctx, []byte(`{"captcha":{"login_gate":true},"waf":{"enabled":true,"login_urls":["/wp-login.php"]}}`))
	if w := a.centralWAF(); w == nil || !w.All || len(w.Suspects) != 0 {
		t.Fatalf("login-page CAPTCHA for everyone: %+v", w)
	}
	if a.WAF.Gate() != nil {
		t.Fatal("the server's own login-page CAPTCHA is still used")
	}

	// A pass lifts a temporary ban (the firewall's CAPTCHA redirect), not a
	// permanent block.
	a.Firewall.AutoBan("198.51.100.7", "test", "waf")
	a.Firewall.Add("deny", "198.51.100.9", "manual", 0)
	pass("198.51.100.7", "shop.example.com")
	pass("198.51.100.9", "shop.example.com")
	check := func(ip string) string { r, _ := a.Firewall.Check(ip); return r.Status }
	if s := check("198.51.100.7"); s == "temp-blocked" {
		t.Fatalf("temporary ban kept after the CAPTCHA: %s", s)
	}
	if s := check("198.51.100.9"); s != "blocked" {
		t.Fatalf("permanent block lifted: %s", s)
	}
}

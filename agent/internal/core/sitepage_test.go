package core

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xmarthost/xmartguard/agent/internal/captcha"
)

// Site mode without port 7743 (2026-11-06): the page on every website's own
// address is set up and used only while its self-test passes; until then
// (or on a server where the web server does not serve the alias) suspects
// keep going through the CAPTCHA port, as before. Another mode removes it.
func TestSiteModeWithoutPortFallsBack(t *testing.T) {
	a := newTestAgent(t, `{"waf":{"enabled":true}}`)
	a.Cfg.ServerID = "15d69a72-653a-47b6-90f6-fde737bce061"
	dir := filepath.Join(t.TempDir(), "verify")
	saved := captcha.SitePageDir
	captcha.SitePageDir = dir
	defer func() { captcha.SitePageDir = saved }()
	ctx := context.Background()
	if err := a.applyCentralConfig(ctx, centralConfig{Version: 5, Enabled: true, URL: "https://captcha.test/v", Minutes: 30, Mode: "site"}); err != nil {
		t.Fatal(err)
	}
	// The WAF apply asks for the alias: wanted, and the page is written.
	conf, on := a.siteAlias()
	if !on || !strings.Contains(conf, "Alias /xpguard-verify/ "+dir+"/") {
		t.Fatalf("alias %v %q", on, conf)
	}
	if _, err := os.Stat(filepath.Join(dir, "index.html")); err != nil {
		t.Fatal("page not installed")
	}
	// Nothing answers on this test machine's 443: the port mode, and why.
	a.syncSitePage(ctx)
	if a.central.sitePage.Load() {
		t.Fatal("site page used although its self-test failed")
	}
	if why, _ := a.central.siteErr.Load().(string); why == "" {
		t.Fatal("no reason recorded")
	}
	if w := a.centralWAF(); w == nil || w.SitePage || !w.Site || w.HTTPSPort != 7743 {
		t.Fatalf("central %+v", w)
	}
	// Not in use: no instant pass (the portal falls back to the pass list).
	old := UserDomainsPath
	UserDomainsPath = filepath.Join(t.TempDir(), "userdomains")
	defer func() { UserDomainsPath = old }()
	os.WriteFile(UserDomainsPath, []byte("shop.example.com: shop\n*: nobody\n"), 0o644)
	sitepass := func(ip, host string) (map[string]any, error) {
		p, _ := json.Marshal(map[string]any{"ip": ip, "host": host, "also": "198.51.100.7", "minutes": 60})
		r, err := a.Handlers()["captcha.sitepass"](ctx, p)
		m, _ := r.(map[string]any)
		return m, err
	}
	if _, err := sitepass("203.0.113.5", "shop.example.com"); err == nil || !strings.Contains(err.Error(), "not in use") {
		t.Fatalf("instant pass without the page: %v", err)
	}
	// In use (as after a passing self-test): no port, and the WAF accepts
	// the pass cookie the page sets.
	a.central.sitePage.Store(true)
	w := a.centralWAF()
	if w == nil || !w.SitePage || w.Site || w.HTTPSPort != 0 || len(w.Slots) != captcha.SiteSlots {
		t.Fatalf("central %+v", w)
	}
	r, err := sitepass("203.0.113.5", "shop.example.com")
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := r["value"].(string)
	if r["cookie"] != captcha.GateCookie || len(tok) != 32 || r["minutes"] != 30 { // the shorter of 60 and the configured 30
		t.Fatalf("instant pass %v", r)
	}
	found := false
	for _, sl := range a.centralWAF().Slots {
		found = found || sl[0] == tok
	}
	if !found {
		t.Fatal("value not accepted by the WAF")
	}
	if _, err := sitepass("203.0.113.5", "evil.example"); err == nil {
		t.Fatal("instant pass for a website that is not here")
	}
	// Portal mode: the page stays (it sets the pass cookie on the way back,
	// no reload per pass); suspects go to the portal, not the page.
	if err := a.applyCentralConfig(ctx, centralConfig{Version: 6, Enabled: true, URL: "https://captcha.test/v", Minutes: 30}); err != nil {
		t.Fatal(err)
	}
	if _, on := a.siteAlias(); !on {
		t.Fatal("alias not wanted in portal mode")
	}
	if w := a.centralWAF(); w == nil || w.SitePage || w.Site || len(w.Slots) != captcha.SiteSlots {
		t.Fatalf("central %+v", w)
	}
	if r, err := sitepass("203.0.113.6", "shop.example.com"); err != nil || len(r["value"].(string)) != 32 {
		t.Fatalf("instant pass in portal mode: %v %v", r, err)
	}
	// One failed check does not take the page out of use (each change of
	// the WAF restarts LiteSpeed); three in a row do.
	for i := 1; i <= 3; i++ {
		a.syncSitePage(ctx) // nothing answers on this machine's 443
		if got := a.central.sitePage.Load(); got != (i < 3) {
			t.Fatalf("check %d failed: in use %v", i, got)
		}
	}
	// The portal's check off: the alias is switched off and the page removed.
	if err := a.applyCentralConfig(ctx, centralConfig{Version: 7, Enabled: false, URL: "https://captcha.test/v", Minutes: 30}); err != nil {
		t.Fatal(err)
	}
	if _, on := a.siteAlias(); on {
		t.Fatal("alias still wanted")
	}
	if a.syncSitePage(ctx); a.central.sitePage.Load() {
		t.Fatal("site page still in use")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("page left behind")
	}
}

// An agent that restarts (an update) writes the WAF rules of the pages'
// last check, not rules without them: an update must not restart the web
// server twice (business500, 2026-11-07: LiteSpeed restarted ~30 s after
// each agent update).
func TestCentralPagesKeptAcrossRestarts(t *testing.T) {
	a := newTestAgent(t, `{"waf":{"enabled":true}}`)
	a.central.sitePage.Store(true)
	a.central.hostPage.Store("https://server1.example.net/xpguard-check/")
	a.central.hostFW.Store("")
	a.saveCentralPages()
	a.central.sitePage.Store(false)
	a.central.hostPage.Store("")
	a.loadCentralPages()
	if hp, _ := a.central.hostPage.Load().(string); !a.central.sitePage.Load() || hp != "https://server1.example.net/xpguard-check/" {
		t.Fatalf("not restored: %v %q", a.central.sitePage.Load(), hp)
	}
}

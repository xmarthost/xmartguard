package core

import (
	"context"
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
	// In use (as after a passing self-test): no port.
	a.central.sitePage.Store(true)
	if w := a.centralWAF(); w == nil || !w.SitePage || w.Site || w.HTTPSPort != 0 {
		t.Fatalf("central %+v", w)
	}
	// Another mode: the alias is switched off and the page removed.
	if err := a.applyCentralConfig(ctx, centralConfig{Version: 6, Enabled: true, URL: "https://captcha.test/v", Minutes: 30}); err != nil {
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
	if w := a.centralWAF(); w != nil && (w.SitePage || w.Site) {
		t.Fatalf("central %+v", w)
	}
}

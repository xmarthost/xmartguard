package waf

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/xmarthost/xmartguard/agent/internal/settings"
)

// LiteSpeed's ModSecurity ignores ctl:ruleRemoveById. Every exemption that
// removes rules is also a tx marker or a chained condition in the rule
// itself, so trusted services, API calls and shop visitors pass on
// LiteSpeed as they do on Apache.
func TestExemptionsWithoutCtl(t *testing.T) {
	c := settings.Defaults().WAF
	c.Enabled, c.IPDBPost, c.BotBlocker, c.Webshell = true, true, true, true
	central := &Central{URL: "https://captcha.xpguard.org/v", ServerID: "15d69a72-653a-47b6-90f6-fde737bce061"}
	out := Render(c, Options{Dir: "/r", Trusted: true, Central: central, VerifiedBots: []string{"googlebot", "bingbot"}})
	next := func(id int) string {
		lines := strings.Split(out, "\n")
		for i, l := range lines {
			if strings.HasPrefix(l, "SecRule ") && strings.Contains(l, fmt.Sprintf("id:%d,", id)) && i+1 < len(lines) {
				return strings.TrimSpace(lines[i+1])
			}
		}
		return ""
	}
	for _, id := range []int{IDRootProbe, IDRootProbe + 1000, IDEmptyUAWP, IDEmptyUAWP + 1000, IDXMLRPCGet, IDCentralGate, IDCentralNoBrowser, IDNoUAPost, IDNoUAPost + 1000, IDFakeSearchBot} {
		if ruleLine(out, id) == "" {
			t.Errorf("rule %d not rendered", id)
		} else if next(id) != `SecRule &TX:xg_trusted "@eq 0" "t:none,chain"` {
			t.Errorf("rule %d does not skip trusted services: %s", id, next(id))
		}
	}
	if strings.Count(out, `SecRule &TX:xg_trusted "@eq 0" "t:none,chain"`) != strings.Count(guardChains(out, `SecRule &TX:xg_trusted "@eq 0" "t:none,chain"`, IDRootProbe, IDFakeSearchBot), `SecRule &TX:xg_trusted "@eq 0" "t:none,chain"`) {
		t.Error("the guard is added twice")
	}
	// Without the trusted list there is nothing to test.
	if plain := Render(c, Options{Dir: "/r"}); strings.Contains(plain[strings.Index(plain, fmt.Sprintf("id:%d,", IDXMLRPCGet)):][:400], "&TX:xg_trusted") {
		t.Error("trusted guard without trusted services")
	}
	// API calls and webhooks: the marker, then the IPDB POST rule tests it.
	if l := strings.Join(chainOf(out, IDIPDBPostAPI), "\n"); !strings.Contains(l, "setvar:tx.xg_api=1") {
		t.Errorf("API calls not marked: %s", l)
	}
	for _, id := range []int{IDIPDBPost, IDIPDBPost + 1000} {
		i := strings.Index(out, fmt.Sprintf("id:%d,", id))
		if i < 0 || !strings.Contains(out[i:i+400], `SecRule &TX:xg_api "@eq 0"`) {
			t.Errorf("IPDB POST rule %d does not skip API calls", id)
		}
	}
	if i := strings.Index(out, fmt.Sprintf("id:%d,", IDTorPost)); i < 0 || strings.Contains(out[i:i+400], "xg_api") {
		t.Error("Tor POST rule must not skip API calls")
	}
	for _, id := range []int{IDShopScrape, IDShopScrape + 1000} {
		if next(id) != `SecRule &TX:xg_same_origin "@eq 0" "t:none,chain"` || !strings.Contains(strings.Join(chainOf(out, IDShopScrape+2000), "\n"), "setvar:tx.xg_same_origin=1") {
			t.Errorf("shop rule %d does not skip same-site browsing: %s", id, next(id))
		}
	}
}

// On a real Apache with every ctl:ruleRemoveById taken out of xPGuard's
// rules (what LiteSpeed does): a trusted service, an API call and a
// shopper moving within the site still pass; others are still blocked.
func TestExemptionsOnApacheWithoutCtl(t *testing.T) {
	m, send := apacheWith(t, `{"waf":{"upload_scan":false,"ipdb_post":true,"tor_action":"off","wordpress":true,"bad_bots":true}}`)
	listed := []string{"127.0.0.1"}
	trusted := []string{"192.0.2.0/24"}
	m.IPDBIPs = func() []string { return listed }
	m.TrustedIPs = func() []string { return trusted }
	// The shop rule is approved (new rules only log until then).
	m.Intel = func() *Intel { return &Intel{Enforce: []int{IDShopScrape}} }
	os.WriteFile("/var/www/html/xg-ok.html", []byte("ok"), 0o644)
	defer os.Remove("/var/www/html/xg-ok.html")
	reCtl := regexp.MustCompile(`,ctl:ruleRemoveById=[0-9-]+`)
	apply := func() {
		t.Helper()
		if err := m.Apply(); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(m.RulesDir, "rules.conf")
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		os.WriteFile(p, reCtl.ReplaceAll(b, nil), 0o644)
		if err := exec.Command("apache2ctl", "graceful").Run(); err != nil {
			t.Fatal(err)
		}
		waitApache()
	}
	apply()
	if b, _ := os.ReadFile(filepath.Join(m.RulesDir, "rules.conf")); strings.Contains(string(b), "ruleRemoveById") {
		t.Fatal("ctl still in the rules")
	}
	check := func(what string, blocked bool, code int) {
		t.Helper()
		if (code == 403) != blocked {
			t.Errorf("%s: %d", what, code)
		}
	}
	check("POST from a listed address", true, send("POST", "/xg-ok.html"))
	check("API call from a listed address", false, send("POST", "/xg-ok.html", "Authorization: Bearer abc.def"))
	check("signed webhook from a listed address", false, send("POST", "/xg-ok.html", "Stripe-Signature: t=1,v1=abc"))
	check("API call behind a proxy", false, send("POST", "/xg-ok.html", "X-Forwarded-For: 127.0.0.1", "X-Api-Key: k1"))
	check("GET to xmlrpc.php", true, send("GET", "/xmlrpc.php"))
	check("shop filter scraping", true, send("GET", "/xg-ok.html?filter_color=a,b,c"))
	check("shopper moving within the site", false, send("GET", "/xg-ok.html?filter_color=a,b,c", "Sec-Fetch-Site: same-origin"))
	// The filter botnet of blacksoulltd.com (business900, 2026-10-22): three
	// filters, browser User-Agent, no cookies, a Referer of the site.
	flood := "/xg-ok.html?filter_cat=pants&filter_color=red&filter_size=3xl"
	check("filter flood with a forged Referer", true, send("GET", flood, "Referer: https://shop.example.com/shop/"))
	check("filter flood claiming same-site from another site", true, send("GET", flood, "Sec-Fetch-Site: same-origin", "Referer: https://evil.example/"))
	check("shopper clicking a filter on the site", false, send("GET", flood, "Sec-Fetch-Site: same-origin", "Referer: https://shop.example.com/shop/"))
	check("shopper with a cookie", false, send("GET", flood, "Cookie: woocommerce_items_in_cart=1"))
	check("one filter value from a link", false, send("GET", "/xg-ok.html?filter_color=red"))
	// The same request from a trusted service (Jetpack, a monitor).
	trusted = []string{"127.0.0.0/8"}
	apply()
	check("GET to xmlrpc.php from a trusted service", false, send("GET", "/xmlrpc.php"))
}

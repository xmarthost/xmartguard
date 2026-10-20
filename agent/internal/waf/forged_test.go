package waf

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/xmarthost/xmartguard/agent/internal/settings"
)

// rxOf returns the @rx pattern of a rendered rule line.
func rxOf(t *testing.T, line string) *regexp.Regexp {
	t.Helper()
	m := regexp.MustCompile(`"!?@rx (.*?)" "`).FindStringSubmatch(line)
	if m == nil {
		t.Fatalf("no @rx in %q", line)
	}
	return regexp.MustCompile(m[1])
}

// chainOf returns the rendered lines of the rule with this id (the first
// line and its chained links).
func chainOf(out string, id int) []string {
	lines := strings.Split(out, "\n")
	for i, l := range lines {
		if strings.HasPrefix(l, "SecRule ") && strings.Contains(l, fmt.Sprintf("id:%d,", id)) {
			c := []string{l}
			for j := i; strings.HasSuffix(lines[j], `,chain"`) && j+1 < len(lines); j++ {
				c = append(c, strings.TrimSpace(lines[j+1]))
			}
			return c
		}
	}
	return nil
}

// Audit A3 F1: the WordPress login cookie, the WP nonce, Sec-Fetch-Site,
// the Referer and the WHMCS cookie are sent by the client, so anyone can
// send them. They may relax HTML and scripts (what editors save), but never
// switch the OWASP CRS off for any address of any site.
func TestForgedEditorMarkers(t *testing.T) {
	setup := wpAreaSetup() + sessionSetup() + editorSetup() + autodiscoverSetup()
	// The admin and REST API are known by the script path and the
	// rest_route argument of the front controller, never by text anywhere
	// in the address (…/shop.php?id=1…&rest_route=).
	if strings.Contains(editorSetup(), "REQUEST_URI") || strings.Contains(editorSetup(), "rest_route=") {
		t.Fatal("editor rules read the address text")
	}
	for _, id := range []int{IDEditorCookie, IDEditorCookie + 1000, IDEditorAdmin} {
		if c := chainOf(setup, id); len(c) == 0 || !strings.HasPrefix(c[0], `SecRule TX:xg_wp_area "@eq 1"`) {
			t.Errorf("editor rule %d is not keyed on the WordPress area: %v", id, c)
		}
	}
	if c := chainOf(setup, IDEditorAuth); len(c) == 0 || !strings.HasPrefix(c[0], `SecRule TX:xg_wp_rest "@eq 1"`) {
		t.Errorf("application password rule is not keyed on the REST API: %v", c)
	}
	admin := rxOf(t, chainOf(setup, IDWPArea)[0])
	rest := rxOf(t, chainOf(setup, IDWPArea+1000)[0])
	front := rxOf(t, chainOf(setup, IDWPArea+2000)[1])
	for p, want := range map[string]bool{"/wp-admin/admin-ajax.php": true, "/blog/wp-admin/post.php": true, "/shop.php": false, "/wp-admin.php": false} {
		if admin.MatchString(p) != want {
			t.Errorf("wp-admin %s: %v", p, !want)
		}
	}
	for p, want := range map[string]bool{"/wp-json/wp/v2/posts": true, "/blog/wp-json/x/v1/y": true, "/shop.php": false} {
		if rest.MatchString(p) != want {
			t.Errorf("wp-json %s: %v", p, !want)
		}
	}
	for p, want := range map[string]bool{"/": true, "/index.php": true, "/blog/": true, "/shop.php": false, "/wp-login.php": false} {
		if front.MatchString(p) != want {
			t.Errorf("?rest_route= on %s: %v", p, !want)
		}
	}
	// Screens WordPress checks the login of first: not admin-ajax.php,
	// admin-post.php or async-upload.php (plugin hooks run for visitors).
	core := chainOf(setup, IDWPCore)
	screen, notAjax := rxOf(t, core[0]), rxOf(t, core[1])
	for p, want := range map[string]bool{"/wp-admin/post.php": true, "/wp-admin/": true, "/wp-admin/admin-ajax.php": false, "/wp-admin/admin-post.php": false, "/wp-admin/async-upload.php": false} {
		if (screen.MatchString(p) && !notAjax.MatchString(p)) != want {
			t.Errorf("core screen %s: %v", p, !want)
		}
	}
	// After the CRS: SQL, command, PHP and file inclusion attacks in a
	// relaxed request outside those screens are refused at the level's
	// threshold.
	post := sessionPost(10)
	c := chainOf(post, IDEditorCap)
	if len(c) != 3 || !strings.HasPrefix(c[0], `SecRule TX:xg_editor "@eq 1"`) || !strings.Contains(c[0], ",deny,") ||
		c[1] != `SecRule &TX:xg_wp_core "@eq 0" "t:none,chain"` || c[2] != `SecRule `+editorCapScores+` "@ge 10" "t:none"` {
		t.Errorf("editor cap: %q", c)
	}
	// A new blocking rule: it watches until approved in the portal.
	if l := chainOf(applyMonitor(post, Monitored(nil)), IDEditorCap)[0]; strings.Contains(l, "deny") || !strings.Contains(l, "[watch]") {
		t.Errorf("editor cap does not watch before approval: %s", l)
	}
	if l := chainOf(applyMonitor(post, Monitored((&Intel{Enforce: []int{IDEditorCap}}).Clean())), IDEditorCap)[0]; !strings.Contains(l, "deny,status:403") {
		t.Errorf("approved editor cap does not block: %s", l)
	}
	// Every relaxation to editorThreshold sets xg_editor, so the cap applies.
	// (Outlook's Autodiscover post is answered by cPanel, not a website.)
	for _, l := range strings.Split(sessionSetup()+editorSetup(), "\n") {
		if strings.Contains(l, fmt.Sprintf("threshold=%d", editorThreshold)) && !strings.Contains(l, "xg_editor=1") {
			t.Errorf("relaxed without the editor marker: %s", l)
		}
	}
	for _, id := range []int{IDWHMCSArea, IDWHMCSArea + 1000, IDAdminArea} {
		if c := chainOf(setup, id); len(c) == 0 || !strings.Contains(c[len(c)-1], "setvar:tx.xg_editor=1") {
			t.Errorf("rule %d relaxes without the editor marker: %v", id, c)
		}
	}

	cfg := settings.Defaults().WAF
	cfg.Enabled, cfg.IPDBPost, cfg.TorAction = true, true, "post"
	out := Render(cfg, Options{Dir: "/r"})
	// The rules.conf markers come before anything that tests them.
	if !strings.Contains(out, wpAreaSetup()) {
		t.Error("WordPress area markers missing from the rules")
	}
	// Forgeable markers outside the wp-admin screens take out the XSS rules
	// only (Apache honours the removal); WHMCS is never let through whole.
	for _, id := range []int{IDWPAjaxExcl, IDWPCustomizer, IDAdminPanel, IDWHMCSAdmin, IDWHMCSAdminFetch} {
		c := chainOf(out, id)
		if len(c) == 0 {
			t.Fatalf("rule %d not rendered", id)
		}
		last := c[len(c)-1]
		if !strings.Contains(last, removeXSS()) || strings.Contains(last, "attack-sqli") || strings.Contains(last, "930000") || strings.Contains(strings.Join(c, "\n"), "allow") || strings.Contains(last, "ruleEngine") {
			t.Errorf("rule %d removes more than the XSS rules: %v", id, c)
		}
	}
	// IPDB and Tor POST blocks: only the WordPress admin and REST API skip
	// them for a login cookie (not wp-login.php, forms or other pages).
	for _, id := range []int{IDIPDBPost, IDIPDBPost + 1000, IDTorPost, IDTorPost + 1000} {
		c := strings.Join(chainOf(out, id), "\n")
		if !strings.Contains(c, `&TX:xg_wp_editing "@eq 0"`) || strings.Contains(c, "xg_wp_user") {
			t.Errorf("rule %d: %s", id, c)
		}
	}
	if c := chainOf(out, IDWPEditing); len(c) != 2 || !strings.Contains(c[0], "TX:xg_wp_user") || !strings.Contains(c[1], "TX:xg_wp_area") {
		t.Errorf("editing marker: %v", c)
	}
}

// On Apache with the OWASP CRS: forged editor markers (a made-up
// wordpress_logged_in_<32 hex> cookie, Sec-Fetch-Site, a same-host wp-admin
// Referer, an application password, a WHMCS cookie) with an obvious attack
// still get 403, on any page, on admin-ajax.php, the REST API and admin
// areas. Run as root with XG_DESTRUCTIVE_TESTS=1 and XG_CRS_DIR.
func TestForgedEditorMarkersWithCRS(t *testing.T) {
	src := os.Getenv("XG_CRS_DIR")
	if src == "" {
		t.Skip("set XG_CRS_DIR to an OWASP CRS 4 checkout")
	}
	crsManager(t, src, `{"waf":{"enabled":true,"wordpress":true,"generic":true,"level":"normal"}}`, "off", func(m *Manager) {
		m.Intel = func() *Intel { return &Intel{Enforce: []int{IDEditorCap}} }
	})
	form := "application/x-www-form-urlencoded"
	probe := crsProbeQuery()
	cookie := "Cookie: wordpress_logged_in_00000000000000000000000000000000=x"
	same := "Sec-Fetch-Site: same-origin"
	own := "Referer: https://site.example.com/wp-admin/post.php"
	cases := []struct {
		name, method, uri, body string
		hdr                     []string
	}{
		{"any page with &rest_route=", "GET", "/shop.php?" + probe + "&rest_route=", "", []string{cookie, same, own}},
		{"front page with ?rest_route=", "GET", "/?rest_route=/x/v1/y&" + probe, "", []string{cookie, same, own}},
		{"admin-ajax.php", "POST", "/wp-admin/admin-ajax.php", "action=nopriv_x&" + probe, []string{cookie, same, own, "X-WP-Nonce: 0a1b2c3d4e"}},
		{"plugin REST route with an application password", "POST", "/wp-json/plugin/v1/x", "a=1&" + probe, []string{"Authorization: Bearer abcdefghijkl", cookie, same, own}},
		{"admin area of another application", "POST", "/admin/save.php", probe, []string{"Cookie: PHPSESSID=abc", same, "Referer: https://site.example.com/admin/"}},
		{"WHMCS-looking admin page", "POST", "/x/config.php", probe, []string{"Cookie: WHMCSabcdefgh=1", same, "Referer: https://site.example.com/x/"}},
	}
	for _, c := range cases {
		ctype := ""
		if c.body != "" {
			ctype = form
		}
		if got := sendBody(t, "site.example.com", c.method, c.uri, ctype, c.body, c.hdr...); got != 403 {
			t.Errorf("%s: got %d, want 403", c.name, got)
		}
	}
}

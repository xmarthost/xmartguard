package waf

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/settings"
)

func TestExclusionsRender(t *testing.T) {
	c := settings.WAF{RuleExclusions: []settings.RuleExclusion{
		{Rule: 941100, Domain: "Morningmobility.fit", Path: "/wp-admin/admin.php"},
		{Rule: 942100, Domain: "*.example.com"},
		{Rule: 7700506, Path: "/api/"},
		{Rule: 949110},
		{Rule: 1, Domain: "bad domain\""},                                          // dropped
		{Rule: 2, Path: "/x\" ctl:ruleEngine=Off"},                                 // dropped
		{Rule: 941100, Domain: "morningmobility.fit", Path: "/wp-admin/admin.php"}, // duplicate
	}}
	out := Render(c, Options{Dir: "/r"})
	for _, want := range []string{
		`"id:7700010,`, `"id:7700011,`, `"id:7700012,`, "ctl:ruleRemoveByTag=attack-xss",
		`SecRule SERVER_NAME "@rx ^(?:www\.)?morningmobility\.fit$" "id:7704000,`,
		`SecRule REQUEST_FILENAME "@beginsWith /wp-admin/admin.php" "t:none,t:urlDecodeUni,ctl:ruleRemoveById=941100"`,
		`SecRule SERVER_NAME "@rx ^(?:[^.]+\.)*example\.com$" "id:7704001,phase:1,t:none,t:lowercase,pass,nolog,ctl:ruleRemoveById=942100"`,
		`SecRule REQUEST_FILENAME "@beginsWith /api/" "id:7704002,phase:1,t:none,t:urlDecodeUni,pass,nolog,ctl:ruleRemoveById=7700506"`,
		`SecAction "id:7704003,phase:1,pass,nolog,ctl:ruleRemoveById=949110"`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in\n%s", want, out)
		}
	}
	if strings.Contains(out, "id:7704004") || strings.Contains(out, `/x" ctl`) || strings.Contains(out, "bad domain") {
		t.Fatalf("invalid or duplicate exclusion rendered:\n%s", out)
	}
	// cPanel's service subdomains, mail client setup and attendance devices.
	for _, want := range []string{
		`SecRule SERVER_NAME "@rx ^(?:cpanel|whm|webmail|webdisk|cpcalendars|cpcontacts)\." "id:7700020,phase:1,t:none,t:lowercase,pass,nolog,ctl:ruleEngine=Off"`,
		`cgi-sys/+(?:autodiscover|autoconfig)\.cgi$" "id:7700021,`,
		`iclock/+(?:cdata|getrequest|devicecmd|registry|push|ping|querydata|fdata)(?:\.aspx|\.php)?$" "id:7700022,phase:1,t:none,t:urlDecodeUni,t:lowercase,pass,nolog,ctl:ruleRemoveById=920420,`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q", want)
		}
	}
	// The exclusions come first: the whitelist would otherwise remove them.
	if i, j := strings.Index(out, "id:7700010"), strings.Index(out, "id:7700309"); i < 0 || (j >= 0 && i > j) {
		t.Fatal("exclusions are not at the top")
	}
	// Switched off like any other rule.
	c.DisabledRules = []int{IDWPAdminExcl}
	if strings.Contains(Render(c, Options{Dir: "/r"}), `"id:7700010,`) {
		t.Fatal("disabled exclusion rendered")
	}
	// Kept when our rules are off.
	if !strings.Contains(RenderExclusionsOnly(c, Dynamic{}), "id:7700012") {
		t.Fatal("exclusions missing without our rules")
	}
}

// TestExclusionsWithCRS sends the requests of the two support tickets through
// Apache, ModSecurity and a real OWASP CRS 4 release (XG_CRS_DIR, a clone of
// github.com/coreruleset/coreruleset).
func TestExclusionsWithCRS(t *testing.T) {
	src := os.Getenv("XG_CRS_DIR")
	if src == "" {
		t.Skip("set XG_CRS_DIR to an OWASP CRS 4 checkout")
	}
	// Blocking as the CRS does it: these cases test the exclusions.
	m := crsManager(t, src, `{"waf":{"enabled":true,"wordpress":true,"generic":true,"bad_bots":true,"rule_exclusions":[{"rule":949110,"domain":"allowed.example.com","path":"/form/"}]}}`, "off", nil)

	adsense := `<script async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=ca-pub-1234567890"></script><script>document.write(document.cookie)</script>`
	wpcode := "ihaf_insert_header=" + urlEncode(adsense) + "&submit=Save+Changes"
	page := `{"title":"Hello","content":"<p>Offer</p>` + strings.ReplaceAll(adsense, `"`, `\"`) + `","status":"publish"}`
	cookie := "Cookie: wordpress_logged_in_abc123=admin%7C1700000000%7Ctoken; wp-settings-1=x"
	form, json := "application/x-www-form-urlencoded", "application/json"

	cases := []struct {
		name, host, method, uri, ctype, body string
		hdr                                  []string
		want                                 int
	}{
		{"CRS still blocks the attack for visitors", "shop.example.com", "POST", "/contact/", form, wpcode, nil, 403},
		{"WPCode Header & Footer save (logged in)", "shop.example.com", "POST", "/wp-admin/admin.php?page=wpcode-headers-footers", form, wpcode, []string{cookie}, 200},
		{"WPCode save without login stays blocked", "shop.example.com", "POST", "/wp-admin/admin.php?page=wpcode-headers-footers", form, wpcode, nil, 403},
		{"Editor save through admin-ajax", "shop.example.com", "POST", "/wp-admin/admin-ajax.php", form, "action=elementor_ajax&data=" + urlEncode(adsense), []string{cookie, "Referer: https://shop.example.com/wp-admin/post.php?post=1&action=elementor"}, 200},
		{"admin-ajax from outside the admin stays inspected", "shop.example.com", "POST", "/wp-admin/admin-ajax.php", form, "action=x&data=" + urlEncode(adsense), []string{cookie}, 403},
		{"REST page write (application password)", "shop.example.com", "POST", "/wp-json/wp/v2/pages", json, page, []string{"Authorization: Basic YWRtaW46eHh4eCB4eHh4"}, 200},
		{"REST page update, rest_route form", "shop.example.com", "POST", "/?rest_route=/wp/v2/pages/12", json, page, nil, 200},
		{"Plugin REST route stays inspected", "shop.example.com", "POST", "/wp-json/someplugin/v1/save", json, page, nil, 403},
		{"Comments route stays inspected", "shop.example.com", "POST", "/wp-json/wp/v2/comments", json, page, nil, 403},
		// From the WAF log of a live server.
		{"WooCommerce block checkout (method override)", "shop.example.com", "POST", "/wp-json/wc/store/v1/checkout?__experimental_calc_totals=true&_locale=site", json, `{"payment_method":"stripe"}`, []string{"X-HTTP-Method-Override: PUT", "Nonce: abc"}, 200},
		{"WooCommerce checkout note with PHP words", "shop.example.com", "POST", "/wp-json/wc/store/v1/checkout?_locale=site", json, `{"customer_note":"Please passthru the parcel to reception, phpinfo desk"}`, nil, 200},
		{"Elementor saves with PUT", "shop.example.com", "PUT", "/solar/wp-json/elementor/v1/global-classes?context=preview", json, `{"items":{}}`, nil, 200},
		{"Elementor saves with DELETE", "shop.example.com", "DELETE", "/wp-json/elementor/v1/global-classes?context=frontend", json, `{}`, nil, 200},
		{"PUT is an allowed method (API apps of customers)", "shop.example.com", "PUT", "/api/vouchers/11764", json, `{"amount":100}`, nil, 200},
		{"Method override outside the REST API stays refused", "shop.example.com", "POST", "/contact/", form, "a=1", []string{"X-HTTP-Method-Override: PUT"}, 403},
		{"ViserLab colour stylesheet", "shop.example.com", "GET", "/assets/templates/metro_hyip/css/color.php?base_color=f60233&secondary_color=000000", "", "", nil, 200},
		{"PHP in a css folder stays blocked", "shop.example.com", "GET", "/assets/templates/metro_hyip/css/shell.php", "", "", nil, 403},
		{"Bare Mozilla/5.0 is still a bot", "shop.example.com", "GET", "/", "", "", []string{"User-Agent: Mozilla/5.0"}, 403},
		{"Bare Mozilla/5.0 with WordPress login", "shop.example.com", "GET", "/wp-admin/", "", "", []string{"User-Agent: Mozilla/5.0", cookie}, 200},
		// Hosting defaults (WAF log of a live shared server).
		{"Comment in Urdu with emoji", "shop.example.com", "POST", "/wp-comments-post.php", form, "comment=" + urlEncode("<b>بہت</b> اچھا پروڈکٹ، size ½ 👍 شکریہ") + "&author=Ali&email=a%40b.pk&comment_post_ID=12", nil, 200},
		{"Script in a comment stays blocked", "shop.example.com", "POST", "/wp-comments-post.php", form, "comment=" + urlEncode(adsense) + "&comment_post_ID=12", nil, 403},
		{"Outlook autodiscover by the server address", "203.0.113.10", "POST", "/cgi-sys/autodiscover.cgi", "text/xml", "<Autodiscover/>", nil, 200},
		{"robots.txt with a charset in Accept", "shop.example.com", "GET", "/robots.txt", "", "", []string{"Accept: text/html; charset=us-ascii"}, 200},
		{"Image with a JSON consent cookie", "shop.example.com", "GET", "/wp-content/uploads/2026/09/toy.png", "", "", []string{`Cookie: consent={"necessary":true,"analytics":false}; cart=1 union select 1`}, 200},
		{"SMM panel admin imports services", "smm.example.com", "POST", "/admin/api-services/ajax_services_add", form, "name=" + urlEncode("TikTok | Views 🔥 <b>New</b>") + "&desc=" + urlEncode(adsense), []string{"Cookie: PHPSESSID=abc", "Referer: https://smm.example.com/admin/api-services"}, 200},
		{"Admin POST from another site stays inspected", "smm.example.com", "POST", "/admin/api-services/ajax_services_add", form, "desc=" + urlEncode(adsense), []string{"Cookie: PHPSESSID=abc", "Referer: https://evil.example.net/admin/x"}, 403},
		{"Admin POST without a session stays inspected", "smm.example.com", "POST", "/admin/api-services/ajax_services_add", form, "desc=" + urlEncode(adsense), []string{"Referer: https://smm.example.com/admin/api-services"}, 403},
		// Blocked for visitors from a whitelisted country, and for everyone else too (WAF logs of two live servers).
		{"WooCommerce classic checkout (wc-ajax)", "shop.example.com", "POST", "/?wc-ajax=update_order_review", form, "security=abc&post_data=" + urlEncode("billing_first_name=Ali&order_comments=Please passthru the parcel to reception, phpinfo desk"), nil, 200},
		{"Cart fragments with JSON", "shop.example.com", "POST", "/?wc-ajax=get_refreshed_fragments", form, "time=1&data=" + urlEncode(`{"ids":"[12,13]","url":"/shop/?p=1"}`), nil, 200},
		{"Shop tracking JSON", "shop.example.com", "POST", "/wp-json/commercekit/v1/track/impressions", form, "ids=" + urlEncode(`{"ids":"[12,13]","url":"/shop/?p=1"}`), nil, 200},
		{"Password with $ and brackets (WHMCS admin login)", "shop.example.com", "POST", "/client-area/admin/dologin.php", form, "username=admin&password=" + urlEncode("Kh$an(2026)!"), nil, 200},
		{"Customizer preview of a logged-in user", "shop.example.com", "POST", "/product/toy/?customize_changeset_uuid=6bbcb5ac-be4e-401b-95a1-e58ad5000001&customize_autosaved=on", form, "customized=" + urlEncode(`{"custom_html":"`+adsense+`"}`), []string{cookie}, 200},
		{"Customizer preview without login stays inspected", "shop.example.com", "POST", "/product/toy/?customize_changeset_uuid=6bbcb5ac-be4e-401b-95a1-e58ad5000001", form, "customized=" + urlEncode(adsense), nil, 403},
		{"Block editor autosave with page HTML", "shop.example.com", "POST", "/wp-json/wp/v2/pages/104/autosaves?_locale=user", json, `{"content":"<meta name=\"x\" content=\"y\"><p>Hi</p>"}`, []string{cookie}, 200},
		{"Meta Conversions API bridge (sendBeacon)", "shop.example.com", "POST", "/?ob=open-bridge/events", "text/plain;charset=UTF-8", `{"event":"PageView"}`, nil, 200},
		{"Theme colour stylesheet", "shop.example.com", "GET", "/assets/theme/theme3/frontend/css/color.php?primary_color=F7931A", "", "", nil, 200},
		{"WordPress theme colour stylesheet", "shop.example.com", "GET", "/wp-content/themes/acuasafe/assets/css/color.php?main_color=0f172a&ver=7.1.3", "", "", nil, 200},
		{"color.php without a colour stays blocked", "shop.example.com", "GET", "/assets/theme/theme3/frontend/css/color.php?file=list", "", "", nil, 403},
		{"Block editor asks who is logged in", "shop.example.com", "GET", "/wp-json/wp/v2/users/me?context=edit&_locale=user", "", "", nil, 200},
		{"REST user list stays blocked", "shop.example.com", "GET", "/wp-json/wp/v2/users?per_page=100&_fields=slug", "", "", nil, 403},
		{"REST user list, rest_route form", "shop.example.com", "GET", "/?rest_route=/wp/v2/users&per_page=100&_fields=slug", "", "", nil, 403},
		{"REST user list hidden behind /users/me", "shop.example.com", "GET", "/?rest_route=/wp/v2/users/me&rest_route=/wp/v2/users", "", "", nil, 403},
		{"REST user by number stays blocked", "shop.example.com", "GET", "/wp-json/wp/v2/users/1", "", "", nil, 403},
		{"Bare Mozilla/5.0 API client with credentials", "shop.example.com", "GET", "/wp-json/wp/v2/pages", "", "", []string{"User-Agent: Mozilla/5.0", "Authorization: Basic YWRtaW46eHh4eCB4eHh4"}, 200},
	}
	for _, c := range cases {
		// Allowed requests reach Apache (404 here: no WordPress behind it).
		if got := sendBody(t, c.host, c.method, c.uri, c.ctype, c.body, c.hdr...); (got == 403) != (c.want == 403) || got == 0 {
			t.Errorf("%s: %s %s got %d, want %d", c.name, c.method, c.uri, got, c.want)
		}
	}
	// The per-site exclusion: the rule that blocked a harmless script tag.
	xss := "q=" + urlEncode(`<script>alert(1)</script>`)
	if sendBody(t, "shop.example.com", "POST", "/form/", form, xss) != 403 {
		t.Fatal("test attack not blocked")
	}
	if got := sendBody(t, "allowed.example.com", "POST", "/form/", form, xss); got == 403 {
		t.Fatal("per-site exclusion not applied")
	}
	if sendBody(t, "allowed.example.com", "POST", "/other/", form, xss) != 403 {
		t.Fatal("per-site exclusion applied outside its path")
	}
	// Control: without the exclusion the ticket's request is blocked.
	m.Settings.Patch([]byte(`{"waf":{"disabled_rules":[7700010,7700012,7700013,7700014,7700015,7700016,7700017,7700018,7700023,7700024,7700025,7700026]}}`))
	if err := m.Apply(); err != nil {
		t.Fatal(err)
	}
	waitApache()
	if sendBody(t, "shop.example.com", "POST", "/wp-admin/admin.php?page=wpcode-headers-footers", form, wpcode, cookie) != 403 {
		t.Fatal("WPCode save passes even without the exclusion: the test proves nothing")
	}
	for _, c := range []struct {
		uri, ctype, body string
		hdr              []string
	}{
		{"/wp-json/wc/store/v1/checkout?_locale=site", json, `{"customer_note":"Please passthru the parcel to reception, phpinfo desk"}`, nil},
		{"/wp-json/wc/store/v1/checkout?__experimental_calc_totals=true", json, `{"payment_method":"stripe"}`, []string{"X-HTTP-Method-Override: PUT"}},
	} {
		if sendBody(t, "shop.example.com", "POST", c.uri, c.ctype, c.body, c.hdr...) != 403 {
			t.Fatalf("%s passes even without the exclusion", c.uri)
		}
	}
	for _, c := range cases {
		proves := false
		for _, n := range []string{"Urdu", "consent cookie", "SMM panel", "robots.txt", "classic checkout", "Cart fragments", "Shop tracking",
			"Password with", "Customizer preview of", "editor autosave", "colour stylesheet"} {
			// Not "Meta Conversions": its text/plain beacon is an allowed
			// content type for every site since 0.22.0.
			proves = proves || strings.Contains(c.name, n)
		}
		if proves && c.name != "ViserLab colour stylesheet" {
			if got := sendBody(t, c.host, c.method, c.uri, c.ctype, c.body, c.hdr...); got != 403 {
				t.Errorf("%s passes even without the hosting defaults (%d)", c.name, got)
			}
		}
	}
}

// crsManager starts Apache with our rules and the OWASP CRS release in src.
func crsManager(t *testing.T, src, patch, soft string, setup func(*Manager)) *Manager {
	t.Helper()
	m, _ := apacheWith(t, patch)
	if !strings.Contains(patch, `"level"`) {
		// These tests check single rules at the CRS's own threshold.
		m.Settings.Patch([]byte(`{"waf":{"level":"strict"}}`))
	}
	if setup != nil {
		setup(m)
	}
	files := map[string]string{}
	b, err := os.ReadFile(filepath.Join(src, "crs-setup.conf.example"))
	if err != nil {
		t.Fatal(err)
	}
	files["crs-setup.conf.example"] = string(b)
	all, _ := filepath.Glob(filepath.Join(src, "rules", "*"))
	for _, f := range all {
		b, _ := os.ReadFile(f)
		files["rules/"+filepath.Base(f)] = string(b)
	}
	if err := m.InstallCRS("4.18.0", files); err != nil {
		t.Fatal(err)
	}
	var rs RuleSets
	rs.CRS.Enabled, rs.CRS.Version, rs.CRS.SoftBlock = true, "4.18.0", soft
	// Debian ships no modsecurity.conf here: the JSON body parser of cPanel's.
	rs.Custom.Enabled = true
	rs.Custom.Rules = `SecRule REQUEST_HEADERS:Content-Type "^application/json" "id:200001,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"`
	m.SetRuleSets(rs)
	if err := m.Apply(); err != nil {
		t.Fatal(err)
	}
	waitApache()
	return m
}

// TestSoftBlockWithCRS: one weak signal in a page view of a visitor with a
// clean reputation brings the CAPTCHA page, not a 403; POST requests, real
// attacks and IPDB-listed visitors (also behind Cloudflare) are refused,
// visitors who solved the CAPTCHA pass. And cPanel's per-website switch
// turns everything off for that website.
func TestSoftBlockWithCRS(t *testing.T) {
	src := os.Getenv("XG_CRS_DIR")
	if src == "" {
		t.Skip("set XG_CRS_DIR to an OWASP CRS 4 checkout")
	}
	udata := t.TempDir()
	old := CPanelUserdata
	CPanelUserdata = udata
	defer func() { CPanelUserdata = old }()
	os.MkdirAll(filepath.Join(udata, "std/2_4/xenova/demo.xenovatech.co"), 0o755)
	os.WriteFile(filepath.Join(udata, "std/2_4/xenova/demo.xenovatech.co/modsec.conf"), []byte("<IfModule mod_security2.c>\nSecRuleEngine Off\n</IfModule>\n"), 0o644)
	var listed, passed, trusted []string
	m := crsManager(t, src, `{"waf":{"enabled":true,"wordpress":true,"webshell":true}}`, "", func(m *Manager) {
		m.IPDBIPs = func() []string { return listed }
		m.TrustedIPs = func() []string { return trusted }
		m.Central = func() *Central {
			return &Central{URL: "https://captcha.xpguard.test/v", ServerID: "49c5f26a-f37e-40e0-9eed-62ef53a8a85a", Pass: passed}
		}
	})
	reload := func() {
		if err := m.Apply(); err != nil {
			t.Fatal(err)
		}
		waitApache()
	}
	reload()
	weak := "/?s=1%27%20or%20%271%27%3D%271" // one rule (942100), score 5
	weakBody := "s=1%27%20or%20%271%27%3D%271"
	strong := "/?q=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E" // several rules
	// Page views of a browser (it accepts HTML); scripts are checked below.
	get := func(host, uri string, hdr ...string) int {
		return sendBody(t, host, "GET", uri, "", "", append([]string{"Accept: text/html,application/xhtml+xml,*/*;q=0.8"}, hdr...)...)
	}
	post := func(hdr ...string) int {
		return sendBody(t, "shop.example.com", "POST", "/contact/", "application/x-www-form-urlencoded", weakBody, hdr...)
	}
	check := func(name string, got, want int) {
		t.Helper()
		if (want == 403 && got != 403) || (want == 302 && got != 302) || (want == 200 && (got == 403 || got == 302 || got == 0)) {
			t.Errorf("%s: got %d, want %d", name, got, want)
		}
	}
	check("weak signal, clean visitor: CAPTCHA", get("shop.example.com", weak), 302)
	check("weak signal behind Cloudflare: CAPTCHA", get("shop.example.com", weak, "CF-Connecting-IP: 198.51.100.9"), 302)
	check("weak signal from a script (not a browser): 403, no CAPTCHA", get("shop.example.com", weak, "Accept: */*"), 403)
	check("weak signal in a POST: refused", post(), 403)
	check("real attack: refused", get("shop.example.com", strong), 403)
	check("normal page", get("shop.example.com", "/?s=shoes"), 200)

	listed = []string{"198.51.100.0/24"}
	reload()
	check("IPDB-listed behind Cloudflare: refused", get("shop.example.com", weak, "CF-Connecting-IP: 198.51.100.9"), 403)
	listed = []string{"127.0.0.1"}
	reload()
	check("IPDB-listed: refused", get("shop.example.com", weak), 403)

	listed, passed = nil, []string{"127.0.0.1"}
	reload()
	check("solved the CAPTCHA: weak GET passes", get("shop.example.com", weak), 200)
	check("solved the CAPTCHA: weak POST passes", post(), 200)
	check("solved the CAPTCHA: real attack still refused", get("shop.example.com", strong), 403)

	// Trusted services (search and link-preview bots) are never sent to
	// the CAPTCHA: a weak signal passes, a real attack is still refused.
	passed, trusted = nil, []string{"127.0.0.1"}
	reload()
	check("trusted service: weak GET passes (no CAPTCHA)", get("shop.example.com", weak, "User-Agent: facebookexternalhit/1.1"), 200)
	check("trusted service: weak POST passes", post(), 200)
	check("trusted service: real attack still refused", get("shop.example.com", strong), 403)
	trusted = nil
	reload()
	check("no longer trusted: CAPTCHA again", get("shop.example.com", weak), 302)

	check("cPanel switched ModSecurity off: attack passes there", get("demo.xenovatech.co", strong), 200)
	check("cPanel switched ModSecurity off: our rules too", get("demo.xenovatech.co", "/wso.php"), 200)
	check("other websites keep the WAF", get("xenovatech.co", "/wso.php"), 403)
}

// TestEditorOnListedAddressWithCRS: a logged-in editor whose shared mobile
// address is on the IPDB saves an Elementor page with an HTML widget
// (thebassspot.com, 403 on every save). The save from their own wp-admin
// passes; the same body without the browser's same-site proof, from another
// site or with a made-up cookie is still refused.
func TestEditorOnListedAddressWithCRS(t *testing.T) {
	src := os.Getenv("XG_CRS_DIR")
	if src == "" {
		t.Skip("set XG_CRS_DIR to an OWASP CRS 4 checkout")
	}
	crsManager(t, src, `{"waf":{"enabled":true,"wordpress":true,"level":"normal","disabled_rules":[7700010,7700011,7700012,7700013,7700014,7700015]}}`, "", func(m *Manager) {
		m.IPDBIPs = func() []string { return []string{"127.0.0.1"} }
		m.Central = func() *Central {
			return &Central{URL: "https://captcha.xpguard.test/v", ServerID: "49c5f26a-f37e-40e0-9eed-62ef53a8a85a"}
		}
	})
	form := "application/x-www-form-urlencoded"
	editor := "Cookie: wordpress_logged_in_0123456789abcdef0123456789abcdef=admin%7C1700000000%7Ctok%7Chmac"
	fake := "Cookie: wordpress_logged_in_x=1"
	same := "Sec-Fetch-Site: same-origin"
	own := "Referer: https://shop.example.com/wp-admin/post.php?post=8&action=elementor"
	widget := `<img src="https://shop.example.com/wp-content/uploads/2026/06/logo.png" alt="" onerror="this.remove();"><script>document.write(document.cookie)</script> $(cat /etc/passwd)`
	save := "action=elementor_ajax&_nonce=abc&actions=" + urlEncode(`{"save_builder":{"action":"save_builder","data":{"elements":[{"widgetType":"html","settings":{"html":"`+strings.ReplaceAll(widget, `"`, `\"`)+`"}}]}}}`)
	cases := []struct {
		name, uri string
		hdr       []string
		want      int
	}{
		{"Elementor save from own wp-admin", "/wp-admin/admin-ajax.php", []string{editor, same, own}, 200},
		{"no same-site proof stays blocked", "/wp-admin/admin-ajax.php", []string{editor, own}, 403},
		{"Referer of another site stays blocked", "/wp-admin/admin-ajax.php", []string{editor, same, "Referer: https://evil.example.net/wp-admin/post.php"}, 403},
		{"made-up cookie stays blocked", "/wp-admin/admin-ajax.php", []string{fake, same, own}, 403},
		{"front-end form stays inspected", "/contact/", []string{editor, same, own}, 403},
	}
	for _, c := range cases {
		if got := sendBody(t, "shop.example.com", "POST", c.uri, form, save, c.hdr...); (got == 403) != (c.want == 403) || got == 0 {
			t.Errorf("%s: got %d, want %d", c.name, got, c.want)
		}
	}
}

// TestBlockEditorWithoutCookieWithCRS: on LiteSpeed servers logged-in
// editors were not recognised by their cookie (Rank Math, page and menu
// saves and the block editor's user list got 403). The block editor's own
// REST calls are also known by its nonce, sent same-origin from the site's
// wp-admin; the same request without that proof is still refused.
func TestBlockEditorWithoutCookieWithCRS(t *testing.T) {
	src := os.Getenv("XG_CRS_DIR")
	if src == "" {
		t.Skip("set XG_CRS_DIR to an OWASP CRS 4 checkout")
	}
	crsManager(t, src, `{"waf":{"enabled":true,"wordpress":true,"level":"normal","disabled_rules":[7700010,7700011,7700012,7700013,7700014,7700015]}}`, "", nil)
	nonce := "X-WP-Nonce: 0a1b2c3d4e"
	same := "Sec-Fetch-Site: same-origin"
	own := "Referer: https://shop.example.com/wp-admin/post.php?post=12&action=edit"
	page := `{"content":"<!-- wp:html --><div onmouseover=\"alert(document.cookie)\"><script>track()</script></div><!-- /wp:html -->","title":"\\u0645\\u0643\\u0629"}`
	users := "/wp-json/wp/v2/users?context=view&per_page=100&_fields=id%2Cname&capabilities%5B0%5D=edit_theme_options&_locale=user"
	cases := []struct {
		name, method, uri, body string
		hdr                     []string
		want                    int
	}{
		{"page save from own wp-admin", "POST", "/wp-json/wp/v2/pages/12?_locale=user", page, []string{nonce, same, own}, 200},
		{"user list of the block editor", "GET", users, "", []string{nonce, same, own}, 200},
		{"no same-site proof stays blocked", "POST", "/wp-json/wp/v2/pages/12?_locale=user", page, []string{nonce, own}, 403},
		{"Referer of another site stays blocked", "POST", "/wp-json/wp/v2/pages/12?_locale=user", page, []string{nonce, same, "Referer: https://evil.example.net/wp-admin/post.php"}, 403},
		{"no nonce stays blocked", "POST", "/wp-json/wp/v2/pages/12?_locale=user", page, []string{same, own}, 403},
		{"user list for visitors stays blocked", "GET", users, "", nil, 403},
	}
	for _, c := range cases {
		ctype := ""
		if c.body != "" {
			ctype = "application/json"
		}
		if got := sendBody(t, "shop.example.com", c.method, c.uri, ctype, c.body, c.hdr...); (got == 403) != (c.want == 403) || got == 0 {
			t.Errorf("%s: got %d, want %d", c.name, got, c.want)
		}
	}
}

// TestContentTypePolicyWithCRS: xPGuard's content type policy stands in for
// CRS 920420 (taken out after loading): form posts, multipart uploads and
// JSON pass, an unknown body type still scores.
func TestContentTypePolicyWithCRS(t *testing.T) {
	src := os.Getenv("XG_CRS_DIR")
	if src == "" {
		t.Skip("set XG_CRS_DIR to an OWASP CRS 4 checkout")
	}
	crsManager(t, src, `{"waf":{"enabled":true}}`, "", nil)
	for _, c := range []struct {
		ctype string
		want  int
	}{
		{"application/x-www-form-urlencoded; charset=UTF-8", 200},
		{"multipart/form-data; boundary=----WebKitFormBoundaryAbC", 200},
		{"application/json", 200},
		{"text/html", 403},
		{"application/x-php", 403},
	} {
		body := "a=1"
		if strings.HasPrefix(c.ctype, "multipart") {
			body = "------WebKitFormBoundaryAbC\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1\r\n------WebKitFormBoundaryAbC--\r\n"
		} else if c.ctype == "application/json" {
			body = `{"a":1}`
		}
		if got := sendBody(t, "shop.example.com", "POST", "/?wc-ajax=update_order_review", c.ctype, body); (got == 403) != (c.want == 403) || got == 0 {
			t.Errorf("%s: got %d, want %d", c.ctype, got, c.want)
		}
	}
}

func urlEncode(s string) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func sendBody(t *testing.T, host, method, uri, ctype, body string, hdr ...string) int {
	t.Helper()
	c, err := net.DialTimeout("tcp", "127.0.0.1:80", 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	ua, accept := browserUA, "*/*"
	var extra []string
	for _, h := range hdr {
		if strings.HasPrefix(h, "User-Agent: ") {
			ua = strings.TrimPrefix(h, "User-Agent: ")
		} else if strings.HasPrefix(h, "Accept: ") {
			accept = strings.TrimPrefix(h, "Accept: ")
		} else {
			extra = append(extra, h)
		}
	}
	hdr = extra
	req := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: %s\r\n", method, uri, host, ua, accept)
	if ctype != "" {
		req += fmt.Sprintf("Content-Type: %s\r\nContent-Length: %d\r\n", ctype, len(body))
	}
	for _, h := range hdr {
		req += h + "\r\n"
	}
	req += "Connection: close\r\n\r\n" + body
	io.WriteString(c, req)
	line, _ := bufio.NewReader(c).ReadString('\n')
	var code int
	fmt.Sscanf(line, "HTTP/1.1 %d", &code)
	return code
}

func TestScoredDetailNamesWhereRulesMatched(t *testing.T) {
	r := newReasons(8)
	for _, l := range []string{
		"[client 1.2.3.4:1] ModSecurity: Warning. Matched \"Operator `Rx' with parameter `x' against variable `REQUEST_COOKIES:consent' (Value: `{}' ) [file \"/x\"] [id \"942550\"] [msg \"JSON-Based SQL Injection\"] [uri \"/\"] [unique_id \"U9\"]",
		`[client 1.2.3.4:1] ModSecurity: Warning. Pattern match "x" at ARGS:q. [file "/x"] [id "941100"] [msg "XSS Attack Detected via libinjection"] [uri "/"] [unique_id "U9"]`,
	} {
		e, _ := ParseLine(l)
		r.apply(e)
	}
	d, _ := ParseLine(`[client 1.2.3.4:1] ModSecurity: Access denied with code 403 (phase 2). Operator GE matched 5 at TX:blocking_inbound_anomaly_score. [file "/x"] [id "949110"] [msg "Inbound Anomaly Score Exceeded (Total Score: 10)"] [uri "/"] [unique_id "U9"]`)
	d = r.apply(d)
	if d.Detail != "Matched rules: 942550 (REQUEST_COOKIES:consent), 941100 (ARGS:q)" {
		t.Fatalf("%q", d.Detail)
	}
}

// TestLevelsWithCRS: the WAF levels on a real CRS. Normal lets one weak
// signal through and never blocks a logged-in WordPress user saving their
// site (digitalcaps.uk, xenovasolutions.com), also where rule removal by tag
// is not supported (it works by the anomaly threshold); attacks from
// visitors are still blocked. Strict blocks the single signal.
func TestLevelsWithCRS(t *testing.T) {
	src := os.Getenv("XG_CRS_DIR")
	if src == "" {
		t.Skip("set XG_CRS_DIR to an OWASP CRS 4 checkout")
	}
	// Our WordPress exclusions are switched off here: the level alone must do it.
	m := crsManager(t, src, `{"waf":{"enabled":true,"wordpress":true,"level":"normal","disabled_rules":[7700010,7700011,7700012,7700013,7700014,7700015]}}`, "off", nil)
	form, json := "application/x-www-form-urlencoded", "application/json"
	editor := "Cookie: wordpress_logged_in_0123456789abcdef0123456789abcdef=admin%7C1700000000%7Ctok%7Chmac"
	fake := "Cookie: wordpress_logged_in_x=1"
	post := `{"content":"<!-- wp:paragraph --><p>Offer</p><!-- /wp:paragraph --><script>document.write(document.cookie)</script> $(cat /etc/passwd)","status":"publish"}`
	// One CRS rule (941310, score 5) with the hosting defaults off.
	weak := "comment=" + urlEncode("<b>بہت</b> اچھا پروڈکٹ")
	attack := "q=" + urlEncode(`<script>document.write(document.cookie)</script> $(cat /etc/passwd)`)
	cases := []struct {
		name, method, uri, ctype, body string
		hdr                            []string
		want                           int
	}{
		{"editor saves a post (REST)", "POST", "/wp-json/wp/v2/posts/2368", json, post, []string{editor}, 200},
		{"editor saves through RankMath", "POST", "/wp-json/rankmath/v1/updateMeta", json, post, []string{editor}, 200},
		{"editor saves through admin-ajax", "POST", "/wp-admin/admin-ajax.php", form, "action=elementor_ajax&data=" + urlEncode(post), []string{editor}, 200},
		{"application password on REST", "POST", "/wp-json/wp/v2/pages/85", json, post, []string{"Authorization: Basic YWRtaW46eHh4eCB4eHh4IHh4eHg="}, 200},
		{"fake cookie stays blocked", "POST", "/wp-json/wp/v2/posts/2368", json, post, []string{fake}, 403},
		{"anonymous REST write stays blocked", "POST", "/wp-json/wp/v2/posts/2368", json, post, nil, 403},
		{"editor cookie on a front-end form stays inspected", "POST", "/contact/", form, attack, []string{editor}, 403},
		{"one weak signal in a form passes", "POST", "/contact/", form, weak, nil, 200},
		{"attack in a form is blocked", "POST", "/contact/", form, attack, nil, 403},
		// An app's own API (a Node.js ERP updating a voucher): CRS 911100
		// allowed only GET/HEAD/POST/OPTIONS.
		{"API update with PUT", "PUT", "/api/vouchers/11764", json, `{"voucher_type":"CPV","lines":[{"account_id":4,"credit":1100}]}`, nil, 200},
		{"API delete with DELETE", "DELETE", "/api/vouchers/11764", json, "", nil, 200},
		{"API change with PATCH", "PATCH", "/api/vouchers/11764", json, `{"is_posted":true}`, nil, 200},
		// Outlook asking cPanel for its mail settings.
		{"Outlook autodiscover", "POST", "/autodiscover/autodiscover.xml", "text/xml", `<?xml version="1.0" encoding="utf-8"?><Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006"><Request><EMailAddress>user@shop.example.com</EMailAddress><AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema></Request></Autodiscover>`, nil, 200},
	}
	check := func(level string) {
		for _, c := range cases {
			want := c.want
			if level == "strict" && (c.name == "one weak signal in a form passes" || strings.HasPrefix(c.name, "editor saves") || c.name == "application password on REST") {
				want = 403
			}
			if got := sendBody(t, "shop.example.com", c.method, c.uri, c.ctype, c.body, c.hdr...); (got == 403) != (want == 403) || got == 0 {
				t.Errorf("%s: %s: got %d, want %d", level, c.name, got, want)
			}
		}
	}
	check("normal")
	m.Settings.Patch([]byte(`{"waf":{"level":"strict"}}`))
	if err := m.Apply(); err != nil {
		t.Fatal(err)
	}
	waitApache()
	check("strict")
}

// The CRS self-test is blocked at every level, also without the
// libinjection rules (941100, 942100), which LiteSpeed's engine lacks.
func TestCRSSelfTestEveryLevel(t *testing.T) {
	src := os.Getenv("XG_CRS_DIR")
	if src == "" {
		t.Skip("set XG_CRS_DIR to an OWASP CRS 4 checkout")
	}
	m := crsManager(t, src, `{"waf":{"enabled":true,"level":"low","disabled_rules":[941100,942100]}}`, "off", nil)
	for _, level := range []string{"low", "normal", "strict"} {
		m.Settings.Patch([]byte(`{"waf":{"level":"` + level + `"}}`))
		if err := m.Apply(); err != nil {
			t.Fatal(err)
		}
		waitApache()
		old := SelfTestURLs
		SelfTestURLs = []string{"http://127.0.0.1"}
		st := runSelfTest(true, "", 0)
		SelfTestURLs = old
		if st.CRS != "blocked" {
			t.Errorf("%s: %+v", level, st)
		}
	}
}

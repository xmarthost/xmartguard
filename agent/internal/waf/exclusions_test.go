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
	if strings.Contains(out, "id:7704004") || strings.Contains(out, "ruleEngine=Off") || strings.Contains(out, "bad domain") {
		t.Fatalf("invalid or duplicate exclusion rendered:\n%s", out)
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
	// Kept where a vendor replaces our rules and when our rules are off.
	if !strings.Contains(RenderLoginWatch(c, "Malware.Expert", Dynamic{}), "ctl:ruleRemoveById=941100") || !strings.Contains(RenderExclusionsOnly(c, Dynamic{}), "id:7700012") {
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
		{"PUT outside the REST API stays refused", "shop.example.com", "PUT", "/upload.php", json, `{}`, nil, 403},
		{"Method override outside the REST API stays refused", "shop.example.com", "POST", "/contact/", form, "a=1", []string{"X-HTTP-Method-Override: PUT"}, 403},
		{"ViserLab colour stylesheet", "shop.example.com", "GET", "/assets/templates/metro_hyip/css/color.php?base_color=f60233&secondary_color=000000", "", "", nil, 200},
		{"PHP in a css folder stays blocked", "shop.example.com", "GET", "/assets/templates/metro_hyip/css/shell.php", "", "", nil, 403},
		{"Bare Mozilla/5.0 is still a bot", "shop.example.com", "GET", "/", "", "", []string{"User-Agent: Mozilla/5.0"}, 403},
		{"Bare Mozilla/5.0 with WordPress login", "shop.example.com", "GET", "/wp-admin/", "", "", []string{"User-Agent: Mozilla/5.0", cookie}, 200},
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
	m.Settings.Patch([]byte(`{"waf":{"disabled_rules":[7700010,7700013,7700014]}}`))
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
	if sendBody(t, "shop.example.com", "PUT", "/wp-json/elementor/v1/global-classes", json, `{}`) != 403 {
		t.Fatal("PUT passes even without the exclusion")
	}
}

// crsManager starts Apache with our rules and the OWASP CRS release in src.
func crsManager(t *testing.T, src, patch, soft string, setup func(*Manager)) *Manager {
	t.Helper()
	m, _ := apacheWith(t, patch)
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
	var listed, passed []string
	m := crsManager(t, src, `{"waf":{"enabled":true,"wordpress":true,"webshell":true}}`, "", func(m *Manager) {
		m.IPDBIPs = func() []string { return listed }
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
	get := func(host, uri string, hdr ...string) int { return sendBody(t, host, "GET", uri, "", "", hdr...) }
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

	check("cPanel switched ModSecurity off: attack passes there", get("demo.xenovatech.co", strong), 200)
	check("cPanel switched ModSecurity off: our rules too", get("demo.xenovatech.co", "/wso.php"), 200)
	check("other websites keep the WAF", get("xenovatech.co", "/wso.php"), 403)
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
	ua := browserUA
	var extra []string
	for _, h := range hdr {
		if strings.HasPrefix(h, "User-Agent: ") {
			ua = strings.TrimPrefix(h, "User-Agent: ")
		} else {
			extra = append(extra, h)
		}
	}
	hdr = extra
	req := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\n", method, uri, host, ua)
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

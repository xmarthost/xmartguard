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
		`SecRule SERVER_NAME "@rx ^(?:www\.)?morningmobility\.fit$" "id:7700020,`,
		`SecRule REQUEST_FILENAME "@beginsWith /wp-admin/admin.php" "t:none,t:urlDecodeUni,ctl:ruleRemoveById=941100"`,
		`SecRule SERVER_NAME "@rx ^(?:[^.]+\.)*example\.com$" "id:7700021,phase:1,t:none,t:lowercase,pass,nolog,ctl:ruleRemoveById=942100"`,
		`SecRule REQUEST_FILENAME "@beginsWith /api/" "id:7700022,phase:1,t:none,t:urlDecodeUni,pass,nolog,ctl:ruleRemoveById=7700506"`,
		`SecAction "id:7700023,phase:1,pass,nolog,ctl:ruleRemoveById=949110"`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in\n%s", want, out)
		}
	}
	if strings.Contains(out, "id:7700024") || strings.Contains(out, "ruleEngine=Off") || strings.Contains(out, "bad domain") {
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
	if !strings.Contains(RenderLoginWatch(c, "Malware.Expert"), "ctl:ruleRemoveById=941100") || !strings.Contains(RenderExclusionsOnly(c), "id:7700012") {
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
	m, _ := apacheWith(t, `{"waf":{"enabled":true,"wordpress":true,"rule_exclusions":[{"rule":949110,"domain":"allowed.example.com","path":"/form/"}]}}`)
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
	rs.CRS.Enabled, rs.CRS.Version = true, "4.18.0"
	// Debian ships no modsecurity.conf here: the JSON body parser of cPanel's.
	rs.Custom.Enabled = true
	rs.Custom.Rules = `SecRule REQUEST_HEADERS:Content-Type "^application/json" "id:200001,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"`
	m.SetRuleSets(rs)
	if err := m.Apply(); err != nil {
		t.Fatal(err)
	}
	waitApache()

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
	m.Settings.Patch([]byte(`{"waf":{"disabled_rules":[7700010]}}`))
	if err := m.Apply(); err != nil {
		t.Fatal(err)
	}
	waitApache()
	if sendBody(t, "shop.example.com", "POST", "/wp-admin/admin.php?page=wpcode-headers-footers", form, wpcode, cookie) != 403 {
		t.Fatal("WPCode save passes even without the exclusion: the test proves nothing")
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
	req := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\nContent-Type: %s\r\nContent-Length: %d\r\n", method, uri, host, browserUA, ctype, len(body))
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

package waf

import (
	"strings"
	"testing"

	"github.com/xmarthost/xmartguard/agent/internal/settings"
)

// Lines captured from a real Apache 2.4 + ModSecurity 2.9.7 running these rules.
var realLines = []struct {
	line                       string
	ip, host, uri, cat, action string
	id                         int
}{
	{`[Sat Sep 26 01:45:54.714760 2026] [security2:error] [pid 4587:tid 1] [client 127.0.0.1:35700] [client 127.0.0.1] ModSecurity: Access denied with code 403 (phase 1). Pattern match "/(?:\\.env$)" at REQUEST_FILENAME. [file "/x/rules.conf"] [line "5"] [id "7700201"] [msg "XMartGuard - Access to sensitive file blocked"] [tag "xmartguard/files"] [hostname "shop.example"] [uri "/.env"] [unique_id "a"]`,
		"127.0.0.1", "shop.example", "/.env", "waf", "Access denied with code 403", IDSensitive},
	{`[Sat Sep 26 01:45:54.727971 2026] [security2:error] [pid 4587:tid 1] [client 203.0.113.9:35720] [client 203.0.113.9] ModSecurity: Access denied with code 403 (phase 1). Matched phrase "sqlmap" at REQUEST_HEADERS:User-Agent. [file "/x/rules.conf"] [line "20"] [id "7700501"] [msg "XMartGuard - Bad bot blocked"] [tag "xmartguard/bot"] [hostname "shop.example"] [uri "/index.html"] [unique_id "b"]`,
		"203.0.113.9", "shop.example", "/index.html", "bot", "Access denied with code 403", IDBadBots},
	{`[Sat Sep 26 01:46:10.471444 2026] [security2:error] [pid 4703:tid 1] [client 198.51.100.4:45142] [client 198.51.100.4] ModSecurity: Warning. String match "200" at RESPONSE_STATUS. [file "/x/rules.conf"] [line "9"] [id "7700401"] [msg "XMartGuard - Failed login: WordPress"] [tag "xmartguard/login"] [hostname "blog.example"] [uri "/wp-login.php"] [unique_id "c"]`,
		"198.51.100.4", "blog.example", "/wp-login.php", "login", "Logged", IDLoginWP},
}

func TestParseRealModSecurityLines(t *testing.T) {
	for _, c := range realLines {
		e, ok := ParseLine(c.line)
		if !ok {
			t.Fatalf("not parsed: %s", c.line)
		}
		if e.IP != c.ip || e.Host != c.host || e.URI != c.uri || e.Category != c.cat || e.RuleID != c.id || !strings.HasPrefix(e.Action, c.action) {
			t.Errorf("got %+v, want ip=%s host=%s uri=%s cat=%s id=%d action=%s", e, c.ip, c.host, c.uri, c.cat, c.id, c.action)
		}
	}
	// Startup notices and non-ModSecurity lines are ignored.
	for _, l := range []string{
		`[Sat Sep 26 01:46:09 2026] [security2:notice] [pid 1] ModSecurity for Apache/2.9.7 configured.`,
		`[Sat Sep 26 01:46:09 2026] [core:error] [pid 1] [client 1.2.3.4:1] AH00128: File does not exist`,
	} {
		if _, ok := ParseLine(l); ok {
			t.Errorf("parsed unexpected line: %s", l)
		}
	}
}

func TestRenderRespectsSettings(t *testing.T) {
	c := settings.Defaults().WAF
	c.SEOBots = false
	c.AIBots = false
	c.DisabledRules = []int{7700302, 950001}
	c.WhitelistIPs = []string{"198.51.100.7"}
	r := Render(c, Options{Dir: "/etc/xmartguard/waf", InspectPath: "/etc/xmartguard/waf/upload-scan", UploadScan: true})
	for _, want := range []string{"id:7700001", "198.51.100.7", "ctl:ruleRemoveById=7700302", "ctl:ruleRemoveById=950001", "@inspectFile /etc/xmartguard/waf/upload-scan", "id:7700501", "id:7700401"} {
		if !strings.Contains(r, want) {
			t.Errorf("rules missing %q", want)
		}
	}
	for _, not := range []string{"id:7700502", "id:7700503", "id:7700504"} {
		if strings.Contains(r, not) {
			t.Errorf("rules unexpectedly contain %q", not)
		}
	}
	c.UploadScan = false
	if strings.Contains(Render(c, Options{Dir: "/d", InspectPath: "/x", UploadScan: true}), "inspectFile") {
		t.Error("upload scan rendered while disabled")
	}
}

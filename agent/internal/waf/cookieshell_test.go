package waf

import (
	"strings"
	"testing"

	"github.com/xmarthost/xmartguard/agent/internal/settings"
)

// Web shells that read their commands from a base64 cookie get past the
// parameter rules: the cookie rule decodes it. New: it only watches until
// approved, and a fake logged-in cookie gives no way around it.
func TestCookieShellRule(t *testing.T) {
	c := settings.Defaults().WAF
	c.Enabled = true
	out := Render(c, Options{Dir: "/r"})
	l := ruleLine(out, IDCookieShell)
	if l == "" || !strings.Contains(l, "t:base64Decode") || !strings.Contains(l, "REQUEST_COOKIES") || !strings.Contains(l, "[watch]") || strings.Contains(l, "deny") {
		t.Fatalf("rule: %s", l)
	}
	if strings.Contains(strings.Join(chainOf(out, IDCookieShell), "\n"), "logged_in") {
		t.Error("a logged-in cookie skips the rule")
	}
	if l := strings.Join(chainOf(out, IDStaticPost), "\n"); !strings.Contains(l, "@streq POST") || !strings.Contains(l, "gif|jpe?g") || !strings.Contains(l, "[watch]") {
		t.Fatalf("static POST rule: %s", l)
	}
	out = Render(c, Options{Dir: "/r", Intel: (&Intel{Enforce: []int{IDCookieShell}}).Clean()})
	if l := ruleLine(out, IDCookieShell); !strings.Contains(l, "deny,status:403") {
		t.Fatalf("approved rule does not block: %s", l)
	}
}

// Plugin bugs of 2024-2026 made admins from requests that ask for the
// administrator role; WordPress's own user screens and REST users route
// (which check the login themselves) are left alone. Watch first.
func TestAdminRoleArgRule(t *testing.T) {
	c := settings.Defaults().WAF
	c.Enabled = true
	out := Render(c, Options{Dir: "/r"})
	chain := strings.Join(chainOf(out, IDAdminRoleArg), "\n")
	for _, want := range []string{"ARGS:role|", "ARGS:default_role", "^administrator$", "user-new|user-edit|users|profile", "wp/+v2/+users", "[watch]"} {
		if !strings.Contains(chain, want) {
			t.Errorf("rule lacks %q:\n%s", want, chain)
		}
	}
	if strings.Contains(chain, "logged_in") || strings.Contains(chain, "deny") {
		t.Errorf("cookie exception or blocking before approval:\n%s", chain)
	}
}

// Application passwords guessed on the REST API counted as failed logins
// (toward the brute-force ban), like the login page.
func TestAppPasswordLoginRule(t *testing.T) {
	c := settings.Defaults().WAF
	c.Enabled = true
	chain := strings.Join(chainOf(Render(c, Options{Dir: "/r"}), IDLoginAppPass), "\n")
	for _, want := range []string{"REQUEST_HEADERS:Authorization", "^basic", "/wp-json/", "rest_route", `RESPONSE_STATUS "@streq 401"`, ",pass,"} {
		if !strings.Contains(chain, want) {
			t.Errorf("rule lacks %q:\n%s", want, chain)
		}
	}
	if classify(IDLoginAppPass, "") != "login" || loginRuleName[IDLoginAppPass] == "" {
		t.Error("not counted as a failed login")
	}
}

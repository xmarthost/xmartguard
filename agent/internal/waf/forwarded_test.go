package waf

import (
	"regexp"
	"strings"
	"testing"

	"github.com/xmarthost/xmartguard/agent/internal/settings"
)

// Audit A3 F3: behind Cloudflare the visitor's address is CF-Connecting-IP
// (Cloudflare sets it); X-Real-IP and the first X-Forwarded-For entries are
// whatever the client wrote. Behind a local proxy the last X-Forwarded-For
// hop (added by that proxy) is read; rules that relax or clear a flag
// (CAPTCHA solved, whitelisted country) never read the forwarded headers.
func TestForwardedAddressFromTheProxyOnly(t *testing.T) {
	c := settings.Defaults().WAF
	c.Enabled, c.IPDBPost, c.TorAction, c.ProxyIPCheck = true, true, "post", true
	out := Render(c, Options{Dir: "/r"})
	if strings.Contains(out, "X-Real-IP") {
		t.Error("a rule reads X-Real-IP")
	}
	cf := "@ipMatch " + strings.Join(cloudflareRanges(), ",")
	for _, id := range []int{IDIPDBPost + 1000, IDTorPost + 1000, IDProxyBlocked} {
		ch := strings.Join(chainOf(out, id), "\n")
		if !strings.Contains(ch, cf) || strings.Contains(ch, "X-Forwarded-For") || !strings.Contains(ch, "REQUEST_HEADERS:CF-Connecting-IP") {
			t.Errorf("Cloudflare rule %d:\n%s", id, ch)
		}
	}
	for _, id := range []int{IDIPDBPost + 3000, IDTorPost + 3000, IDProxyBlocked + 1000} {
		ch := strings.Join(chainOf(out, id), "\n")
		if !strings.Contains(ch, "@ipMatch "+localProxies) || strings.Contains(ch, "CF-Connecting-IP") || !strings.Contains(ch, reLastHop) {
			t.Errorf("local proxy rule %d:\n%s", id, ch)
		}
	}
	// The last hop, not the client's first entry.
	re := regexp.MustCompile(strings.TrimPrefix(reLastHop, "@rx "))
	for in, want := range map[string]string{"203.0.113.9": "203.0.113.9", "17.0.0.1, 203.0.113.9": "203.0.113.9", "17.0.0.1,203.0.113.9 ": "203.0.113.9", "2001:db8::1": "2001:db8::1"} {
		if m := re.FindStringSubmatch(in); m == nil || m[1] != want {
			t.Errorf("%q: %v", in, m)
		}
	}

	m := &Manager{RulesDir: "/r", Central: func() *Central {
		return &Central{URL: "https://captcha.xpguard.org/v", ServerID: "15d69a72-653a-47b6-90f6-fde737bce061"}
	}, TrustedCountryIPs: func() []string { return []string{"39.32.0.0/11"} }}
	sb, ok := m.softBlock(CRSConfig{}, 5)
	if !ok {
		t.Fatal("soft blocking not rendered")
	}
	for _, id := range []int{IDSoftVerified + 1, IDSoftCountry + 1} {
		ch := strings.Join(chainOf(sb.setup, id), "\n")
		if !strings.Contains(ch, cf) || strings.Contains(ch, "X-Forwarded-For") || !strings.Contains(ch, "CF-Connecting-IP") {
			t.Errorf("relaxing rule %d:\n%s", id, ch)
		}
	}
	for _, id := range []int{IDSoftVerified + 2000, IDSoftCountry + 2000} {
		if chainOf(sb.setup, id) != nil {
			t.Errorf("relaxing rule %d reads X-Forwarded-For", id)
		}
	}
	if ch := strings.Join(chainOf(sb.setup, IDSoftStrict+2000), "\n"); !strings.Contains(ch, reLastHop) {
		t.Errorf("bad-reputation mark behind a local proxy:\n%s", ch)
	}
	if strings.Contains(sb.setup, "X-Real-IP") {
		t.Error("soft blocking reads X-Real-IP")
	}
}

// Audit A3 F4: a direct request with a Googlebot User-Agent from an address
// not on Google's list is fake, also when it adds an X-Forwarded-For
// header; behind Cloudflare CF-Connecting-IP is checked against the list.
func TestFakeSearchBotIgnoresForwardedHeaders(t *testing.T) {
	c := settings.Defaults().WAF
	c.Enabled, c.BotBlocker = true, true
	out := Render(c, Options{Dir: "/r", Trusted: true, VerifiedBots: []string{"googlebot", "bingbot"}})
	direct := strings.Join(chainOf(out, IDFakeSearchBot), "\n")
	if strings.Contains(direct, "X-Forwarded-For") || strings.Contains(direct, "&REQUEST_HEADERS:CF-Connecting-IP") ||
		!strings.Contains(direct, `SecRule REMOTE_ADDR "!@ipMatchFromFile /r/proxy-ranges.txt"`) {
		t.Errorf("direct rule:\n%s", direct)
	}
	cf := chainOf(out, IDFakeSearchBot+1000)
	if len(cf) < 3 || !strings.Contains(cf[len(cf)-1], `SecRule REQUEST_HEADERS:CF-Connecting-IP "!@ipMatchFromFile /r/trusted-ips.txt"`) ||
		!strings.Contains(strings.Join(cf, "\n"), "@ipMatch "+strings.Join(cloudflareRanges(), ",")) {
		t.Errorf("Cloudflare rule: %q", cf)
	}
	// Real crawlers (trusted services) skip both, also on LiteSpeed.
	for _, id := range []int{IDFakeSearchBot, IDFakeSearchBot + 1000} {
		if ch := chainOf(out, id); len(ch) < 2 || ch[1] != `SecRule &TX:xg_trusted "@eq 0" "t:none,chain"` {
			t.Errorf("rule %d does not skip trusted services: %q", id, ch)
		}
	}
}

// Audit A3 F6: settings strings go into the rules only when they are what
// they claim to be: an invalid address would fail the config test (and
// freeze the WAF), a quote would add actions to a rule.
func TestSettingsStringsValidated(t *testing.T) {
	c := settings.Defaults().WAF
	c.Enabled, c.BruteForce = true, true
	c.WhitelistIPs = []string{"203.0.113.7/32", "example.com", "1.2.3.4/33", `1.2.3.4" "id:1,exec:/x`, "2001:db8::/32"}
	c.WhitelistDomains = []string{"shop.example.com", "*.example.org", `x.com)$" "id:2,ctl:ruleEngine=Off`, "a b.com"}
	c.LoginURLs = []string{"/my-login.php", `/x" "id:3,exec:/tmp/x`, "/with space", "/wp-login.php"}
	out := Render(c, Options{Dir: "/r"})
	for _, bad := range []string{"example.com,", "/33", "exec:", "x.com)", "a b", "with space", `x" "`} {
		if strings.Contains(out, bad) {
			t.Errorf("rules contain %q", bad)
		}
	}
	if !strings.Contains(ruleLine(out, IDWhitelist), `"@ipMatch 203.0.113.7,2001:db8::/32"`) {
		t.Errorf("whitelist: %s", ruleLine(out, IDWhitelist))
	}
	if l := ruleLine(out, IDWhiteDomains); !strings.Contains(l, `shop\.example\.com|[^.]+\.example\.org`) {
		t.Errorf("domains: %s", l)
	}
	if !strings.Contains(out, `my-login\.php`) {
		t.Error("valid login URL dropped")
	}
	// Every rule line still has balanced quotes.
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "SecRule ") && strings.Count(l, `"`)%2 != 0 {
			t.Errorf("unbalanced quotes: %s", l)
		}
	}
}

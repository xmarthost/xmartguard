package waf

import (
	"strings"
	"testing"

	"github.com/xmarthost/xmartguard/agent/internal/settings"
)

type banRecorder struct{ ips []string }

func (b *banRecorder) AutoBan(ip, reason, source string) { b.ips = append(b.ips, ip) }

// Audit A3 F8: a Cloudflare edge or a local proxy is never banned by the
// WAF (it serves every proxied website); the rules that only match proxied
// requests never count toward a ban; a direct attacker still is banned.
func TestWAFNeverBansProxies(t *testing.T) {
	m := learnManager(t)
	fw := &banRecorder{}
	m.Firewall = fw
	blocks, logins := newCounter(), newCounter()
	for i := 0; i < 40; i++ {
		for _, ip := range []string{"104.16.0.1", "2606:4700::1", "127.0.0.1"} {
			m.maybeBanBlocked(Event{IP: ip, RuleID: IDWebshell}, blocks)
			m.maybeBan(Event{IP: ip, RuleID: IDLoginWP, Category: "login"}, logins)
		}
	}
	if len(fw.ips) != 0 {
		t.Fatalf("proxy banned: %v", fw.ips)
	}
	for i := 0; i < 40; i++ {
		m.maybeBanBlocked(Event{IP: "198.51.100.20", RuleID: IDWebshell}, blocks)
	}
	if len(fw.ips) == 0 || fw.ips[0] != "198.51.100.20" {
		t.Fatalf("direct attacker not banned: %v", fw.ips)
	}
	for _, id := range []int{IDProxyBlocked, IDProxyBlocked + 1000, IDTorPost + 1000, IDTorPost + 2000, IDTorPost + 3000, IDTorBlock + 1000, IDTorBlock + 2000, IDTorBlock + 3000, IDIPDBPost + 3000} {
		if !noBanRules[id] {
			t.Errorf("rule %d counts toward a ban", id)
		}
	}
}

// Audit A3 F9: the login counters count failures, not every POST: a
// successful OpenCart or custom-URL login redirects (only 200 counts), and
// XML-RPC counts only methods that log in (not pingbacks or Jetpack).
func TestLoginRulesCountFailures(t *testing.T) {
	c := settings.Defaults().WAF
	c.Enabled, c.BruteForce, c.WordPress = true, true, true
	c.LoginURLs = []string{"/members/login.php"}
	out := Render(c, Options{Dir: "/r"})
	for _, id := range []int{IDLoginWP, IDLoginOpenCart, IDLoginCustom} {
		ch := chainOf(out, id)
		if len(ch) == 0 || !strings.Contains(ch[0], "phase:3") || ch[len(ch)-1] != `SecRule RESPONSE_STATUS "@streq 200" "t:none"` {
			t.Errorf("rule %d counts successful logins: %q", id, ch)
		}
	}
	ch := chainOf(out, IDLoginXMLRPC)
	re := rxOf(t, ch[len(ch)-1])
	for body, want := range map[string]bool{
		"<methodname>wp.getusersblogs</methodname>":    true,
		"<methodname>system.multicall</methodname>":    true,
		"<methodname> metaweblog.newpost</methodname>": true,
		"<methodname>pingback.ping</methodname>":       false,
		"<methodname>system.listmethods</methodname>":  false,
		"<methodname>jetpack.jsonapi</methodname>":     false,
	} {
		if re.MatchString(body) != want {
			t.Errorf("XML-RPC %s counted: %v", body, !want)
		}
	}
}

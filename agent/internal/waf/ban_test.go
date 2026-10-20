package waf

import "testing"

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

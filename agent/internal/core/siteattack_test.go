package core

import (
	"slices"
	"strings"
	"testing"

	"github.com/xmarthost/xmartguard/agent/internal/store"
)

// The owner's test from a VPN that changed address every few attempts:
// 22 failed WordPress logins on websoulhost.com from 6 addresses in 3
// minutes, none banned (the threshold counts per address). Such a site's
// login page now asks every visitor for the CAPTCHA, and an address with 3
// failed logins gets it on its next visit.
func TestLoginAttackSites(t *testing.T) {
	a := newTestAgent(t, `{}`)
	now := store.Now()
	add := func(host, ip string, rule, n int) {
		for i := 0; i < n; i++ {
			a.DB.Exec(`INSERT INTO waf_events (at, ip, host, uri, rule_id, msg, category, action) VALUES (?, ?, ?, '/wp-login.php', ?, 'xPGuard - Failed login: WordPress', 'login', 'Logged')`, now-int64(60+i), ip, host, rule)
		}
	}
	for ip, n := range map[string]int{"45.58.242.100": 3, "45.58.242.10": 7, "45.58.238.93": 1, "45.58.238.19": 4, "149.143.161.99": 5, "149.143.161.22": 2} {
		add("websoulhost.com", ip, 7700401, n)
	}
	// One address (a person who forgot the password, or one bot): the ban
	// threshold deals with it, the site stays open.
	add("solo.example.com", "198.51.100.5", 7700401, 20)
	// A few people mistyping.
	add("quiet.example.com", "198.51.100.6", 7700401, 4)
	add("quiet.example.com", "198.51.100.7", 7700401, 4)
	add("quiet.example.com", "198.51.100.8", 7700401, 4)
	// A protected login URL under attack, written with www and a port.
	for _, ip := range []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"} {
		add("WWW.Panel.Example.com:443", ip, 7700405, 6)
	}
	// XML-RPC calls are no login page; old attempts are over.
	for _, ip := range []string{"203.0.113.4", "203.0.113.5", "203.0.113.6"} {
		add("xmlrpc.example.com", ip, 7700402, 10)
		a.DB.Exec(`INSERT INTO waf_events (at, ip, host, uri, rule_id, category, action) VALUES (?, ?, 'old.example.com', '/wp-login.php', 7700401, 'login', 'Logged')`, now-3*3600, ip)
	}
	got := a.loginAttackSites()
	if strings.Join(got, ",") != "panel.example.com,websoulhost.com" {
		t.Fatalf("sites under attack: %v", got)
	}
	// Gated pages: not xmlrpc.php or the admin scripts of Joomla and OpenCart.
	if l := siteLoginURLs([]string{"/wp-login.php", "/xmlrpc.php", "/administrator/index.php", "/admin/index.php", "/client-area/login"}); strings.Join(l, ",") != "/wp-login.php,/client-area/login" {
		t.Fatalf("gated pages: %v", l)
	}
	// Three failed logins: a suspect (CAPTCHA on the next login page visit).
	sus := a.centralSuspects()
	for _, ip := range []string{"45.58.242.100", "45.58.242.10", "45.58.238.19", "149.143.161.99", "198.51.100.5", "198.51.100.6"} {
		if !slices.Contains(sus, ip) {
			t.Errorf("%s with 3+ failed logins is no suspect", ip)
		}
	}
	for _, ip := range []string{"45.58.238.93", "149.143.161.22", "203.0.113.4"} {
		if slices.Contains(sus, ip) {
			t.Errorf("%s is a suspect", ip)
		}
	}
}

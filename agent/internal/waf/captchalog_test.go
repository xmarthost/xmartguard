package waf

import (
	"strings"
	"testing"
)

// The owner tried 10 fake logins and was then sent to the CAPTCHA, but
// searched the WAF log's "Blocked attacks" and found nothing: failed
// logins are their own kind ("Failed CMS logins"), and the CAPTCHA
// redirect was never recorded. It is now, once per address and site in
// half an hour, and never counts toward a ban.
func TestCaptchaRedirectLogged(t *testing.T) {
	m := learnManager(t)
	fw := &banRecorder{}
	m.Firewall = fw
	st := newTailState()
	gate := func(uid string) Event {
		e, ok := ParseLine(`[Sat Oct 25 06:01:10.471444 2026] [security2:error] [pid 1:tid 1] [client 45.58.238.97:45142] [client 45.58.238.97] ModSecurity: Access denied with redirection to https://captcha.xpguard.org/v?s=x&ip=45.58.238.97&h=websoulhost.com&u=/wp-login.php using status 302 (phase 1). Matched "Operator ` + "`" + `Eq' with parameter ` + "`" + `1' against variable ` + "`" + `TX:xg_suspect' (Value: ` + "`" + `1' ) [file "/x/rules.conf"] [line "9"] [id "7700904"] [msg "xPGuard - suspicious visitor sent to the CAPTCHA"] [tag "xpguard/captcha"] [hostname "websoulhost.com"] [uri "/wp-login.php"] [unique_id "` + uid + `"]`)
		if !ok {
			t.Fatal("gate line not parsed")
		}
		return e
	}
	login := func(uid string) Event {
		e, _ := ParseLine(`[Sat Oct 25 06:01:00.471444 2026] [security2:error] [pid 1:tid 1] [client 45.58.238.97:45142] [client 45.58.238.97] ModSecurity: Warning. String match "200" at RESPONSE_STATUS. [file "/x/rules.conf"] [line "9"] [id "7700401"] [msg "xPGuard - Failed login: WordPress"] [tag "xpguard/login"] [hostname "websoulhost.com"] [uri "/wp-login.php"] [unique_id "` + uid + `"]`)
		return e
	}
	for i := 0; i < 3; i++ {
		m.handleEvent(login("L"+string(rune('a'+i))), st)
	}
	// A checkout attempt counts toward the ban, not as a login.
	co, _ := ParseLine(`[Sat Oct 25 06:01:00.471444 2026] [security2:error] [pid 1:tid 1] [client 45.58.238.98:45142] [client 45.58.238.98] ModSecurity: Warning. Pattern match "x" at REQUEST_URI. [file "/x/rules.conf"] [line "9"] [id "7700407"] [msg "xPGuard - Checkout attempt: WooCommerce"] [tag "xpguard/login"] [hostname "websoulhost.com"] [uri "/wp-json/wc/store/v1/checkout"] [unique_id "C1"]`)
	if co.Category != "login" {
		t.Fatalf("checkout category %q", co.Category)
	}
	m.handleEvent(co, st)
	// Every page the visitor opens is a redirect: one line in half an hour.
	for _, uid := range []string{"G1", "G2", "G3"} {
		m.handleEvent(gate(uid), st)
	}
	rows, err := m.DB.Query(`SELECT category, action, rule_id FROM waf_events WHERE ip = '45.58.238.97' ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for rows.Next() {
		var cat, action string
		var id int
		rows.Scan(&cat, &action, &id)
		got = append(got, cat+"/"+action)
	}
	rows.Close()
	want := "login/Logged,login/Logged,login/Logged,captcha/Sent to the CAPTCHA"
	if strings.Join(got, ",") != want {
		t.Fatalf("log: %v", got)
	}
	if len(fw.ips) != 0 {
		t.Fatalf("banned: %v", fw.ips)
	}
	// Not "Blocked attacks" (the counts on the page stay as they were).
	if s := m.countStats(); s.Blocked24h != 0 || s.Logins24h != 3 {
		t.Fatalf("stats %+v", s)
	}
}

// Every failed login tells the agent at once (it checks for a login attack
// within seconds, not at the next minute).
func TestFailedLoginNotifies(t *testing.T) {
	m := learnManager(t)
	m.Firewall = &banRecorder{}
	var got []string
	m.OnLoginFailed = func(host, ip string) { got = append(got, host+"|"+ip) }
	st := newTailState()
	e, _ := ParseLine(`[Sat Oct 25 06:01:00.471444 2026] [security2:error] [pid 1:tid 1] [client 45.58.241.5:45142] [client 45.58.241.5] ModSecurity: Warning. String match "200" at RESPONSE_STATUS. [file "/x/rules.conf"] [line "9"] [id "7700401"] [msg "xPGuard - Failed login: WordPress"] [tag "xpguard/login"] [hostname "websoulhost.com"] [uri "/wp-login.php"] [unique_id "N1"]`)
	m.handleEvent(e, st)
	if len(got) != 1 || got[0] != "websoulhost.com|45.58.241.5" {
		t.Fatalf("told: %v", got)
	}
}

// business600 (LiteSpeed, 2026-10-31): the self-test's score probes were
// refused even under threshold 100, and which rule refused them was not
// in the log (self-test lines are dropped). The probes' lines are kept
// now as "selftest", never counted or banned; the plain self-test URLs
// stay out.
func TestSelfTestProbesLogged(t *testing.T) {
	m := learnManager(t)
	fw := &banRecorder{}
	m.Firewall = fw
	st := newTailState()
	line := func(uri, uid string) Event {
		e, ok := ParseLine(`[Sat Oct 31 10:10:55.471444 2026] [security2:error] [pid 1:tid 1] [client 127.0.0.1:45142] [client 127.0.0.1] ModSecurity: Access denied with code 403 (phase 2). Matched "Operator ` + "`" + `Ge' with parameter ` + "`" + `10' against variable ` + "`" + `TX:BLOCKING_INBOUND_ANOMALY_SCORE' (Value: ` + "`" + `40' ) [file "/x/REQUEST-949-BLOCKING-EVALUATION.conf"] [line "9"] [id "949110"] [msg "Inbound Anomaly Score Exceeded (Total Score: 40)"] [hostname "127.0.0.1"] [uri "` + uri + `"] [unique_id "` + uid + `"]`)
		if !ok {
			t.Fatal("line not parsed")
		}
		return e
	}
	for i := 0; i < 12; i++ {
		m.handleEvent(line("/xpguard-crs-selftest/score/joomla_100", "S"+string(rune('a'+i))), st)
	}
	m.handleEvent(line("/xpguard-crs-selftest", "P1"), st)
	m.handleEvent(line("/xpguard-waf-selftest", "P2"), st)
	var n, other int
	m.DB.QueryRow(`SELECT count(*) FROM waf_events WHERE category = 'selftest' AND uri LIKE '/xpguard-crs-selftest/score/%'`).Scan(&n)
	m.DB.QueryRow(`SELECT count(*) FROM waf_events WHERE category != 'selftest'`).Scan(&other)
	if n != 12 || other != 0 {
		t.Fatalf("selftest rows %d, others %d", n, other)
	}
	if len(fw.ips) != 0 {
		t.Fatalf("banned: %v", fw.ips)
	}
}

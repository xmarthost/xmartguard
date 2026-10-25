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

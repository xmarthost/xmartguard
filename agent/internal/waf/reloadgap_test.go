package waf

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/store"
)

// Tests change address lists and check the result at once.
func TestMain(m *testing.M) {
	ListReloadGap = func(bool, bool) time.Duration { return 0 }
	PassSettle = 0
	ServiceDownWait = 0
	LiteSpeedMinGap, LiteSpeedNowWait = 0, 0
	os.Exit(m.Run())
}

// countReloads is a Target whose test and reload commands only count.
func countReloads(t *testing.T, liteSpeed bool) (Target, func() []string) {
	dir := t.TempDir()
	log := filepath.Join(dir, "calls.log")
	script := func(name string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("#!/bin/sh\necho "+name+" >>"+log+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	tg := Target{Name: "cpanel", ModSec: true, Engine: "On", LiteSpeed: liteSpeed,
		IncludeFile: filepath.Join(dir, "include.conf"),
		configTest:  []string{script("configtest")}, reload: []string{script("restartsrv_httpd")}}
	old := liteSpeedRestart
	liteSpeedRestart = []string{script("lswsctrl")}
	t.Cleanup(func() { liteSpeedRestart = old })
	return tg, func() []string {
		b, _ := os.ReadFile(log)
		return strings.Fields(string(b))
	}
}

func TestLiteSpeedRestartsOnce(t *testing.T) {
	tg, calls := countReloads(t, true)
	m := &Manager{RulesDir: t.TempDir()}
	if err := m.install(tg, "SecRule A", nil); err != nil {
		t.Fatal(err)
	}
	// cPanel's restartsrv_httpd restarts LiteSpeed as well: never both.
	if got := strings.Join(calls(), ","); got != "configtest,lswsctrl" {
		t.Fatalf("calls = %s, want one config test and one LiteSpeed restart", got)
	}
}

func TestAddressListsWaitForTheReloadGap(t *testing.T) {
	old := ListReloadGap
	t.Cleanup(func() { ListReloadGap = old })
	ListReloadGap = func(liteSpeed, pass bool) time.Duration {
		if pass {
			return 300 * time.Millisecond
		}
		return time.Hour
	}
	tg, calls := countReloads(t, true)
	m := &Manager{RulesDir: t.TempDir()}
	reloads := func() int { return strings.Count(strings.Join(calls(), ","), "lswsctrl") }
	lists := func(ipdb, pass string) map[string]string {
		return map[string]string{FileIPDBIPs: ipdb, FileCaptchaPass: pass, FileBadBots: "sqlmap\n"}
	}
	if err := m.install(tg, "SecRule A", lists("192.0.2.1\n", "127.0.0.2\n")); err != nil {
		t.Fatal(err)
	}
	// A new IPDB list right after a reload waits (and is not written yet).
	if err := m.install(tg, "SecRule A", lists("192.0.2.1\n192.0.2.2\n", "127.0.0.2\n")); err != nil {
		t.Fatal(err)
	}
	if reloads() != 1 {
		t.Fatalf("an IPDB list update restarted LiteSpeed again (%d restarts)", reloads())
	}
	if b, _ := os.ReadFile(filepath.Join(m.RulesDir, FileIPDBIPs)); string(b) != "192.0.2.1\n" {
		t.Fatalf("the waiting list was written: %q", b)
	}
	if m.deferred == nil {
		t.Fatal("no reload scheduled for the waiting list")
	}
	m.deferred.Stop()
	// A visitor who solved the CAPTCHA is let through before install
	// returns (the visitor is sent back then), after only the short gap.
	start := time.Now()
	if err := m.install(tg, "SecRule A", lists("192.0.2.1\n192.0.2.2\n", "127.0.0.2\n203.0.113.5\n")); err != nil {
		t.Fatal(err)
	}
	if reloads() != 2 {
		t.Fatalf("a CAPTCHA pass was put off (%d restarts)", reloads())
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("a CAPTCHA pass waited %v", d)
	}
	// Rules and bot lists apply at once.
	if err := m.install(tg, "SecRule B", lists("192.0.2.1\n", "127.0.0.2\n203.0.113.5\n")); err != nil {
		t.Fatal(err)
	}
	if reloads() != 3 {
		t.Fatalf("a rule change waited (%d restarts)", reloads())
	}
	// A pass that only expires is not urgent.
	if err := m.install(tg, "SecRule B", lists("192.0.2.1\n", "127.0.0.2\n")); err != nil {
		t.Fatal(err)
	}
	if reloads() != 3 {
		t.Fatalf("an expired pass restarted LiteSpeed (%d restarts)", reloads())
	}
	m.deferred.Stop()
	// Changes someone made (ApplyNow) do not wait.
	if err := m.installMode(tg, "SecRule B", lists("192.0.2.9\n", "127.0.0.2\n"), modeNow); err != nil {
		t.Fatal(err)
	}
	if reloads() != 4 {
		t.Fatalf("ApplyNow waited (%d restarts)", reloads())
	}
	// Periodic refreshes (learned exclusions, fleet intelligence) wait even
	// when the rules changed.
	if err := m.installMode(tg, "SecRule C", lists("192.0.2.9\n", "127.0.0.2\n"), modeBackground); err != nil {
		t.Fatal(err)
	}
	if reloads() != 4 {
		t.Fatalf("a background refresh restarted LiteSpeed (%d restarts)", reloads())
	}
	if m.deferred == nil {
		t.Fatal("no reload scheduled for the background refresh")
	}
	m.deferred.Stop()
}

// A visitor solving the CAPTCHA again although already on the pass list:
// the server is reloaded again (LiteSpeed's old processes still served the
// visitor), but not more than every 20 seconds.
func TestRepeatedPassReloadsAgain(t *testing.T) {
	tg, calls := countReloads(t, true)
	m := &Manager{RulesDir: t.TempDir(), target: tg}
	if err := m.RefreshPasses(); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(calls(), ","); got != "lswsctrl" {
		t.Fatalf("calls = %s, want one LiteSpeed restart", got)
	}
	if err := m.RefreshPasses(); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(strings.Join(calls(), ","), "lswsctrl"); n != 1 {
		t.Fatalf("%d restarts within 20 seconds", n)
	}
	m.lastReload = time.Now().Add(-time.Minute)
	if err := m.RefreshPasses(); err != nil || strings.Count(strings.Join(calls(), ","), "lswsctrl") != 2 {
		t.Fatalf("no restart after the gap: %v %v", calls(), err)
	}
	// No web server with ModSecurity: nothing to reload.
	if err := (&Manager{}).RefreshPasses(); err != nil {
		t.Fatal(err)
	}
}

// A pass that waits out the gap first (PassReloadWait) is reloaded at once
// afterwards, so passes that arrived during the wait share that reload.
func TestPassReloadWait(t *testing.T) {
	old := ListReloadGap
	t.Cleanup(func() { ListReloadGap = old })
	ListReloadGap = func(liteSpeed, pass bool) time.Duration {
		if pass && liteSpeed {
			return 300 * time.Millisecond
		}
		return time.Hour
	}
	tg, calls := countReloads(t, true)
	m := &Manager{RulesDir: t.TempDir(), target: tg}
	if w := m.PassReloadWait(); w != 0 {
		t.Fatalf("wait before any reload: %v", w)
	}
	pass := func(list string) map[string]string { return map[string]string{FileCaptchaPass: list} }
	if err := m.install(tg, "SecRule A", pass("203.0.113.1\n")); err != nil {
		t.Fatal(err)
	}
	w := m.PassReloadWait()
	if w <= 0 || w > 300*time.Millisecond {
		t.Fatalf("wait right after a reload: %v", w)
	}
	time.Sleep(w)
	// Two visitors solved it during the wait: one reload for both, no
	// further wait.
	start := time.Now()
	if err := m.install(tg, "SecRule A", pass("203.0.113.1\n203.0.113.2\n203.0.113.3\n")); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 200*time.Millisecond {
		t.Fatalf("the pass waited again after the gap: %v", d)
	}
	if n := strings.Count(strings.Join(calls(), ","), "lswsctrl"); n != 2 {
		t.Fatalf("%d restarts, want 2", n)
	}
	if ListReloadGap = old; old(true, true) > 30*time.Second {
		t.Fatalf("a CAPTCHA pass on LiteSpeed may wait %v", old(true, true))
	}
}

// A check script that answers "service is down" the first n times.
func downScript(t *testing.T, dir, log string, n int) string {
	p := filepath.Join(dir, "configtest")
	cnt := filepath.Join(dir, "count")
	body := "#!/bin/sh\necho configtest >>" + log + "\nc=$(cat " + cnt + " 2>/dev/null || echo 0)\nc=$((c+1))\necho $c >" + cnt +
		"\nif [ $c -le " + fmt.Sprint(n) + " ]; then echo \"(XID bze9zy) The \\\"httpd\\\" service is down.\"; exit 1; fi\n"
	if err := os.WriteFile(p, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// restartsrv_httpd --check caught while LiteSpeed restarts said "The httpd
// service is down" and the new rules were rolled back (business200, 13
// times a day). It is asked again; rules stay when LiteSpeed comes back.
func TestLiteSpeedDownDuringRestartKeepsRules(t *testing.T) {
	tg, calls := countReloads(t, true)
	dir := filepath.Dir(tg.IncludeFile)
	tg.configTest = []string{downScript(t, dir, filepath.Join(dir, "calls.log"), 2)}
	m := &Manager{RulesDir: t.TempDir()}
	if err := m.install(tg, "SecRule A", nil); err != nil {
		t.Fatalf("rules rolled back: %v", err)
	}
	if got := strings.Join(calls(), ","); got != "configtest,configtest,configtest,lswsctrl" {
		t.Fatalf("calls = %s", got)
	}
	if b, _ := os.ReadFile(tg.IncludeFile); len(b) == 0 {
		t.Fatal("include not written")
	}
}

// Still down after the retries: the rules (not yet loaded) are not the
// cause, so LiteSpeed is restarted with them and checked again.
func TestLiteSpeedStillDownRestartsAndChecks(t *testing.T) {
	tg, calls := countReloads(t, true)
	dir := filepath.Dir(tg.IncludeFile)
	tg.configTest = []string{downScript(t, dir, filepath.Join(dir, "calls.log"), 4)}
	m := &Manager{RulesDir: t.TempDir()}
	if err := m.install(tg, "SecRule A", nil); err != nil {
		t.Fatalf("install: %v", err)
	}
	if got := strings.Join(calls(), ","); got != "configtest,configtest,configtest,configtest,lswsctrl,configtest" {
		t.Fatalf("calls = %s", got)
	}
}

// A real refusal (not "service is down") still rolls back at once, and on
// Apache "down" is never retried.
func TestRefusedRulesStillRollBack(t *testing.T) {
	tg, calls := countReloads(t, true)
	dir := filepath.Dir(tg.IncludeFile)
	bad := filepath.Join(dir, "bad")
	os.WriteFile(bad, []byte("#!/bin/sh\necho configtest >>"+filepath.Join(dir, "calls.log")+"\necho 'Syntax error on line 3'\nexit 1\n"), 0o755)
	tg.configTest = []string{bad}
	m := &Manager{RulesDir: t.TempDir()}
	if err := m.install(tg, "SecRule A", nil); err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("err = %v", err)
	}
	if got := strings.Join(calls(), ","); got != "configtest" {
		t.Fatalf("calls = %s", got)
	}
	if _, err := os.Stat(tg.IncludeFile); err == nil {
		t.Fatal("refused rules left in place")
	}
	ap, calls2 := countReloads(t, false)
	d2 := filepath.Dir(ap.IncludeFile)
	ap.configTest = []string{downScript(t, d2, filepath.Join(d2, "calls.log"), 1)}
	if err := (&Manager{RulesDir: t.TempDir()}).install(ap, "SecRule A", nil); err == nil {
		t.Fatal("Apache: down not reported")
	}
	if got := strings.Join(calls2(), ","); got != "configtest" {
		t.Fatalf("Apache calls = %s", got)
	}
}

// A WebAdmin rule set naming xpguard-waf.conf on cPanel (business200: the
// file was missing) gets an empty file: the rules load through
// modsec2.user.conf, and LiteSpeed must not fail if the set is switched on.
func TestStaleLiteSpeedRuleSetGetsStub(t *testing.T) {
	tg, _ := countReloads(t, true)
	dir := t.TempDir()
	old := LiteSpeedConf
	LiteSpeedConf = filepath.Join(dir, "httpd_config.xml")
	t.Cleanup(func() { LiteSpeedConf = old })
	os.WriteFile(LiteSpeedConf, []byte("<censorshipRuleSet><name>xPGuard</name><ruleSet>Include $SERVER_ROOT/conf/xpguard-waf.conf</ruleSet></censorshipRuleSet>"), 0o644)
	if err := (&Manager{RulesDir: t.TempDir()}).install(tg, "SecRule A", nil); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "xpguard-waf.conf"))
	if err != nil || strings.Contains(string(b), "SecRule") {
		t.Fatalf("stub %q %v", b, err)
	}
	// An existing file is left alone.
	os.WriteFile(filepath.Join(dir, "xpguard-waf.conf"), []byte("own"), 0o644)
	if staleRuleSetFile() != "" {
		t.Fatal("an existing rule set file would be replaced")
	}
}

// After an agent update on LiteSpeed servers the load went up: the WAF
// start, the portal's rule sync and the CAPTCHA settings each restarted
// LiteSpeed within a minute, and every restart left the old "nobody"
// processes serving their connections. Restarts are LiteSpeedMinGap
// apart, also across an agent restart; what comes sooner is done later
// in one restart, and a change someone made waits for the gap.
func TestLiteSpeedRestartsSpacedOut(t *testing.T) {
	oldGap, oldNow := LiteSpeedMinGap, LiteSpeedNowWait
	t.Cleanup(func() { LiteSpeedMinGap, LiteSpeedNowWait = oldGap, oldNow })
	LiteSpeedMinGap, LiteSpeedNowWait = time.Hour, 0
	dir := t.TempDir()
	t.Setenv("XG_STATE_DIR", filepath.Join(dir, "state"))
	db, err := store.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	tg, calls := countReloads(t, true)
	rules := t.TempDir()
	m := &Manager{RulesDir: rules, DB: db}
	reloads := func() int { return strings.Count(strings.Join(calls(), ","), "lswsctrl") }
	if err := m.install(tg, "SecRule A", nil); err != nil || reloads() != 1 {
		t.Fatalf("first restart: %d %v", reloads(), err)
	}
	// The next rule change right after: not now, scheduled once.
	if err := m.install(tg, "SecRule B", nil); err != nil || reloads() != 1 {
		t.Fatalf("second restart at once: %d %v", reloads(), err)
	}
	if m.deferred == nil {
		t.Fatal("no restart scheduled")
	}
	m.deferred.Stop()
	// The agent is updated (a new Manager): the last restart is remembered.
	m2 := &Manager{RulesDir: rules, DB: db}
	if err := m2.install(tg, "SecRule C", nil); err != nil || reloads() != 1 {
		t.Fatalf("restart right after the agent restart: %d %v", reloads(), err)
	}
	m2.deferred.Stop()
	// A change someone made waits out a short rest of the gap, then restarts.
	LiteSpeedMinGap, LiteSpeedNowWait = 300*time.Millisecond, 2*time.Second
	if err := m2.installMode(tg, "SecRule D", nil, modeNow); err != nil || reloads() != 2 {
		t.Fatalf("ApplyNow: %d %v", reloads(), err)
	}
	// Apache re-reads its configuration: no gap.
	tga, callsA := countReloads(t, false)
	ma := &Manager{RulesDir: t.TempDir()}
	for _, r := range []string{"SecRule A", "SecRule B"} {
		if err := ma.install(tga, r, nil); err != nil {
			t.Fatal(err)
		}
	}
	if n := strings.Count(strings.Join(callsA(), ","), "restartsrv_httpd"); n != 2 {
		t.Fatalf("Apache reloads: %d", n)
	}
}

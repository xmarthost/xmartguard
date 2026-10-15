package waf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Tests change address lists and check the result at once.
func TestMain(m *testing.M) {
	ListReloadGap = func(bool, bool) time.Duration { return 0 }
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

package waf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xmarthost/xmartguard/agent/internal/settings"
)

func TestRemoteFromLogs(t *testing.T) {
	dir := t.TempDir()
	good := "https://rules.example/download.php?rules=generic&extra=webshell"
	bad := "https://rules.example/bad"
	log := filepath.Join(dir, "error_log")
	_ = os.WriteFile(log, []byte(strings.Join([]string{
		`[Mon Sep 28 12:00:00 2026] [security2:notice] ModSecurity: Loaded 0 rules from: '` + good + `'.`,
		`[Mon Sep 28 12:00:00 2026] [security2:notice] ModSecurity: Problems loading external resources: Failed to download: "` + good + `" error: HTTP response code said error.`,
		`[Mon Sep 28 12:10:00 2026] [security2:notice] ModSecurity: Loaded 2750 rules from: '` + good + `'.`,
		`[Mon Sep 28 12:10:00 2026] [security2:notice] ModSecurity: Loaded 0 rules from: '` + bad + `'.`,
		`[Mon Sep 28 12:10:00 2026] [security2:notice] ModSecurity: Problems loading external resources: Failed to download: "` + bad + `" error: HTTP response code said error.`,
		``,
	}, "\n")), 0o644)

	m := &Manager{}
	m.ruleSets.Remote = []RemoteRules{{ID: "ok", Key: "K.1", URL: good}, {ID: "bad", Key: "K.2", URL: bad}, {ID: "new", Key: "K.3", URL: "https://rules.example/new"}}
	states := []RuleSetState{
		{ID: "remote:ok", State: "active", Detail: "loaded by ModSecurity from x; POST blocklist rbl.example.net"},
		{ID: "remote:bad", State: "active"},
		{ID: "remote:new", State: "active"},
		{ID: "custom", State: "active"},
	}
	m.checkRemoteStates(states, []string{filepath.Join(dir, "missing"), log})
	if states[0].State != "active" || !strings.HasPrefix(states[0].Detail, "2750 rules loaded") || !strings.HasSuffix(states[0].Detail, "POST blocklist rbl.example.net") {
		t.Fatalf("ok: %+v", states[0])
	}
	if states[1].State != "error" || !strings.Contains(states[1].Detail, "license") {
		t.Fatalf("bad: %+v", states[1])
	}
	if states[2].State != "active" || !strings.Contains(states[2].Detail, "not logged") {
		t.Fatalf("new: %+v", states[2])
	}
	if states[3].Detail != "" {
		t.Fatalf("custom touched: %+v", states[3])
	}
}

func TestGateRules(t *testing.T) {
	c := settings.Defaults().WAF
	c.LoginURLs = []string{"/wp-login.php", "/admin/index.php"}
	off := Render(c, Options{Dir: "/x"})
	if strings.Contains(off, "xg_gate") {
		t.Fatal("gate rendered while off")
	}
	on := Render(c, Options{Dir: "/x", Gate: &Gate{Tokens: []string{"0123456789abcdef0123456789abcdef", "bad token\""}, HTTPPort: 7780, HTTPSPort: 7743}})
	for _, want := range []string{
		`SecRule REQUEST_COOKIES:xg_gate "@rx ^(?:0123456789abcdef0123456789abcdef)$" "id:7700901`,
		`redirect:http://%{REQUEST_HEADERS.Host}:7780/.xmartguard/gate?back=%{REQUEST_URI}`,
		`redirect:https://%{REQUEST_HEADERS.Host}:7743/.xmartguard/gate?back=%{REQUEST_URI}`,
		`(?:/wp-login\.php|/admin/index\.php)$`,
	} {
		if !strings.Contains(on, want) {
			t.Fatalf("missing %q in\n%s", want, on)
		}
	}
	if strings.Contains(on, "bad token") {
		t.Fatal("invalid token rendered")
	}
}

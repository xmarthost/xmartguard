package waf

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xmarthost/xmartguard/agent/internal/settings"
	"github.com/xmarthost/xmartguard/agent/internal/store"
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
		`SecRule &REQUEST_HEADERS:Cookie "@eq 0" "t:none"`,
		`SecRule REQUEST_HEADERS:Cookie "!@rx (?:^|;)\s*xg_gate=(?:0123456789abcdef0123456789abcdef)\s*(?:;|$)" "t:none"`,
		`redirect:https://%{REQUEST_HEADERS.Host}:7743/.xpguard/gate?back=%{REQUEST_URI}`,
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

func TestFeedHitsAndVendorRBL(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "error_log")
	_ = os.WriteFile(log, []byte(`[Mon Sep 28 16:14:32 2026] [error] [client 195.160.216.121] ModSecurity: Access denied with code -, [Rule: 'REMOTE_ADDR' '@rbl rbl.malware.expert'] [id "400010"] [msg "Malware.Expert - Malware host detected by rbl.malware.expert"] [tag "MEWAF"] [uri "/wp-login.php"]
[Mon Sep 28 16:15:36 2026] [error] [client 91.200.239.38] ModSecurity: Access denied with code -, [id "7700503"] [msg "xPGuard - AI crawler blocked"]
`), 0o644)
	link := filepath.Join(dir, "link_log")
	_ = os.Symlink(log, link)
	url := "https://rules.malware.expert/download.php?rules=generic&extra=webshell,rbl"
	if n := feedHits([]string{log, link}, url); n != 1 {
		t.Fatalf("hits %d", n)
	}
	m := &Manager{}
	m.ruleSets.Remote = []RemoteRules{{ID: "me", Key: "K.1", URL: url}}
	st := []RuleSetState{{ID: "remote:me", State: "active"}}
	m.checkRemoteStates(st, []string{log})
	if !strings.HasPrefix(st[0].Detail, "working: 1 requests blocked") {
		t.Fatalf("%+v", st[0])
	}
	if !vendorHasRBL(url, "rbl.malware.expert") || vendorHasRBL("https://rules.malware.expert/download.php?rules=generic", "rbl.malware.expert") {
		t.Fatal("vendorHasRBL")
	}
	// Our POST blocklist is not rendered twice when the feed has its own.
	mm := &Manager{RulesDir: t.TempDir()}
	var rs RuleSets
	rs.Remote = []RemoteRules{{ID: "me", Name: "Malware.Expert", Key: "ABCD.1", URL: url, Enabled: true, RBL: "rbl.malware.expert"}}
	mm.SetRuleSets(rs)
	inc, _, _ := mm.extras(Target{Name: "rhel"})
	if strings.Contains(inc, "7700801") {
		t.Fatal(inc)
	}
}

func TestVendorLoginCaptcha(t *testing.T) {
	m := &Manager{RulesDir: t.TempDir()}
	var rs RuleSets
	rs.Remote = []RemoteRules{{ID: "me", Name: "Malware.Expert", Key: "ABCD.1", URL: "https://rules.malware.expert/download.php?rules=generic&extra=webshell,recaptcha", Enabled: true}}
	m.SetRuleSets(rs)
	if m.VendorLoginCaptcha() != "Malware.Expert" {
		t.Fatal("recaptcha extra not seen")
	}
	_, _, states := m.extras(Target{Name: "rhel"})
	if !strings.Contains(states[len(states)-2].Detail, "login CAPTCHA by Malware.Expert") {
		t.Fatalf("%+v", states)
	}
	rs.Remote[0].URL = "https://rules.malware.expert/download.php?rules=generic&extra=webshell"
	m.SetRuleSets(rs)
	if m.VendorLoginCaptcha() != "" {
		t.Fatal("no recaptcha extra")
	}
	rs.Remote[0].URL, rs.Remote[0].Enabled = "https://rules.malware.expert/download.php?rules=generic&extra=recaptcha", false
	m.SetRuleSets(rs)
	if m.VendorLoginCaptcha() != "" {
		t.Fatal("disabled feed counted")
	}
}

// Where Malware.Expert replaces xPGuard's rules only the failed-login
// detectors remain: nothing of ours blocks a request there.
func TestRenderLoginWatch(t *testing.T) {
	c := settings.Defaults().WAF
	c.LoginURLs = []string{"/wp-login.php", "/my-login"}
	out := RenderLoginWatch(c, "Malware.Expert")
	if strings.Contains(out, "deny") || strings.Contains(out, "redirect:") || strings.Contains(out, "@pmFromFile") || strings.Contains(out, "@inspectFile") {
		t.Fatalf("blocking rule kept:\n%s", out)
	}
	for _, want := range []string{"Malware.Expert's rules are used instead", "id:7700401", "Failed login: WordPress", "/wp-login.php", "(?:/my-login)$"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in\n%s", want, out)
		}
	}
	c.BruteForce = false
	if strings.Contains(RenderLoginWatch(c, "Malware.Expert"), "SecRule") {
		t.Fatal("rules with brute force off")
	}
	m := &Manager{}
	if m.OwnRulesReplacedBy() != "" {
		t.Fatal("replaced without portal config")
	}
	var rs RuleSets
	rs.OwnRules = &struct {
		Enabled    bool   `json:"enabled"`
		ReplacedBy string `json:"replaced_by,omitempty"`
	}{true, "Malware.Expert"}
	m.SetRuleSets(rs)
	if m.OwnRulesReplacedBy() != "Malware.Expert" {
		t.Fatal("replacement not seen")
	}
}

func TestVendorRulesList(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XG_STATE_DIR", filepath.Join(dir, "state"))
	t.Setenv("XG_CONFIG_DIR", filepath.Join(dir, "conf"))
	db, _ := store.Open()
	defer db.Close()
	st, _ := settings.Load()
	st.Patch([]byte(`{"waf":{"disabled_rules":[1000050, 7700201]}}`))
	m := &Manager{DB: db, Settings: st}
	var rs RuleSets
	rs.OwnRules = &struct {
		Enabled    bool   `json:"enabled"`
		ReplacedBy string `json:"replaced_by,omitempty"`
	}{true, "Malware.Expert"}
	rs.Remote = []RemoteRules{{ID: "me", Name: "Malware.Expert", Key: "K.1", Enabled: true, URL: "https://rules.malware.expert/download.php?rules=generic&extra=webshell,rbl,recaptcha"}}
	m.SetRuleSets(rs)
	now := store.Now()
	for _, e := range []struct {
		id  int
		msg string
		at  int64
	}{{400010, "Malware.Expert - Malware host detected", now}, {400010, "", now - 3*86400}, {7700201, "xPGuard - sensitive", now}, {942100, "CRS SQLi", now - 5*86400}, {1100050, "", now}} {
		db.Exec(`INSERT INTO waf_events (at, ip, rule_id, msg, category) VALUES (?, '203.0.113.9', ?, ?, 'waf')`, e.at, e.id, e.msg)
	}
	v := m.VendorRules()
	if v.Name != "Malware.Expert" || len(v.Packages) != 4 || v.Packages[0].Title != "Generic rules" || v.Packages[3].ID != "recaptcha" {
		t.Fatalf("packages: %+v", v.Packages)
	}
	ids := []int{}
	for _, r := range v.Rules {
		ids = append(ids, r.ID)
	}
	// Ours and CRS are left out; switched-off vendor rules stay listed.
	if fmt.Sprint(ids) != "[400010 1100050 1000050]" {
		t.Fatalf("rules %v", ids)
	}
	if r := v.Rules[0]; r.Hits != 2 || r.Hits24h != 1 || r.Msg != "Malware.Expert - Malware host detected" || !r.Enabled {
		t.Fatalf("%+v", r)
	}
	if v.Rules[2].Enabled || !v.Rules[1].Enabled {
		t.Fatal("disabled rule shown on")
	}
	out := RenderLoginWatch(st.Get().WAF, "Malware.Expert")
	if !strings.Contains(out, "ctl:ruleRemoveById=1000050") {
		t.Fatalf("disabled vendor rule not removed:\n%s", out)
	}
}

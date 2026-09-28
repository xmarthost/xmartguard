package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// fakeAgent records calls and keeps settings in memory.
type fakeAgent struct {
	settings map[string]map[string]any
	calls    []string
	params   []map[string]any
}

func newFake() *fakeAgent {
	return &fakeAgent{settings: map[string]map[string]any{
		"scanner":  {"enabled": true, "whitelist_users": []any{"alice"}, "virus_action": "notify", "trim": false},
		"firewall": {"enabled": true, "tcp_in": "22,80,443", "blocked_countries": []any{}, "excluded_jails": []any{}},
		"ai":       {"enabled": true, "provider": "builtin", "scope": "suspicious"},
		"waf":      {"enabled": true, "disabled_rules": []any{float64(7700001)}},
	}}
}

func (f *fakeAgent) call(action string, params any) (json.RawMessage, error) {
	f.calls = append(f.calls, action)
	b, _ := json.Marshal(params)
	var p map[string]any
	_ = json.Unmarshal(b, &p)
	f.params = append(f.params, p)
	switch action {
	case "settings.get":
		return json.Marshal(map[string]any{"settings": f.settings})
	case "settings.set":
		for sec, v := range p {
			for k, x := range v.(map[string]any) {
				f.settings[sec][k] = x
			}
		}
		return json.Marshal(map[string]any{})
	case "findings.list":
		return json.Marshal(map[string]any{"total": 3, "findings": []map[string]any{
			{"id": 1, "path": "/home/bob/public_html/a.php", "owner": "bob", "signature": "PHP.Backdoor.EvalInput", "created_at": time.Now().Add(-2 * time.Hour).Unix()},
			{"id": 2, "path": "/home/bob/public_html/b.php", "owner": "bob", "signature": "PHP.Mailer", "created_at": time.Now().Add(-72 * time.Hour).Unix()},
			{"id": 3, "path": "/home/eve/c.php", "owner": "eve", "signature": "PHP.Backdoor.EvalInput", "created_at": time.Now().Unix()},
		}})
	case "finding.action":
		return json.Marshal(map[string]any{"done": len(p["ids"].([]any)), "failed": map[string]string{}})
	}
	return json.Marshal(map[string]any{"ok": true})
}

func run(t *testing.T, f *fakeAgent, args ...string) string {
	t.Helper()
	var out bytes.Buffer
	c := &cli{call: f.call, out: &out, cmd: args[0], args: args[1:]}
	if err := c.run(); err != nil {
		t.Fatalf("%v: %v", args, err)
	}
	return out.String()
}

func TestCLISettingsCommands(t *testing.T) {
	f := newFake()
	run(t, f, "whitelist", "--user", "--add", "bob,carol")
	if got := strList(f.settings["scanner"]["whitelist_users"]); strings.Join(got, ",") != "alice,bob,carol" {
		t.Fatalf("whitelist: %v", got)
	}
	run(t, f, "whitelist", "--user", "--remove", "alice")
	if got := strList(f.settings["scanner"]["whitelist_users"]); strings.Join(got, ",") != "bob,carol" {
		t.Fatalf("whitelist remove: %v", got)
	}
	run(t, f, "file-action", "--virus", "quarantine")
	if f.settings["scanner"]["virus_action"] != "quarantine" {
		t.Fatal("file-action")
	}
	run(t, f, "fw", "--port", "tcp-in", "--add", "2083", "--remove", "x")
	if f.settings["firewall"]["tcp_in"] != "22,80,443,2083" {
		t.Fatalf("port: %v", f.settings["firewall"]["tcp_in"])
	}
	run(t, f, "fw", "--deny-country", "cn", "RU")
	if got := strList(f.settings["firewall"]["blocked_countries"]); strings.Join(got, ",") != "CN,RU" {
		t.Fatalf("countries: %v", got)
	}
	run(t, f, "ai-scan", "--provider", "portal", "--scope", "all", "--learn", "enable")
	if f.settings["ai"]["provider"] != "portal" || f.settings["ai"]["scope"] != "all" || f.settings["ai"]["learn"] != true {
		t.Fatalf("ai: %v", f.settings["ai"])
	}
	run(t, f, "trim", "--enable", "--max", "15%")
	if f.settings["scanner"]["trim"] != true || f.settings["scanner"]["trim_max_percent"] != float64(15) {
		t.Fatalf("trim: %v", f.settings["scanner"])
	}
	run(t, f, "waf", "--whitelist", "--add", "7700002")
	if got := strList(f.settings["waf"]["disabled_rules"]); strings.Join(got, ",") != "7700001,7700002" {
		t.Fatalf("waf: %v", got)
	}
	run(t, f, "lfd", "--ignore", "sshd")
	if got := strList(f.settings["firewall"]["excluded_jails"]); strings.Join(got, ",") != "sshd" {
		t.Fatalf("lfd: %v", got)
	}
	if out := run(t, f, "dailyscan"); !strings.Contains(out, "daily scan: disabled") {
		t.Fatalf("show: %q", out)
	}
}

func TestCLILogActionFilters(t *testing.T) {
	f := newFake()
	out := run(t, f, "log-action", "--quarantine", "--user", "bob", "--from", "-24 hours", "--to", "now")
	last := f.params[len(f.params)-1]
	if f.calls[len(f.calls)-1] != "finding.action" || last["action"] != "quarantine" {
		t.Fatalf("calls: %v", f.calls)
	}
	if ids := last["ids"].([]any); len(ids) != 1 || ids[0] != float64(1) {
		t.Fatalf("ids: %v", ids)
	}
	if !strings.Contains(out, "quarantine: 1 done") {
		t.Fatalf("out: %q", out)
	}
	run(t, f, "log-action", "--trim", "--log-id", "3,2")
	if last := f.params[len(f.params)-1]; len(last["ids"].([]any)) != 2 || last["action"] != "trim" {
		t.Fatalf("log-id: %v", last)
	}
	var buf bytes.Buffer
	c := &cli{call: f.call, out: &buf, cmd: "log-action", args: []string{"--delete"}}
	if err := c.run(); err == nil {
		t.Fatal("log-action without filters must be refused")
	}
}

func TestCLIIPAndExpiry(t *testing.T) {
	f := newFake()
	run(t, f, "ip", "--temp-ban", "203.0.113.9", "--expiry", "2h", "--reason", "scanner")
	p := f.params[len(f.params)-1]
	if f.calls[len(f.calls)-1] != "fw.add" || p["kind"] != "tempban" || p["minutes"] != float64(120) || p["comment"] != "scanner" {
		t.Fatalf("temp-ban: %v %v", f.calls, p)
	}
	run(t, f, "ip", "--deny", "--remove", "198.51.100.0/24")
	if p := f.params[len(f.params)-1]; f.calls[len(f.calls)-1] != "fw.remove" || p["Kind"] != "deny" {
		t.Fatalf("remove: %v", p)
	}
	for in, want := range map[string]int{"30m": 30, "7d": 10080} {
		if got, err := parseExpiry(in); err != nil || got != want {
			t.Errorf("%s: %d %v", in, got, err)
		}
	}
	if _, err := parseWhen("01-08-2023"); err != nil {
		t.Fatal(err)
	}
}

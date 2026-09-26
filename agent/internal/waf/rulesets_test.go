package waf

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuditLogSerialEntry(t *testing.T) {
	entry := `--9a1b2c3d-A--
[27/Sep/2026:00:30:11.123456 +0500] ZabcUNIQUE 104.199.194.126 51234 10.0.0.5 443
--9a1b2c3d-B--
GET /wp-json/gravitysmtp/v1/tests/mock-data?page=gravitysmtp-settings HTTP/1.1
Host: www.shop.example
User-Agent: scanner

--9a1b2c3d-F--
HTTP/1.1 406 Not Acceptable

--9a1b2c3d-H--
Message: Access denied with code 406 (phase 2). String match "/wp-json/gravitysmtp/v1/tests/mock-data?page=gravitysmtp-settings" at REQUEST_URI. [file "/etc/apache2/conf.d/modsec_vendor_configs/VENDOR/10_rules.conf"] [line "12"] [id "500159"] [msg "Vendor - Wordpress Plugin - Gravity SMTP Sensitive Information Exposure"]
Action: Intercepted (phase 2)
Apache-Handler: application/x-httpd-ea-php82

--9a1b2c3d-Z--
`
	var p auditParser
	var got []Event
	for _, l := range strings.Split(entry, "\n") {
		if e, uid, ok := p.feed(l); ok {
			if uid != "ZabcUNIQUE" {
				t.Errorf("uid %q", uid)
			}
			got = append(got, e)
		}
	}
	if len(got) != 1 {
		t.Fatalf("events: %+v", got)
	}
	e := got[0]
	if e.IP != "104.199.194.126" || e.Host != "shop.example" || e.Method != "GET" || e.RuleID != 500159 ||
		!strings.HasPrefix(e.URI, "/wp-json/gravitysmtp") || e.Action != "Access denied with code 406" || e.Category != "waf" {
		t.Fatalf("event %+v", e)
	}

	// Warnings only (request passed): no event.
	warn := strings.Replace(strings.Replace(entry, "Access denied with code 406 (phase 2)", "Warning", 1), "Action: Intercepted (phase 2)\n", "", 1)
	p = auditParser{}
	for _, l := range strings.Split(warn, "\n") {
		if _, _, ok := p.feed(l); ok {
			t.Fatal("warning-only entry recorded")
		}
	}
}

func TestParseLiteSpeedAndDedupe(t *testing.T) {
	ls := `2026-09-27 00:30:11.391741 [NOTICE] [12345] [T0] [104.199.194.126:51234-Q:ABCD-1#APVH_www.shop.example:443] [Module:mod_security] mod_security rule [id "500159"] [msg "Vendor - Gravity SMTP"] Access denied with code 406 [uri "/wp-json/gravitysmtp/v1/tests/mock-data"] [unique_id "u1"]`
	e, ok := ParseLine(ls)
	if !ok || e.IP != "104.199.194.126" || e.Host != "shop.example" || e.RuleID != 500159 || e.UID != "u1" || !strings.HasPrefix(e.Action, "Access denied") {
		t.Fatalf("litespeed line: ok=%v %+v", ok, e)
	}
	s := newSeenIDs(2)
	if !s.add("a") || s.add("a") || !s.add("b") || !s.add("c") || !s.add("a") {
		t.Fatal("dedupe ring wrong")
	}
}

func TestValidateCustomRules(t *testing.T) {
	ok := "# block a path\nSecRule REQUEST_URI \"@beginsWith /old-admin\" \\\n  \"id:1000001,phase:1,deny,status:403,log,msg:'Old admin path'\"\nSecRuleRemoveById 942100\n"
	if err := ValidateCustomRules(ok); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]string{
		"apache directive": "CustomLog \"|/bin/sh -c id\" common",
		"exec action":      "SecRule ARGS \"@rx x\" \"id:1000002,phase:2,pass,exec:/tmp/x.sh\"",
		"inspectFile":      "SecRule FILES_TMPNAMES \"@inspectFile /tmp/x\" \"id:1000003,phase:2,deny\"",
		"from file":        "SecRule REMOTE_ADDR \"@ipMatchFromFile /etc/shadow\" \"id:1000004,phase:1,deny\"",
		"reserved id":      "SecAction \"id:7700009,phase:1,pass,nolog\"",
		"include":          "Include /etc/passwd",
	} {
		if ValidateCustomRules(bad) == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestExtrasRenderCRSAndCustom(t *testing.T) {
	dir := t.TempDir()
	m := &Manager{RulesDir: dir}
	files := map[string]string{
		"crs-setup.conf.example":                "SecDefaultAction \"phase:1,log,auditlog,pass\"\n",
		"rules/REQUEST-901-INITIALIZATION.conf": "SecAction \"id:901001,phase:1,pass,nolog\"\n",
		"rules/scanners-user-agents.data":       "sqlmap\n",
		"../escape.conf":                        "bad",
		"rules/../../x.conf":                    "bad",
	}
	if err := m.InstallCRS("4.29.0", files); err != nil {
		t.Fatal(err)
	}
	if exists(filepath.Join(dir, "escape.conf")) || exists(filepath.Join(dir, "crs", "x.conf")) {
		t.Fatal("path escaped the CRS directory")
	}
	var rs RuleSets
	rs.CRS.Enabled, rs.CRS.Version, rs.CRS.Paranoia = true, "4.29.0", 2
	rs.Custom.Enabled, rs.Custom.Rules = true, "SecRuleRemoveById 942100"
	m.SetRuleSets(rs)
	inc, extra, states := m.extras(Target{Name: "rhel"})
	if !strings.Contains(inc, filepath.Join(dir, "crs", "4.29.0", "rules", "*.conf")) || !strings.Contains(inc, "custom.conf") {
		t.Fatalf("includes: %s", inc)
	}
	setup := extra[filepath.Join(dir, "crs-setup.conf")]
	if !strings.Contains(setup, "blocking_paranoia_level=2") || !strings.Contains(setup, "inbound_anomaly_score_threshold=5") {
		t.Fatalf("setup: %s", setup)
	}
	if states[0].State != "active" || states[1].State != "active" {
		t.Fatalf("states %+v", states)
	}
	// Not downloaded yet: reported, not included.
	rs.CRS.Version = "4.30.0"
	m.SetRuleSets(rs)
	inc, _, states = m.extras(Target{Name: "rhel"})
	if strings.Contains(inc, "crs/") || states[0].State != "error" {
		t.Fatalf("missing CRS included: %s %+v", inc, states)
	}
}

// A fake whmapi1 that records calls and knows one installed vendor.
func TestApplyVendorsWithWHM(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "calls")
	fake := filepath.Join(dir, "whmapi1")
	os.WriteFile(fake, []byte(`#!/bin/sh
echo "$@" >> `+log+`
case "$2" in
modsec_get_vendors) echo '{"metadata":{"result":1},"data":{"vendors":[{"vendor_id":"MalwareExpert","name":"Malware.Expert","enabled":1,"update":1,"installed_from":"https://example.net/meta_me.yaml"},{"vendor_id":"comodo_litespeed","name":"Comodo","enabled":0,"update":0,"installed_from":"https://waf.comodo.com/doc/meta_comodo_litespeed.yaml"}]}}' ;;
modsec_add_vendor) echo '{"metadata":{"result":1},"data":{"vendor_id":"NewVendor"}}' ;;
*) echo '{"metadata":{"result":1},"data":{}}' ;;
esac
`), 0o755)
	old := WHMAPI
	WHMAPI = fake
	defer func() { WHMAPI = old }()
	managed := map[string]string{}
	vendors := []Vendor{
		{ID: "malware_expert", Name: "Malware.Expert", URL: "https://example.net/meta_me.yaml", Enabled: true},
		{ID: "comodo", Name: "Comodo", URL: "https://waf.comodo.com/doc/meta_comodo_apache.yaml", Enabled: true},
		{ID: "custom1", Name: "New", URL: "https://example.org/meta_new.yaml", Enabled: true},
	}
	states := ApplyVendors(context.Background(), Target{Name: "cpanel", LiteSpeed: true}, vendors, managed)
	for _, s := range states {
		if s.State != "active" {
			t.Fatalf("state %+v", s)
		}
	}
	calls, _ := os.ReadFile(log)
	c := string(calls)
	for _, want := range []string{
		"modsec_enable_vendor vendor_id=comodo_litespeed", // LiteSpeed variant, enabled
		"modsec_enable_vendor_updates vendor_id=comodo_litespeed",
		"modsec_add_vendor url=https://example.org/meta_new.yaml",
		"modsec_enable_vendor vendor_id=NewVendor",
	} {
		if !strings.Contains(c, want) {
			t.Errorf("missing call %q in:\n%s", want, c)
		}
	}
	if strings.Contains(c, "vendor_id=MalwareExpert") {
		t.Error("already enabled vendor was changed")
	}
	if managed["https://example.org/meta_new.yaml"] != "NewVendor" {
		t.Errorf("managed %+v", managed)
	}
	// Removed from the portal: the vendor the agent added is disabled.
	os.Remove(log)
	ApplyVendors(context.Background(), Target{Name: "cpanel", LiteSpeed: true}, vendors[:1], managed)
	calls, _ = os.ReadFile(log)
	if strings.Contains(string(calls), "modsec_disable_vendor vendor_id=MalwareExpert") {
		t.Error("kept vendor disabled")
	}
	// Without WHM: reported as unsupported.
	st := ApplyVendors(context.Background(), Target{Name: "rhel"}, vendors[:1], map[string]string{})
	if len(st) != 1 || st[0].State != "unsupported" {
		t.Fatalf("no WHM: %+v", st)
	}
}

func TestSystemCRSIsDetected(t *testing.T) {
	dir := t.TempDir()
	old := SystemCRSRoot
	SystemCRSRoot = dir
	defer func() { SystemCRSRoot = old }()
	if systemCRS(Target{Name: "debian"}) != "" && !exists("/etc/apache2/mods-enabled/security2.conf") {
		t.Fatal("detected without a package")
	}
	os.WriteFile(filepath.Join(dir, "owasp-crs.load"), []byte("x"), 0o644)
	if exists("/etc/apache2/mods-enabled/security2.conf") {
		b, _ := os.ReadFile("/etc/apache2/mods-enabled/security2.conf")
		want := strings.Contains(string(b), "\n\tIncludeOptional /usr/share/modsecurity-crs/") || strings.Contains(string(b), "\nIncludeOptional /usr/share/modsecurity-crs/")
		if got := systemCRS(Target{Name: "debian"}) != ""; got != want {
			t.Fatalf("debian CRS detection %v, want %v", got, want)
		}
	}
	if systemCRS(Target{Name: ""}) != "" {
		t.Fatal("unknown server detected")
	}
}

func TestCRSBlockIsNamedAfterTheAttack(t *testing.T) {
	warn := `[Sat Sep 26 19:55:15.2 2026] [security2:error] [pid 1] [client 203.0.113.5:4] [client 203.0.113.5] ModSecurity: Warning. detected SQLi using libinjection. [file "/x/REQUEST-942-APPLICATION-ATTACK-SQLI.conf"] [line "65"] [id "942100"] [msg "SQL Injection Attack Detected via libinjection"] [hostname "shop.example"] [uri "/"] [unique_id "Zq1"]`
	deny := `[Sat Sep 26 19:55:15.3 2026] [security2:error] [pid 1] [client 203.0.113.5:4] [client 203.0.113.5] ModSecurity: Access denied with code 403 (phase 2). Operator GE matched 5 at TX:anomaly_score. [file "/x/REQUEST-949-BLOCKING-EVALUATION.conf"] [line "94"] [id "949110"] [msg "Inbound Anomaly Score Exceeded (Total Score: 5)"] [hostname "shop.example"] [uri "/"] [unique_id "Zq1"]`
	r := newReasons(8)
	w, _ := ParseLine(warn)
	r.apply(w)
	d, _ := ParseLine(deny)
	d = r.apply(d)
	if d.Msg != "SQL Injection Attack Detected via libinjection (Total Score: 5)" {
		t.Fatalf("msg %q", d.Msg)
	}
}

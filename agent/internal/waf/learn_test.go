package waf

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/xmarthost/xmartguard/agent/internal/settings"
	"github.com/xmarthost/xmartguard/agent/internal/store"
)

func learnManager(t *testing.T) *Manager {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XG_STATE_DIR", filepath.Join(dir, "state"))
	t.Setenv("XG_CONFIG_DIR", filepath.Join(dir, "conf"))
	db, err := store.Open()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	st, _ := settings.Load()
	return &Manager{DB: db, Settings: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		IPDBIPs: func() []string { return []string{"203.0.113.0/24"} }}
}

func addEvent(t *testing.T, m *Manager, at int64, ip, host, uri string, rule int, detail string) {
	t.Helper()
	if _, err := m.DB.Exec(`INSERT INTO waf_events (at, ip, method, host, uri, rule_id, msg, category, action, user, detail) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		at, ip, "", host, uri, rule, "SQL Injection Attack Detected via libinjection (Total Score: 5)", "waf", "Access denied with code 403", "", detail); err != nil {
		t.Fatal(err)
	}
}

// TestLearnFalsePositives replays the patterns of a live server's log.
func TestLearnFalsePositives(t *testing.T) {
	m := learnManager(t)
	now := int64(1_800_000_000)
	sqli := "Matched rules: 942100 (REQUEST_COOKIES:cart)"
	// Real shoppers of one shop, different networks: product images blocked.
	for _, ip := range []string{"39.45.1.10", "39.45.1.11", "119.73.4.2", "175.29.8.9"} {
		addEvent(t, m, now-600, ip, "www.hapetsupplies.com", "/wp-content/uploads/2026/09/brush-variation-1-100x100.png", 949110, sqli)
		addEvent(t, m, now-5000, ip, "hapetsupplies.com", "/wp-content/uploads/2026/09/scoop-variation-2.png", 949110, sqli)
	}
	// An attack campaign: the same rule, but the addresses hit many sites
	// and other rules.
	for i, ip := range []string{"45.1.1.1", "46.2.2.2", "47.3.3.3", "48.4.4.4"} {
		addEvent(t, m, now-400, ip, "victim.example.org", "/search", 949110, sqli)
		addEvent(t, m, now-400, ip, "other"+string(rune('a'+i))+".example.org", "/search", 949110, sqli)
	}
	// Three visitors, but one is on the IPDB: two clean ones are not enough.
	for _, ip := range []string{"81.1.1.1", "82.2.2.2", "203.0.113.7"} {
		addEvent(t, m, now-300, ip, "shop.example.net", "/checkout/", 949110, sqli)
	}
	// Clean-looking visitors on a probe path are never learned.
	for _, ip := range []string{"91.1.1.1", "92.2.2.2", "93.3.3.3"} {
		addEvent(t, m, now-300, ip, "blog.example.net", "/.env", 949110, sqli)
	}
	// The home page would be a whole-website exclusion: never for an
	// attack rule, however many visitors.
	for i := 0; i < 12; i++ {
		addEvent(t, m, now-300-int64(i)*3000, fmt.Sprintf("%d.1.1.%d", 60+i, i), "toys.example.com", "/?utm_source=x", 949110, sqli)
	}
	// A "does not exist" probe from rotating clean addresses.
	for i := 0; i < 12; i++ {
		addEvent(t, m, now-300-int64(i)*3000, fmt.Sprintf("%d.2.2.%d", 100+i, i), "hawk.example.com", "/_probe-does-not-exist-9f3c", 949110, "Matched rules: 942550")
	}
	// A path that ends in a domain name.
	for i := 0; i < 12; i++ {
		addEvent(t, m, now-300-int64(i)*3000, fmt.Sprintf("%d.3.3.%d", 120+i, i), "quad.example.com", "/shop/page/3ymarketers.com", 949110, "Matched rules: 920440")
	}
	// A burst: five clean addresses within minutes is a scan, not visitors.
	for i := 0; i < 5; i++ {
		addEvent(t, m, now-300-int64(i)*60, fmt.Sprintf("%d.4.4.%d", 140+i, i), "burst.example.com", "/contact/", 949110, sqli)
	}
	// High-risk (PHP injection) needs six visitors from three networks: five here.
	for i := 0; i < 5; i++ {
		addEvent(t, m, now-300-int64(i)*3000, fmt.Sprintf("%d.5.5.%d", 160+i, i), "php.example.com", "/order/", 949110, "Matched rules: 933150")
	}
	// Three visitors from one network only.
	for _, ip := range []string{"10.9.0.1", "10.9.0.2", "10.9.0.3"} {
		addEvent(t, m, now-300, ip, "office.example.com", "/form/", 949110, sqli)
	}
	// Scanners that send an address as Host: never a website.
	for _, ip := range []string{"51.1.1.1", "52.2.2.2", "53.3.3.3", "54.4.4.4", "55.5.5.5"} {
		addEvent(t, m, now-300, ip, "127.0.0.1", "/cgi-sys/autodiscover.cgi", 949110, "Matched rules: 920350")
	}
	// Old events are outside the window.
	for _, ip := range []string{"71.1.1.1", "72.2.2.2", "73.3.3.3"} {
		addEvent(t, m, now-3*86400, ip, "old.example.com", "/page/", 949110, sqli)
	}

	changed, err := m.Learn(now)
	if err != nil {
		t.Fatal(err)
	}
	got := m.AutoExclusions()
	if !changed || len(got) != 1 {
		t.Fatalf("changed=%v, learned %+v", changed, got)
	}
	e := got[0]
	if e.Rule != 942100 || e.Domain != "hapetsupplies.com" || e.Path != "/wp-content/uploads/" || e.State != "active" || e.IPs != 4 || e.Where != "REQUEST_COOKIES:cart" {
		t.Fatalf("learned %+v", e)
	}
	// It is in the rules, for that website and path only.
	rules := Render(settings.WAF{}, Options{Dynamic: m.dynamic()})
	if !strings.Contains(rules, `"id:7704500,`) || !strings.Contains(rules, `@beginsWith /wp-content/uploads/" "t:none,t:urlDecodeUni,ctl:ruleRemoveById=942100"`) {
		t.Fatalf("learned exclusion not rendered:\n%s", rules)
	}
	// Learning again changes nothing.
	if changed, _ := m.Learn(now + 60); changed || len(m.AutoExclusions()) != 1 {
		t.Fatal("learned twice")
	}
	// Rejected: gone from the rules and not learned again.
	if err := m.SetAutoExclusion(e.Key, "reject"); err != nil {
		t.Fatal(err)
	}
	if m.Learn(now + 120); strings.Contains(Render(settings.WAF{}, Options{Dynamic: m.dynamic()}), "7704500") || m.AutoExclusions()[0].State != "rejected" {
		t.Fatal("rejected exclusion still used or learned again")
	}
	// Forgotten: learned again while the false positive goes on.
	m.SetAutoExclusion(e.Key, "forget")
	if changed, _ := m.Learn(now + 180); !changed || len(m.AutoExclusions()) != 1 {
		t.Fatal("not learned again after forget")
	}
	// Learned exclusions expire after 30 days.
	if changed, _ := m.Learn(now + 31*86400); !changed || len(m.AutoExclusions()) != 0 {
		t.Fatalf("not expired: %+v", m.AutoExclusions())
	}
}

// Exclusions learned under the old limits that the new ones refuse are
// dropped on the next run; good ones stay.
func TestLearnDropsLooseExclusions(t *testing.T) {
	m := learnManager(t)
	now := int64(1_800_000_000)
	ex := func(rule int, domain, path string, ips int) AutoExclusion {
		return AutoExclusion{RuleExclusion: settings.RuleExclusion{Rule: rule, Domain: domain, Path: path}, Key: fmt.Sprintf("%d|%s|%s", rule, domain, path), IPs: ips, Learned: now - 86400, Expires: now + 86400, State: "active"}
	}
	m.saveAuto([]AutoExclusion{
		ex(934100, "hawkdevops.net", "", 6),
		ex(942550, "hawkdevops.net", "/_probe-does-not-exist-9f3c", 5),
		ex(920420, "meetap.net", "", 5),
		ex(920440, "quadaxisglobal.com", "/shop/page/3ymarketers.com", 4),
		ex(920420, "pakluck.com", "", 9),
		ex(942290, "webco.pk", "/solar/wp-admin/admin-ajax.php", 3),
	})
	changed, err := m.Learn(now)
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	var left []string
	for _, e := range m.AutoExclusions() {
		left = append(left, e.Key)
	}
	sort.Strings(left)
	if strings.Join(left, ",") != "920420|pakluck.com|,942290|webco.pk|/solar/wp-admin/admin-ajax.php" {
		t.Fatalf("left %v", left)
	}
}

func TestLearnModes(t *testing.T) {
	m := learnManager(t)
	now := int64(1_800_000_000)
	for i, ip := range []string{"39.45.1.10", "119.73.4.2", "175.29.8.9"} {
		addEvent(t, m, now-60-int64(i)*3000, ip, "exflow.example.com", "/edit-transfer", 949110, "Matched rules: 942100 (ARGS:note), 949999")
	}
	m.Settings.Patch([]byte(`{"waf":{"auto_exclusions":"suggest"}}`))
	if changed, _ := m.Learn(now); changed {
		t.Fatal("suggest mode changed the rules")
	}
	l := m.AutoExclusions()
	if len(l) != 1 || l[0].State != "suggested" || l[0].Path != "/edit-transfer" || len(m.activeAuto()) != 0 {
		t.Fatalf("%+v", l)
	}
	m.SetAutoExclusion(l[0].Key, "accept")
	m.Settings.Patch([]byte(`{"waf":{"auto_exclusions":"auto"}}`))
	if len(m.activeAuto()) != 1 {
		t.Fatal("accepted suggestion not used")
	}
	m.Settings.Patch([]byte(`{"waf":{"auto_exclusions":"off"}}`))
	if len(m.activeAuto()) != 0 {
		t.Fatal("learned exclusions used while off")
	}
}

func TestLearnPath(t *testing.T) {
	for in, want := range map[string]string{
		"/wp-json/wp/v2/posts/912/autosaves?_locale=user": "/wp-json/wp/v2/posts/",
		"/edit-transfer":             "/edit-transfer",
		"/":                          "",
		"/?p=1":                      "",
		"//images//a.png":            "/images/a.png",
		"/customerSave/6298/":        "/customerSave/",
		"/a b":                       "-",
		"/product/arduino-leonardo/": "/product/arduino-leonardo/",
	} {
		if got := learnPath(in); got != want {
			t.Errorf("learnPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCPanelModsecOff(t *testing.T) {
	root := t.TempDir()
	old := CPanelUserdata
	CPanelUserdata = root
	defer func() { CPanelUserdata = old }()
	write := func(rel, body string) {
		p := filepath.Join(root, rel)
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(body), 0o644)
	}
	off := "<IfModule mod_security2.c>\n  SecRuleEngine Off\n</IfModule>\n"
	write("std/2_4/xenova/demo.xenovatech.co/modsec.conf", off)
	write("ssl/2_4/xenova/demo.xenovatech.co/modsec.conf", off)
	write("std/2_4/xenova/xenovatech.co/modsec.conf", "SecRuleEngine On\n")
	write("ssl/2_4/shop/Shop.Example.com/modsec.conf", off)
	write("std/2_4/shop/shop.example.com/other.conf", "# SecRuleEngine Off (a comment)\n")
	got := CPanelModsecOff()
	if strings.Join(got, ",") != "demo.xenovatech.co,shop.example.com" {
		t.Fatalf("%v", got)
	}
	rules := Render(settings.WAF{}, Options{Dynamic: Dynamic{CPanelOff: got}})
	want := `SecRule SERVER_NAME "@rx ^(?:www\.)?(?:demo\.xenovatech\.co|shop\.example\.com)$" "id:7700005,phase:1,t:none,t:lowercase,pass,nolog,ctl:ruleEngine=Off"`
	if !strings.Contains(rules, want) {
		t.Fatalf("missing %s in\n%s", want, rules)
	}
	if strings.Index(rules, "id:7700005") > strings.Index(rules, "id:7700010") {
		t.Fatal("the cPanel switch must come first")
	}
}

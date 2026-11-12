package cms

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// Owner, 2026-11-12: a newly disclosed hole is acted on within hours from
// the last inventory, not at the next 72-hour scan: updated; else the
// plugin's folder is shielded and a critical one deactivated; the shield
// goes once the plugin is updated.
func TestRapidResponse(t *testing.T) {
	m, _ := autoUpdateManager(t, `{"cms":{"auto_update":true}}`)
	base := t.TempDir()
	site := func(u string) string {
		root := filepath.Join(base, u, "public_html")
		fakeSite(t, root)
		os.MkdirAll(filepath.Join(root, "wp-content", "plugins", "cf7"), 0o755)
		os.MkdirAll(filepath.Join(root, "wp-content", "plugins", "pro"), 0o755)
		return root
	}
	a, b := site("alice"), site("bob")
	for _, p := range []string{a, b} {
		m.save(Site{Type: WordPress, Path: p, User: filepath.Base(filepath.Dir(p)), Version: "6.8.3", MUPlugins: []string{}, Themes: []Component{},
			Plugins: []Component{
				{Slug: "cf7", Version: "6.2.1", Latest: "6.2.5", Active: true},
				{Slug: "pro", Version: "3.0.1", Active: true}, // premium: wp-cli cannot update it
				{Slug: "safe", Version: "6.2.5", Latest: "6.2.5", Active: true},
			}})
	}
	// wp-cli: cf7 updates on alice only; pro never updates.
	var mu sync.Mutex
	var calls []string
	versions := map[string]string{"alice/cf7": "6.2.1", "bob/cf7": "6.2.1", "alice/pro": "3.0.1", "bob/pro": "3.0.1"}
	m.RunWPCLI = func(_ context.Context, path string, args ...string) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		u := filepath.Base(filepath.Dir(path))
		calls = append(calls, u+": "+strings.Join(args, " "))
		switch {
		case len(args) >= 3 && args[1] == "update" && args[2] == "cf7" && u == "alice":
			versions[u+"/cf7"] = "6.2.5"
			return "Success: Updated 1 of 1.", nil
		case len(args) >= 2 && args[1] == "update":
			return "Warning: cf7: Plugin already updated.\nSuccess: Plugin already updated.", nil
		case len(args) >= 3 && args[1] == "get":
			return versions[u+"/"+args[2]] + "\n", nil
		}
		return "Success", nil
	}
	cf7 := Advisory{ID: "wf-1", Kind: "plugin", Slug: "cf7", Title: "Contact Form 7 <= 6.2.3 - Unauthenticated Arbitrary File Upload", CVSS: 9.8,
		Ranges: []VRange{{From: "6.2", FromInc: true, To: "6.2.3", ToInc: true}}, Patched: []string{"6.2.4"}}
	pro := Advisory{ID: "wf-2", Kind: "plugin", Slug: "pro", Title: "Pro <= 3.0.5 - Privilege Escalation", CVSS: 8.1,
		Ranges: []VRange{{From: "*", To: "3.0.5", ToInc: true}}, Patched: []string{"3.0.6"}}
	low := Advisory{ID: "wf-3", Kind: "plugin", Slug: "safe", CVSS: 4.3, Ranges: []VRange{{From: "*", To: "9", ToInc: true}}}
	var acted []string
	m.OnAutoAction = func(s Site, acts []string) { acted = append(acted, s.User+": "+strings.Join(acts, " | ")) }

	if n := m.Rapid(context.Background(), []Advisory{cf7, pro, low}); n != 2 {
		t.Fatalf("sites acted on: %d\n%v", n, acted)
	}
	shield := func(root, slug string) string {
		b, _ := os.ReadFile(filepath.Join(root, "wp-content", "plugins", slug, ".htaccess"))
		return string(b)
	}
	// alice's cf7 updated: no shield; bob's could not: shielded and deactivated (critical).
	if shield(a, "cf7") != "" || !strings.Contains(shield(b, "cf7"), "Require all denied") {
		t.Errorf("cf7 shields: alice %q bob %q", shield(a, "cf7"), shield(b, "cf7"))
	}
	joined := strings.Join(calls, "\n")
	if !strings.Contains(joined, "bob: plugin deactivate cf7") || strings.Contains(joined, "alice: plugin deactivate cf7") {
		t.Errorf("deactivations:\n%s", joined)
	}
	// pro (8.1, no update): shielded, not deactivated; the low one untouched.
	if !strings.Contains(shield(a, "pro"), "wf-2 version 3.0.1") || strings.Contains(joined, "deactivate pro") || strings.Contains(joined, "safe") {
		t.Errorf("pro / low:\n%s\n%s", shield(a, "pro"), joined)
	}
	// Once only per advisory and version.
	calls = nil
	if n := m.Rapid(context.Background(), []Advisory{cf7, pro}); n != 0 || len(calls) != 0 {
		t.Errorf("acted again: %d %v", n, calls)
	}
	// The site's own .htaccess lines stay; the shield goes after an update.
	p := filepath.Join(b, "wp-content", "plugins", "cf7", ".htaccess")
	os.WriteFile(p, []byte("Options -Indexes\n"+shield(b, "cf7")), 0o644)
	s := Site{Path: b, Plugins: []Component{{Slug: "cf7", Version: "6.2.1"}}}
	if len(unshieldUpdated(&s)) != 0 {
		t.Error("shield lifted before the update")
	}
	s.Plugins[0].Version = "6.2.5"
	if got := unshieldUpdated(&s); len(got) != 1 || shield(b, "cf7") != "Options -Indexes\n" {
		t.Errorf("after update: %v %q", got, shield(b, "cf7"))
	}
	// A symlinked folder is not written through.
	ln := filepath.Join(b, "wp-content", "plugins", "evil")
	os.Symlink(t.TempDir(), ln)
	if Shield(ln, "x", "1") == nil {
		t.Error("shield written through a symlink")
	}
}

func TestAdvisoryAffects(t *testing.T) {
	a := Advisory{Ranges: []VRange{{From: "6.2", FromInc: true, To: "6.2.3", ToInc: true}, {From: "1.0", To: "1.5"}}}
	for v, want := range map[string]bool{"6.2": true, "6.2.3": true, "6.2.4": false, "6.1.9": false, "1.0": false, "1.2": true, "1.5": false, "": false} {
		if a.Affects(v) != want {
			t.Errorf("%q: %v", v, !want)
		}
	}
	if (Advisory{Ranges: []VRange{{From: "*", To: "*"}}}).Affects("3") != true {
		t.Error("open range")
	}
}

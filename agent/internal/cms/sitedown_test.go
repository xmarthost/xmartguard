package cms

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/xmarthost/xmartguard/agent/internal/store"
)

// superfast (2026-11-13): 1,993 of 2,991 automatic updates "failed", and
// every failure in the log was wp-cli's "Error establishing a database
// connection" on suspended or broken accounts. Those sites are not counted
// as failed patches: a suspended account is skipped, a site whose database
// does not answer gets one wp-cli call per pass, and the report lists both
// apart from real failures.
func TestAutoActionsSuspendedAndDatabaseDown(t *testing.T) {
	m, _ := autoUpdateManager(t, `{"cms":{"auto_update":true,"auto_update_cvss":0,"auto_update_days":0}}`)
	m.Suspended = func(u string) bool { return u == "susp" }
	calls := map[string]int{}
	m.RunWPCLI = func(_ context.Context, path string, _ ...string) (string, error) {
		calls[path]++
		if path == "/home/dbgone/public_html" {
			return "", errors.New("wp-cli failed: Error: Error establishing a database connection.")
		}
		return "", errors.New("wp-cli failed: Error: could not create directory.")
	}
	vul := []Vuln{{CVSS: 8, FixedIn: "2.0", Date: store.Now() - 30*86400}}
	site := func(user string) Site {
		return Site{Type: WordPress, Path: "/home/" + user + "/public_html", User: user, Version: "7.1.4", Latest: "7.1.4", MUPlugins: []string{},
			Plugins: []Component{
				{Slug: "one", Version: "1.0", Latest: "2.0", Vulns: vul},
				{Slug: "two", Version: "1.0", Latest: "2.0", Vulns: vul},
			}, Themes: []Component{}}
	}
	for _, u := range []string{"susp", "dbgone", "real"} {
		s := site(u)
		m.save(s)
		m.autoActions(context.Background(), &s)
	}
	if calls["/home/susp/public_html"] != 0 {
		t.Errorf("wp-cli ran on a suspended account: %d", calls["/home/susp/public_html"])
	}
	if calls["/home/dbgone/public_html"] != 1 {
		t.Errorf("site without a database: %d wp-cli calls, want 1", calls["/home/dbgone/public_html"])
	}
	if calls["/home/real/public_html"] != 2 {
		t.Errorf("a real failure still tries every update: %d", calls["/home/real/public_html"])
	}
	// The suspended account's earlier tries (before this version) count as
	// site down too.
	store.SetKV(m.DB, "cms_update_try|/home/susp/public_html|plugin|one|1.0", "1")
	r, err := m.VulnReport()
	if err != nil {
		t.Fatal(err)
	}
	if r.Failed != 2 || r.SiteDown != 2 || r.Suspended != 2 || r.SiteDownDue != 2 || r.DueNotPatch != 2 {
		t.Errorf("report: failed %d site_down %d suspended %d site_down_due %d due %d", r.Failed, r.SiteDown, r.Suspended, r.SiteDownDue, r.DueNotPatch)
	}
	// The database answers again: the mark goes with the first command
	// that works.
	m.RunWPCLI = func(context.Context, string, ...string) (string, error) {
		return "Success: Deactivated 1 of 1 plugins.", nil
	}
	m.Settings.Patch([]byte(`{"cms":{"blacklist_plugins":["one"]}}`))
	s := site("dbgone")
	s.Plugins[0].Active = true
	m.autoActions(context.Background(), &s)
	if store.GetKV(m.DB, siteDownKV+s.Path) != "" {
		t.Error("site-down mark kept after wp-cli worked")
	}
}

func TestAccountSuspendedMarkers(t *testing.T) {
	dir := t.TempDir()
	oldC, oldD := cpanelSuspendedDir, daUsersDir
	t.Cleanup(func() { cpanelSuspendedDir, daUsersDir = oldC, oldD })
	cpanelSuspendedDir, daUsersDir = filepath.Join(dir, "cp"), filepath.Join(dir, "da")
	os.MkdirAll(cpanelSuspendedDir, 0o755)
	os.WriteFile(filepath.Join(cpanelSuspendedDir, "cpuser"), []byte("abuse"), 0o644)
	for u, conf := range map[string]string{"dasusp": "name=dasusp\nsuspended=yes\n", "daok": "name=daok\nsuspended=no\n"} {
		os.MkdirAll(filepath.Join(daUsersDir, u), 0o755)
		os.WriteFile(filepath.Join(daUsersDir, u, "user.conf"), []byte(conf), 0o644)
	}
	for u, want := range map[string]bool{"cpuser": true, "dasusp": true, "daok": false, "nobody": false, "": false, "../cp/cpuser": false} {
		if got := accountSuspended(u); got != want {
			t.Errorf("accountSuspended(%q) = %v, want %v", u, got, want)
		}
	}
}

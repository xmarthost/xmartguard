package cms

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/settings"
	"github.com/xmarthost/xmartguard/agent/internal/store"
)

// The automatic update of vulnerable components (business200, 2026-10-26):
// with the default conditions (CVSS above 6, 7 days old) nothing was ever
// updated on most sites. Many new vulnerabilities have no CVSS score yet
// (FormLayer, Cart Abandonment Recovery, Astra), a critical one waited a
// week, WordPress core was never updated (WP2Shell), and a plugin a major
// version behind (Elementor 3 to 4) would have been jumped to a release
// that breaks sites.
func TestAutoUpdateDue(t *testing.T) {
	cfg := settings.Defaults().CMS // CVSS above 6, 7 days
	now := time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC).Unix()
	day := int64(86400)
	c := func(cvss float64, age int64) Component {
		return Component{Slug: "x", Version: "1.0", Latest: "1.2", Vulns: []Vuln{{CVSS: cvss, FixedIn: "1.1", Date: now - age*day}}}
	}
	for _, tc := range []struct {
		name string
		c    Component
		want bool
	}{
		{"high, old", c(7.5, 30), true},
		{"high, new: waits the days", c(7.5, 2), false},
		{"low", c(4.3, 30), false},
		{"no score yet, old", c(0, 30), true},
		{"no score yet, new: waits", c(0, 2), false},
		{"critical, disclosed today", c(9.8, 0), true},
		{"no update", Component{Version: "1.2", Latest: "1.2", Vulns: []Vuln{{CVSS: 9.8}}}, false},
		{"premium (no release known)", Component{Version: "4.6.5", Vulns: []Vuln{{CVSS: 8.8}}}, false},
		{"not vulnerable", Component{Version: "1.0", Latest: "1.2"}, false},
	} {
		if got := autoUpdateDue(cfg, tc.c, now); got != tc.want {
			t.Errorf("%s: due %v, want %v", tc.name, got, tc.want)
		}
	}

	args := func(kind string, c Component) string { a, _ := UpdateArgs(kind, c); return strings.Join(a, " ") }
	// A whole major version behind, fixed in its own branch: that release.
	if got := args("plugin", Component{Slug: "elementor", Version: "3.21.5", Latest: "4.3.5", Vulns: []Vuln{{FixedIn: "3.21.8"}, {FixedIn: "3.24.2"}}}); got != "plugin update elementor --version=3.24.2" {
		t.Errorf("major behind: %q", got)
	}
	// Same branch, or the fix is in the new major only, or a hole without a
	// fix: the newest release.
	for _, c := range []Component{
		{Slug: "metform", Version: "4.3.2", Latest: "4.3.3", Vulns: []Vuln{{FixedIn: "4.3.3"}}},
		{Slug: "astra", Version: "3.9.0", Latest: "4.14.1", Vulns: []Vuln{{FixedIn: "4.12.4"}}},
		{Slug: "wp-reset", Version: "1.5", Latest: "2.08", Vulns: []Vuln{{FixedIn: "1.6"}, {FixedIn: ""}}},
	} {
		if got := args("plugin", c); got != "plugin update "+c.Slug {
			t.Errorf("%s: %q", c.Slug, got)
		}
	}
	if got := args("core", Component{Version: "6.8.3"}); got != "core update --minor" {
		t.Errorf("core: %q", got)
	}
	// wp-cli takes only the options xPGuard passes.
	for a, ok := range map[string]bool{"--minor": true, "--all": true, "--version=3.24.2": true, "--exec=x": false, "--version=1;id": false} {
		if wpArgAllowed(a) != ok {
			t.Errorf("wpArgAllowed(%q) = %v", a, !ok)
		}
	}
}

type fakeWPRun struct {
	mu    sync.Mutex
	calls []string
	reply string
}

func (f *fakeWPRun) run(_ context.Context, path string, args ...string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, filepath.Base(filepath.Dir(path))+": "+strings.Join(args, " "))
	if f.reply == "" {
		return "Success: Updated 1 of 1.", nil
	}
	return f.reply, nil
}

func autoUpdateManager(t *testing.T, patch string) (*Manager, *fakeWPRun) {
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
	if _, err := st.Patch([]byte(patch)); err != nil {
		t.Fatal(err)
	}
	old := time.Now().AddDate(0, 0, -30).Format("2006-01-02")
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/core/version-check/"):
			fmt.Fprint(w, `{"offers":[{"current":"6.8.6"}]}`)
		case strings.Contains(r.URL.Path, "/plugins/info/"):
			fmt.Fprint(w, `{"version":"1.2.0"}`)
		case r.URL.Path == "/plugin/demo/":
			fmt.Fprintf(w, `{"error":0,"data":{"vulnerability":[{"name":"Demo < 1.1.0","operator":{"max_version":"1.1.0","max_operator":"lt"},"source":[{"id":"CVE-2026-1","date":%q}],"impact":{}}]}}`, old)
		case r.URL.Path == "/core/6.8.3/":
			fmt.Fprintf(w, `{"error":0,"data":{"vulnerability":[{"name":"WordPress 6.8.3","operator":{},"source":[{"id":"CVE-2026-60137","date":%q}],"impact":{"cvss":{"score":"9.8"}}}]}}`, old)
		default:
			fmt.Fprint(w, `{"error":0,"data":{"vulnerability":[]}}`)
		}
	}))
	t.Cleanup(api.Close)
	v := NewVersions(db)
	v.WPAPI = api.URL
	vd := NewVulnDB(db)
	vd.Base = api.URL
	f := &fakeWPRun{}
	return &Manager{DB: db, Settings: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Versions: v, Vulns: vd, RunWPCLI: f.run}, f
}

// fakeSite writes a WordPress 6.8.3 site with the plugin "demo" 1.0.0.
func fakeSite(t *testing.T, root string) {
	t.Helper()
	for p, body := range map[string]string{
		"wp-includes/version.php":            "<?php\n$wp_version = '6.8.3';\n",
		"wp-content/plugins/demo/demo.php":   "<?php\n/*\nPlugin Name: Demo\nVersion: 1.0.0\n*/\n",
		"wp-content/themes/plain/style.css":  "/*\nTheme Name: Plain\nVersion: 1.0\n*/\n",
		"wp-content/plugins/demo/readme.txt": "demo",
	} {
		os.MkdirAll(filepath.Join(root, filepath.Dir(p)), 0o755)
		os.WriteFile(filepath.Join(root, p), []byte(body), 0o644)
	}
}

// The daily check between the full scans: new holes are found and fixed
// within a day, and the core file and database results of the last full
// scan stay.
func TestVulnPass(t *testing.T) {
	m, wp := autoUpdateManager(t, `{"cms":{"auto_update":true}}`)
	root := filepath.Join(t.TempDir(), "alice", "public_html")
	fakeSite(t, root)
	m.save(Site{Type: WordPress, Path: root, User: "alice", Version: "6.8.3", Plugins: []Component{}, Themes: []Component{}, MUPlugins: []string{},
		Core: CoreReport{Unknown: []string{"wp-includes/x.php"}}, CoreIssues: 1, DBIssues: 2, Risk: "critical", ScannedAt: 1})
	if err := m.VulnPass(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(wp.calls, " | "); got != "alice: plugin update demo | alice: core update --minor" {
		t.Fatalf("wp-cli: %s", got)
	}
	sites, _, _ := m.Sites(SiteFilter{})
	s := sites[0]
	if s.CoreIssues != 1 || s.DBIssues != 2 || len(s.Core.Unknown) != 1 || s.ScannedAt != 1 {
		t.Fatalf("full scan results lost: %+v", s)
	}
	if len(s.Plugins) != 1 || s.Plugins[0].Latest != "1.2.0" || len(s.Plugins[0].Vulns) != 1 || len(s.Core.Vulns) != 1 {
		t.Fatalf("inventory: %+v core %+v", s.Plugins, s.Core.Vulns)
	}
	if store.GetKV(m.DB, kvVulnPass) == "" {
		t.Fatal("pass not recorded")
	}
	// "WordPress is up to date" (no security release yet) is no update.
	if !notUpdated("Success: WordPress is up to date.") {
		t.Fatal("core without a release counted as updated")
	}
}

// CMS Threat Alerts » Bulk update: the selected sites, one account's, or
// all (accounts never patched automatically left out unless selected).
func TestBulkUpdate(t *testing.T) {
	m, wp := autoUpdateManager(t, `{"cms":{"exclude_users":["carol"]}}`)
	base := t.TempDir()
	vuln := []Component{{Slug: "demo", Version: "1.0.0", Latest: "1.2.0", Vulns: []Vuln{{CVSS: 4.3, FixedIn: "1.1.0"}}},
		{Slug: "fine", Version: "2.0", Latest: "2.1", Outdated: true}}
	for _, u := range []string{"alice", "bob", "carol"} {
		m.save(Site{Type: WordPress, Path: filepath.Join(base, u, "public_html"), User: u, Version: "6.8.3", Latest: "6.8.6",
			Plugins: vuln, Themes: []Component{}, MUPlugins: []string{}, OutdatedPlugins: 2, Risk: "high"})
	}
	wait := func() BulkStatus {
		for i := 0; i < 200; i++ {
			if b := m.Bulk(); !b.Running {
				return b
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatal("bulk update did not finish")
		return BulkStatus{}
	}
	if _, err := m.BulkUpdate(BulkRequest{Mode: "everything"}); err == nil {
		t.Fatal("unknown mode accepted")
	}
	if n, err := m.BulkUpdate(BulkRequest{Account: "bob", Mode: "vulnerable"}); err != nil || n != 1 {
		t.Fatalf("account: %d %v", n, err)
	}
	if b := wait(); b.Sites != 1 || b.Done != 1 || b.Updated != 1 || b.Failed != 0 {
		t.Fatalf("status %+v", b)
	}
	if got := strings.Join(wp.calls, " | "); got != "bob: plugin update demo" {
		t.Fatalf("account bulk: %s", got)
	}
	// All sites: carol (never patched automatically) is left out.
	wp.calls = nil
	if n, err := m.BulkUpdate(BulkRequest{Mode: "outdated"}); err != nil || n != 2 {
		t.Fatalf("all: %d %v", n, err)
	}
	wait()
	if got := strings.Join(wp.calls, " | "); strings.Contains(got, "carol") || !strings.Contains(got, "alice: plugin update --all") || !strings.Contains(got, "alice: core update --minor") {
		t.Fatalf("all bulk: %s", got)
	}
	// Selected one by one: carol's too.
	wp.calls = nil
	if n, err := m.BulkUpdate(BulkRequest{Paths: []string{filepath.Join(base, "carol", "public_html")}, Mode: "vulnerable"}); err != nil || n != 1 {
		t.Fatalf("selected: %d %v", n, err)
	}
	wait()
	if got := strings.Join(wp.calls, " | "); got != "carol: plugin update demo" {
		t.Fatalf("selected bulk: %s", got)
	}
	// Nothing to do, and not during a scan.
	if _, err := m.BulkUpdate(BulkRequest{Paths: []string{"/nowhere"}, Mode: "vulnerable"}); err == nil {
		t.Fatal("bulk update of no site")
	}
	m.mu.Lock()
	m.running = true
	m.mu.Unlock()
	if _, err := m.BulkUpdate(BulkRequest{Mode: "vulnerable"}); err == nil || !strings.Contains(err.Error(), "scan is running") {
		t.Fatalf("during a scan: %v", err)
	}
}

package cms

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/xmarthost/xmartguard/agent/internal/settings"
	"github.com/xmarthost/xmartguard/agent/internal/store"
)

const sampleWPV = `{"error":0,"message":null,"data":{"name":"Demo","plugin":"demo","vulnerability":[
 {"uuid":"a","name":"Demo < 5.8.4 - Reflected XSS","operator":{"min_version":null,"min_operator":null,"max_version":"5.8.4","max_operator":"lt","unfixed":"0","closed":"0"},
  "source":[{"id":"CVE-2024-0001","name":"x","link":"https://example.org/cve","description":"","date":"2024-01-02"}],
  "impact":{"cvss":{"version":"3.1","vector":"","score":"6.1","severity":"m"}}},
 {"uuid":"b","name":"Demo <= 4.0 - SQL Injection","operator":{"min_version":"3.0","min_operator":"ge","max_version":"4.0","max_operator":"le","unfixed":"0","closed":"0"},
  "source":[{"id":"CVE-2023-0002","link":"","date":"2023-05-01"}],"impact":{"cvss":{"score":9.8}}}
]}}`

func TestVulnDB(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XG_STATE_DIR", filepath.Join(dir, "state"))
	db, err := store.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.URL.Path != "/plugin/demo/" {
			http.NotFound(w, r)
			return
		}
		io.WriteString(w, sampleWPV)
	}))
	defer srv.Close()
	v := &VulnDB{DB: db, Client: srv.Client(), Base: srv.URL}
	got, err := v.Affecting(context.Background(), "plugin", "demo", "3.5")
	if err != nil || len(got) != 2 {
		t.Fatalf("3.5: %+v %v", got, err)
	}
	if got[1].CVSS != 9.8 || got[0].FixedIn != "5.8.4" || got[0].ID != "CVE-2024-0001" || got[0].Date == 0 {
		t.Fatalf("parse: %+v", got)
	}
	got, _ = v.Affecting(context.Background(), "plugin", "demo", "5.0")
	if len(got) != 1 {
		t.Fatalf("5.0: %+v", got)
	}
	got, _ = v.Affecting(context.Background(), "plugin", "demo", "5.8.4")
	if len(got) != 0 {
		t.Fatalf("fixed version still vulnerable: %+v", got)
	}
	if hits != 1 {
		t.Fatalf("cache not used: %d requests", hits)
	}
	if maxCVSS([]Vuln{{CVSS: 3}, {CVSS: 7.5}}) != 7.5 {
		t.Fatal("maxCVSS")
	}
}

func TestEnsureRealCron(t *testing.T) {
	if _, err := exec.LookPath("crontab"); err != nil || os.Geteuid() != 0 {
		t.Skip("needs root and crontab")
	}
	if os.Getenv("XG_DESTRUCTIVE_TESTS") != "1" {
		t.Skip("edits the crontab of user nobody; set XG_DESTRUCTIVE_TESTS=1")
	}
	site := t.TempDir()
	os.WriteFile(filepath.Join(site, "wp-config.php"), []byte("<?php\ndefine('DB_NAME','x');\n"), 0o640)
	defer exec.Command("crontab", "-u", "nobody", "-r").Run()
	changed, err := EnsureRealCron(site, "nobody", 12)
	if err != nil || !changed {
		t.Fatalf("first: %v %v", changed, err)
	}
	cfg, _ := os.ReadFile(filepath.Join(site, "wp-config.php"))
	if !strings.Contains(string(cfg), "DISABLE_WP_CRON") || !strings.HasPrefix(string(cfg), "<?php\ndefine( 'DISABLE_WP_CRON'") {
		t.Fatalf("wp-config: %s", cfg)
	}
	tab, _ := exec.Command("crontab", "-u", "nobody", "-l").Output()
	if !strings.Contains(string(tab), cronLine(site, 12)) {
		t.Fatalf("crontab: %s", tab)
	}
	if changed, _ := EnsureRealCron(site, "nobody", 12); changed {
		t.Fatal("second run changed things again")
	}
	// A new interval replaces the line (one line per site).
	if changed, err := EnsureRealCron(site, "nobody", 1); err != nil || !changed {
		t.Fatalf("interval change: %v %v", changed, err)
	}
	tab, _ = exec.Command("crontab", "-u", "nobody", "-l").Output()
	if strings.Count(string(tab), "cd "+site) != 1 || !strings.Contains(string(tab), cronLine(site, 1)) {
		t.Fatalf("crontab after interval change: %s", tab)
	}
	// Turning the option off undoes both changes.
	if changed, err := RemoveRealCron(site, "nobody"); err != nil || !changed {
		t.Fatalf("remove: %v %v", changed, err)
	}
	tab, _ = exec.Command("crontab", "-u", "nobody", "-l").Output()
	cfg, _ = os.ReadFile(filepath.Join(site, "wp-config.php"))
	if strings.Contains(string(tab), site) || strings.Contains(string(cfg), "DISABLE_WP_CRON") || string(cfg) != "<?php\ndefine('DB_NAME','x');\n" {
		t.Fatalf("not undone:\n%s\n%q", tab, cfg)
	}
	if changed, _ := RemoveRealCron(site, "nobody"); changed {
		t.Fatal("second remove changed things")
	}
}

// Sites get their own minute and hour, so "every 24 hours" does not start
// every site's wp-cron.php at midnight together.
func TestCronLinesSpread(t *testing.T) {
	minutes, hours := map[string]bool{}, map[string]bool{}
	for i := 0; i < 200; i++ {
		f := strings.Fields(cronLine("/home/u"+strconv.Itoa(i)+"/public_html", 24))
		minutes[f[0]], hours[f[1]] = true, true
		if strings.Contains(f[1], ",") || strings.Contains(f[1], "*") {
			t.Fatalf("24h line runs more than once a day: %v", f)
		}
	}
	if len(minutes) < 40 || len(hours) < 20 {
		t.Fatalf("not spread: %d minutes, %d hours", len(minutes), len(hours))
	}
	if f := strings.Fields(cronLine("/home/a/public_html", 6)); strings.Count(f[1], ",") != 3 {
		t.Fatalf("6h line: %v", f)
	}
	if f := strings.Fields(cronLine("/home/a/public_html", 1)); f[1] != "*" {
		t.Fatalf("hourly line: %v", f)
	}
	if l := cronLine("/home/a/public_html", 1); !strings.Contains(l, "nice -n 15 ") || !strings.HasSuffix(l, cronMarker) {
		t.Fatalf("line: %s", l)
	}
}

// Lines written by earlier versions (all at 0:00) move to their own times.
func TestRespreadCrons(t *testing.T) {
	if _, err := exec.LookPath("crontab"); err != nil || os.Geteuid() != 0 {
		t.Skip("needs root and crontab")
	}
	if os.Getenv("XG_DESTRUCTIVE_TESTS") != "1" {
		t.Skip("edits the crontab of user nobody; set XG_DESTRUCTIVE_TESTS=1")
	}
	defer exec.Command("crontab", "-u", "nobody", "-r").Run()
	old := "MAILTO=\"\"\n0 */24 * * * cd /home/x/public_html && php -q wp-cron.php >/dev/null 2>&1 " + cronMarker + "\n5 1 * * * /bin/true\n"
	if err := installCrontab("nobody", old); err != nil {
		t.Skip("crontab:", err)
	}
	if n := RespreadCrons(24); n != 1 {
		t.Fatalf("changed %d crontabs", n)
	}
	tab, _ := exec.Command("crontab", "-u", "nobody", "-l").Output()
	if !strings.Contains(string(tab), cronLine("/home/x/public_html", 24)) || !strings.Contains(string(tab), "5 1 * * * /bin/true") || !strings.Contains(string(tab), "MAILTO") {
		t.Fatalf("crontab: %s", tab)
	}
	if n := RespreadCrons(24); n != 0 {
		t.Fatal("second pass changed things")
	}
}

// wp-cli answers "already updated" when WordPress sees no newer release
// (premium or closed plugins): the version stays, and the update ran again
// on every scan (business200: 774 times for one plugin). One try a week per
// site and version, and only a real update is reported as done.
func TestAutoUpdateNotRepeated(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XG_STATE_DIR", filepath.Join(dir, "state"))
	t.Setenv("XG_CONFIG_DIR", filepath.Join(dir, "conf"))
	db, err := store.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	st, _ := settings.Load()
	if _, err := st.Patch([]byte(`{"cms":{"auto_update":true,"auto_update_cvss":0,"auto_update_days":0}}`)); err != nil {
		t.Fatal(err)
	}
	answer, calls := "Success: Plugin already updated.", 0
	m := &Manager{DB: db, Settings: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		RunWPCLI: func(_ context.Context, _ string, args ...string) (string, error) {
			calls++
			return answer, nil
		}}
	site := &Site{Type: WordPress, Path: "/home/u/public_html", User: "u", Plugins: []Component{
		{Slug: "template-kit-import", Version: "1.0.14", Latest: "1.0.17", Vulns: []Vuln{{ID: "CVE-2024-0001", CVSS: 6.4}}}}}
	if done := m.autoActions(context.Background(), site); len(done) != 0 {
		t.Fatalf("reported as updated: %v", done)
	}
	m.autoActions(context.Background(), site)
	if calls != 1 {
		t.Fatalf("wp-cli ran %d times, want once a week", calls)
	}
	// A newer installed version is a new try, and a real update is reported.
	answer = "Success: Updated 1 of 1 plugins."
	site.Plugins[0].Version = "1.0.15"
	if done := m.autoActions(context.Background(), site); len(done) != 1 || calls != 2 {
		t.Fatalf("done %v, calls %d", done, calls)
	}
}

// A site inside an extracted cPanel backup is not live: its database login
// is old and every check said "Access denied" (business200: hundreds a day).
func TestDiscoverSkipsBackupCopies(t *testing.T) {
	home := t.TempDir()
	for _, site := range []string{"public_html", "backup-10.21.2026_00-03-07_u/homedir/public_html"} {
		d := filepath.Join(home, site)
		os.MkdirAll(filepath.Join(d, "wp-includes"), 0o755)
		os.WriteFile(filepath.Join(d, "wp-config.php"), []byte("<?php"), 0o644)
		os.WriteFile(filepath.Join(d, "wp-includes", "version.php"), []byte("<?php $wp_version = '6.8';"), 0o644)
	}
	got := Discover([]Account{{Name: "u", Home: home}}, nil)
	if len(got) != 1 || got[0].Path != filepath.Join(home, "public_html") {
		t.Fatalf("found %+v, want only the live site", got)
	}
}

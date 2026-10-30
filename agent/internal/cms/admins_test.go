package cms

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/store"
)

// sawanysc (2026-10-28): 11,966 administrators made by a kit; server1's
// rogue admins (adm + random, root_<hex>, a look-alike, @system.local).
// Real sites' administrators stay quiet, and the first read reports only
// recent administrators other than the site's first user.
func TestAdminWatch(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	old := now.Add(-400 * 24 * time.Hour)
	for _, a := range []wpAdmin{
		{Login: "admin_3f9a1c7b", Email: "admin_3f9a1c7b@sawanys.com"},
		{Login: "backup_a1b2c3d4", Email: "x@sawanys.com"},
		{Login: "adm2jwo0u", Email: "a@gmail.com"},
		{Login: "admcfe63j", Email: "a@gmail.com"},
		{Login: "root_80j74hg", Email: "root_80j74hg@wordpress.org"},
		{Login: "admln", Email: "a@gmail.com"},
		{Login: "wp_update", Email: "update@system.local"},
		{Login: "manager_7", Email: "manager_7@example.invalid"},
	} {
		if suspiciousAdmin(a) == "" {
			t.Errorf("%s <%s> not suspicious", a.Login, a.Email)
		}
	}
	for _, a := range []wpAdmin{
		{Login: "admin", Email: "info@shop.pk"}, {Login: "admin2024", Email: "owner@gmail.com"},
		{Login: "administrator", Email: "it@company.co.uk"}, {Login: "sheepoint", Email: "info@sheepointernational.com"},
		{Login: "adminuser", Email: "a@outlook.com"}, {Login: "admission", Email: "school@edu.pk"},
		{Login: "webmaster", Email: "web@site.com"}, {Login: "rootbeer", Email: "r@site.com"},
	} {
		if why := suspiciousAdmin(a); why != "" {
			t.Errorf("%s <%s>: %s", a.Login, a.Email, why)
		}
	}

	// First read: the owner (first user) and old admins are quiet; a
	// recent second admin is new; a kit admin is suspicious.
	site := []wpAdmin{
		{ID: 1, Login: "owner", Email: "o@site.com", Registered: now.Add(-24 * time.Hour)},
		{ID: 2, Login: "editor2", Email: "e@site.com", Registered: old},
		{ID: 7, Login: "trumpweiss", Email: "t@gmail.com", Registered: now.Add(-48 * time.Hour)},
		{ID: 9, Login: "adm7tieyz", Email: "x@gmail.com", Registered: old},
	}
	got := map[string]string{}
	for _, f := range adminFindings("wp_users", site, nil, now) {
		if f.Category != AdminCategory {
			t.Errorf("%s: category %q", f.Row, f.Category)
		}
		got[f.Row] = f.Signature
	}
	if len(got) != 2 || got["ID=7"] != adminSigNew || got["ID=9"] != adminSigSus {
		t.Errorf("first read: %v", got)
	}
	// Later reads: whoever is not in the baseline is new, however old.
	base := map[int64]bool{0: true, 1: true, 2: true}
	got = map[string]string{}
	for _, f := range adminFindings("wp_users", site, base, now) {
		got[f.Row] = f.Signature
	}
	if len(got) != 2 || got["ID=7"] != adminSigNew || got["ID=9"] != adminSigSus {
		t.Errorf("later read: %v", got)
	}
	if fs := adminFindings("wp_users", site[:2], base, now); len(fs) != 0 {
		t.Errorf("known admins reported: %+v", fs)
	}

	// A farm: one summary row and at most 20 named rows.
	var farm []wpAdmin
	for i := range 3000 {
		farm = append(farm, wpAdmin{ID: int64(i + 10), Login: fmt.Sprintf("admin_%08x", i*7919+0x100000), Email: "k@sawanys.com", Registered: now.Add(-time.Hour)})
	}
	fs := adminFindings("wp_users", append(site[:2], farm...), base, now)
	if len(fs) == 0 || fs[0].Signature != adminSigFarm || len(fs) > adminRows+1 {
		t.Fatalf("farm: %d rows, first %+v", len(fs), fs[0])
	}
}

// The baseline: the first read keeps the site's own administrators; a kit
// admin and later ones stay reported; the DB cleaner refuses admin rows.
func TestAdminWatchBaseline(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XG_STATE_DIR", filepath.Join(dir, "state"))
	t.Setenv("XG_CONFIG_DIR", filepath.Join(dir, "conf"))
	db, err := store.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	site, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "site.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer site.Close()
	for _, q := range []string{
		"CREATE TABLE wp_users (ID INTEGER PRIMARY KEY, user_login TEXT, user_email TEXT, user_registered TEXT)",
		"CREATE TABLE wp_usermeta (umeta_id INTEGER PRIMARY KEY, user_id INTEGER, meta_key TEXT, meta_value TEXT)",
	} {
		if _, err := site.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	add := func(id int, login, email, reg string, role string) {
		site.Exec("INSERT INTO wp_users VALUES (?,?,?,?)", id, login, email, reg)
		site.Exec("INSERT INTO wp_usermeta (user_id, meta_key, meta_value) VALUES (?, 'wp_capabilities', ?)", id, `a:1:{s:`+fmt.Sprint(len(role))+`:"`+role+`";b:1;}`)
	}
	add(1, "owner", "o@site.com", "2020-01-01 10:00:00", "administrator")
	add(2, "writer", "w@site.com", "2021-01-01 10:00:00", "author")
	add(3, "adm2jwo0u", "x@gmail.com", "2021-02-01 10:00:00", "administrator")
	m := &Manager{DB: db, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	ctx := context.Background()
	rows := func() map[string]string {
		out := map[string]string{}
		for _, f := range m.watchAdminsDB(ctx, site, "wp_", "/home/u/public_html") {
			out[f.Row] = f.Signature
		}
		return out
	}
	if got := rows(); len(got) != 1 || got["ID=3"] != adminSigSus {
		t.Fatalf("first read: %v", got)
	}
	add(4, "trumpweiss", "t@gmail.com", "2019-05-05 10:00:00", "administrator") // old date, new account
	if got := rows(); len(got) != 2 || got["ID=4"] != adminSigNew || got["ID=3"] != adminSigSus {
		t.Fatalf("later read: %v", got)
	}
	site.Exec("UPDATE wp_usermeta SET meta_value = 'a:1:{s:10:\"subscriber\";b:1;}' WHERE user_id IN (3, 4)")
	if got := rows(); len(got) != 0 {
		t.Fatalf("demoted admins still reported: %v", got)
	}

	db.Exec(`INSERT INTO db_findings (at, site_path, db_name, tbl, row_ref, signature, status, category) VALUES (1, '/home/u/public_html', 'x', 'wp_users', 'ID=4', 'WP.Admin.New', 'detected', 'admin')`)
	var id int64
	db.QueryRow(`SELECT id FROM db_findings WHERE row_ref = 'ID=4'`).Scan(&id)
	if res := m.CleanDBFindings(ctx, []int64{id}); len(res) != 1 || !strings.Contains(res[0].Error, "administrator is not cleaned") {
		t.Fatalf("admin finding cleaned: %+v", res)
	}
}

// Plugin watch: the first listing is the baseline; a later plugin that is
// not on wordpress.org, or claims a version newer than wordpress.org's,
// is reported until it is removed; timestamped clones always; nothing is
// cleaned.
func TestPluginWatch(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XG_STATE_DIR", filepath.Join(dir, "state"))
	t.Setenv("XG_CONFIG_DIR", filepath.Join(dir, "conf"))
	db, err := store.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var notified []string
	m := &Manager{DB: db, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), OnFinding: func(_ Site, f DBFinding) { notified = append(notified, f.Row) }}
	s := Site{Type: WordPress, Path: "/home/u/public_html", User: "u", Plugins: []Component{
		{Slug: "akismet", Name: "Akismet", Version: "5.3", Latest: "5.3"},
		{Slug: "elementor-pro", Name: "Elementor Pro", Version: "3.20"}, // premium, there before
		{Slug: "contact_1772129663", Name: "Contact", Version: "1.0"},
	}}
	sigs := func() map[string]string {
		out := map[string]string{}
		rows, _ := db.Query(`SELECT row_ref, signature FROM db_findings WHERE status = 'detected'`)
		for rows.Next() {
			var r, sig string
			rows.Scan(&r, &sig)
			out[r] = sig
		}
		rows.Close()
		return out
	}
	m.watchPlugins(s)
	if got := sigs(); len(got) != 1 || got["slug=contact_1772129663"] != pluginSigClone {
		t.Fatalf("first listing: %v", got)
	}
	s.Plugins = append(s.Plugins,
		Component{Slug: "system-defence", Name: "wp-warden", Version: "1.0.0"},
		Component{Slug: "core-wp.zip", Name: "WP-CORE", Version: "8.8.2", Latest: "1.2"},
		Component{Slug: "wordfence", Name: "Wordfence", Version: "8.1", Latest: "8.1"},
	)
	m.watchPlugins(s)
	m.watchPlugins(s) // a second pass notifies nothing new
	got := sigs()
	if len(got) != 3 || got["slug=system-defence"] != pluginSigNew || got["slug=core-wp.zip"] != pluginSigNew {
		t.Fatalf("later listing: %v", got)
	}
	if len(notified) != 3 {
		t.Fatalf("notifications: %v", notified)
	}
	s.Plugins = s.Plugins[:2]
	m.watchPlugins(s)
	if got := sigs(); len(got) != 0 {
		t.Fatalf("removed plugins still reported: %v", got)
	}
	var id int64
	db.QueryRow(`SELECT id FROM db_findings WHERE row_ref = 'slug=system-defence'`).Scan(&id)
	db.Exec(`UPDATE db_findings SET status = 'detected' WHERE id = ?`, id)
	if res := m.CleanDBFindings(context.Background(), []int64{id}); len(res) != 1 || !strings.Contains(res[0].Error, "plugin is not cleaned") {
		t.Fatalf("plugin finding cleaned: %+v", res)
	}
}

// The ClickFix page kept in a post or widget (steps in the HTML, the copy
// in the script) is a DB finding the cleaner leaves to a person; a post
// with a copy button and how-to steps is not.
func TestDBClickFixPage(t *testing.T) {
	page := "<p>Verify you are human by completing the action below.</p><ol><li>Press the Windows Key + <b>R</b></li><li>Press <b>Ctrl</b> + <b>V</b></li></ol>" +
		"<script>document.getElementById('b').onclick=function(){navigator.clipboard.writeText('echo inert')}</script>"
	d := ScanValueDetail(page)
	if d.Signature != "DB.Phishing.ClickFix.FakeVerification" || d.Category != "phishing" {
		t.Fatalf("stored page: %+v", d)
	}
	if _, err := CleanStoredValue(page); err == nil {
		t.Fatal("the stored page was cut automatically")
	}
	howto := "<p>Press <b>Win</b> + <b>R</b>, then <b>Ctrl</b> + <b>V</b>.</p><script>function c(){navigator.clipboard.writeText('ipconfig /flushdns')}</script>"
	if d := ScanValueDetail(howto); d.Signature != "" {
		t.Fatalf("how-to post: %+v", d)
	}
}

// wordpress.org did not answer (no plugin has a release version): nothing
// is reported as unknown and earlier rows stay.
func TestPluginWatchLookupsFailed(t *testing.T) {
	if !lookupsFailed([]Component{{Slug: "a"}, {Slug: "b"}, {Slug: "c"}}) {
		t.Error("all unknown not seen as a failed lookup")
	}
	if lookupsFailed([]Component{{Slug: "a", Latest: "1"}, {Slug: "b"}, {Slug: "c"}}) || lookupsFailed([]Component{{Slug: "a"}}) {
		t.Error("a normal listing seen as a failed lookup")
	}
}

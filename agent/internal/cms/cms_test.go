package cms

import (
	"context"
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/settings"
	"github.com/xmarthost/xmartguard/agent/internal/store"
)

func write(t *testing.T, p, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func md5s(s string) string { h := md5.Sum([]byte(s)); return hex.EncodeToString(h[:]) }

// fakeWP builds a WordPress tree with one modified and one foreign core file.
func fakeWP(t *testing.T, root, dbName, dbUser, dbPass string) map[string]string {
	origIndex, origLoad := "<?php // admin index\n", "<?php // loader\n"
	write(t, filepath.Join(root, "wp-config.php"), fmt.Sprintf("<?php\ndefine( 'DB_NAME', '%s' );\ndefine('DB_USER', \"%s\");\ndefine( 'DB_PASSWORD', '%s' );\ndefine( 'DB_HOST', 'localhost' );\n$table_prefix = 'wp_';\n", dbName, dbUser, dbPass))
	write(t, filepath.Join(root, "wp-includes", "version.php"), "<?php\n$wp_version = '6.5.2';\n")
	write(t, filepath.Join(root, "wp-includes", "load.php"), origLoad)
	write(t, filepath.Join(root, "wp-admin", "index.php"), origIndex+"// tampered\n")
	write(t, filepath.Join(root, "wp-includes", "wp-cache-helper.php"), "<?php // not part of WordPress\n")
	write(t, filepath.Join(root, "wp-content", "plugins", "akismet", "akismet.php"), "<?php\n/*\nPlugin Name: Akismet Anti-spam\nVersion: 5.0\n*/\n")
	write(t, filepath.Join(root, "wp-content", "plugins", "hello.php"), "<?php\n/*\nPlugin Name: Hello Dolly\nVersion: 1.7.2\n*/\n")
	write(t, filepath.Join(root, "wp-content", "plugins", "premium-thing", "main.php"), "<?php\n/*\nPlugin Name: Premium Thing\nVersion: 2.0\n*/\n")
	write(t, filepath.Join(root, "wp-content", "themes", "twentytwentyfour", "style.css"), "/*\nTheme Name: Twenty Twenty-Four\nVersion: 1.3\n*/\n")
	write(t, filepath.Join(root, "wp-content", "mu-plugins", "loader.php"), "<?php\n")
	return map[string]string{"wp-admin/index.php": md5s(origIndex), "wp-includes/load.php": md5s(origLoad), "wp-includes/version.php": md5s("<?php\n$wp_version = '6.5.2';\n")}
}

func fakeAPI(t *testing.T, sums map[string]string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/core/version-check"):
			io.WriteString(w, `{"offers":[{"current":"6.8.3"}]}`)
		case strings.HasPrefix(r.URL.Path, "/core/checksums"):
			b, _ := json.Marshal(map[string]any{"checksums": sums})
			w.Write(b)
		case strings.HasPrefix(r.URL.Path, "/plugins/info"):
			switch r.URL.Query().Get("request[slug]") {
			case "akismet":
				io.WriteString(w, `{"version":"5.3.2"}`)
			case "hello":
				io.WriteString(w, `{"version":"1.7.2"}`)
			default:
				w.WriteHeader(404)
				io.WriteString(w, `{"error":"Plugin not found."}`)
			}
		case strings.HasPrefix(r.URL.Path, "/themes/info"):
			io.WriteString(w, `{"version":"1.3"}`)
		default:
			w.WriteHeader(404)
		}
	}))
}

// mariadb creates a throwaway WordPress-like database, or skips.
func mariadb(t *testing.T) (name, user, pass string) {
	t.Helper()
	if _, err := exec.LookPath("mariadb"); err != nil {
		t.Skip("mariadb client not installed")
	}
	if exec.Command("mariadb", "-e", "select 1").Run() != nil {
		t.Skip("mariadb server not running")
	}
	name, user, pass = "xgtest_wp", "xgtest_wp", "pw-"+fmt.Sprint(time.Now().UnixNano()%100000)
	script := fmt.Sprintf(`DROP DATABASE IF EXISTS %[1]s; CREATE DATABASE %[1]s;
DROP USER IF EXISTS '%[2]s'@'localhost'; CREATE USER '%[2]s'@'localhost' IDENTIFIED BY '%[3]s';
GRANT SELECT ON %[1]s.* TO '%[2]s'@'localhost';
USE %[1]s;
CREATE TABLE wp_options (option_id INT PRIMARY KEY AUTO_INCREMENT, option_name VARCHAR(191), option_value LONGTEXT);
CREATE TABLE wp_posts (ID INT PRIMARY KEY, post_title TEXT, post_content LONGTEXT);
CREATE TABLE wp_postmeta (meta_id INT PRIMARY KEY, meta_value LONGTEXT);`, name, user, pass)
	if out, err := exec.Command("mariadb", "-e", script).CombinedOutput(); err != nil {
		t.Skipf("cannot create test database: %v %s", err, out)
	}
	t.Cleanup(func() {
		exec.Command("mariadb", "-e", fmt.Sprintf("DROP DATABASE IF EXISTS %s; DROP USER IF EXISTS '%s'@'localhost';", name, user)).Run()
	})
	db, err := sql.Open("mysql", "root@unix(/run/mysqld/mysqld.sock)/"+name)
	if err != nil {
		t.Skip(err)
	}
	defer db.Close()
	miner := "var m = new Coin" + "Hive.Anonymous('key'); m.start();"
	rows := [][]any{
		{"INSERT INTO wp_options (option_name, option_value) VALUES (?, ?)", "siteurl", `https://blog.example/"><script src=//x.invalid/a.js></script>`},
		{"INSERT INTO wp_options (option_name, option_value) VALUES (?, ?)", "home", "https://blog.example"},
		// A normal analytics snippet stored by a header plugin must not be flagged.
		{"INSERT INTO wp_options (option_name, option_value) VALUES (?, ?)", "ihaf_insert_header", `<script async src="https://www.googletagmanager.com/gtag/js?id=G-1"></script><script>window.dataLayer=window.dataLayer||[];function gtag(){dataLayer.push(arguments);}gtag('js',new Date());</script>`},
		{"INSERT INTO wp_posts (ID, post_title, post_content) VALUES (?, 'Hello', ?)", 7, "<p>Hi</p><script>" + miner + "</script>"},
		{"INSERT INTO wp_posts (ID, post_title, post_content) VALUES (?, 'Clean', ?)", 8, "<p>Clean post with an <iframe src=\"https://www.youtube.com/embed/x\" width=\"560\" height=\"315\"></iframe></p>"},
		{"INSERT INTO wp_postmeta (meta_id, meta_value) VALUES (?, ?)", 3, `<iframe src="https://x.invalid/p" width="0" height="0" frameborder="0"></iframe>`},
	}
	for _, r := range rows {
		if _, err := db.Exec(r[0].(string), r[1:]...); err != nil {
			t.Skipf("seed: %v", err)
		}
	}
	return
}

func TestCMSScanEndToEnd(t *testing.T) {
	dbName, dbUser, dbPass := mariadb(t)
	dir := t.TempDir()
	t.Setenv("XG_STATE_DIR", filepath.Join(dir, "state"))
	t.Setenv("XG_CONFIG_DIR", filepath.Join(dir, "conf"))
	home := filepath.Join(dir, "home", "alice")
	root := filepath.Join(home, "public_html")
	sums := fakeWP(t, root, dbName, dbUser, dbPass)
	// A second, unrelated directory that is not a CMS.
	write(t, filepath.Join(home, "public_html", "static", "index.html"), "hi")
	api := fakeAPI(t, sums)
	defer api.Close()

	db, err := store.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	st, _ := settings.Load()
	v := NewVersions(db)
	v.WPAPI = api.URL
	var notified []DBFinding
	m := &Manager{DB: db, Settings: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Versions: v,
		Accounts:  func() []Account { return []Account{{Name: "alice", Home: home}} },
		Docroots:  func() map[string]string { return map[string]string{root: "blog.example"} },
		OnFinding: func(_ Site, f DBFinding) { notified = append(notified, f) },
	}
	if err := m.scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	sites, total, err := m.Sites(SiteFilter{})
	if err != nil || total != 1 {
		t.Fatalf("sites %d %v", total, err)
	}
	s := sites[0]
	if s.Type != WordPress || s.Domain != "blog.example" || s.User != "alice" || s.Version != "6.5.2" || s.Latest != "6.8.3" {
		t.Fatalf("site %+v", s)
	}
	if len(s.Plugins) != 3 || s.OutdatedPlugins != 1 || s.OutdatedThemes != 0 {
		t.Fatalf("plugins %+v outdated=%d themes=%d", s.Plugins, s.OutdatedPlugins, s.OutdatedThemes)
	}
	for _, p := range s.Plugins {
		if p.Slug == "premium-thing" && (p.Latest != "" || p.Outdated) {
			t.Fatalf("premium plugin marked outdated: %+v", p)
		}
	}
	if len(s.MUPlugins) != 1 {
		t.Fatalf("mu-plugins %v", s.MUPlugins)
	}
	if strings.Join(s.Core.Modified, ",") != "wp-admin/index.php" || strings.Join(s.Core.Unknown, ",") != "wp-includes/wp-cache-helper.php" {
		t.Fatalf("core report %+v", s.Core)
	}
	if s.Risk != "critical" {
		t.Fatalf("risk %s", s.Risk)
	}
	// Database: siteurl injection, miner script in a post, hidden iframe in meta.
	// The analytics snippet and the YouTube iframe must not be reported.
	rows, n, _ := m.DBFindings("detected", "", 50, 0)
	got := map[string]string{}
	for _, r := range rows {
		got[r.Table+" "+r.Row] = r.Signature
	}
	want := map[string]string{
		"wp_options option_name=siteurl": "DB.Injected.SiteURL",
		"wp_posts ID=7":                  "DB.JS.Miner.Browser",
		"wp_postmeta meta_id=3":          "DB.Injected.HiddenIframe",
	}
	if n != len(want) {
		t.Fatalf("db findings %d: %v", n, got)
	}
	for k, sig := range want {
		if got[k] != sig {
			t.Errorf("%s: got %q want %q (all %v)", k, got[k], sig, got)
		}
	}
	if len(notified) != 3 {
		t.Errorf("notifications %d", len(notified))
	}
	// A second scan does not duplicate findings or re-notify.
	if err := m.scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, n2, _ := m.DBFindings("detected", "", 50, 0); n2 != 3 || len(notified) != 3 {
		t.Fatalf("rescan: %d findings, %d notifications", n2, len(notified))
	}
	c := m.Counts()
	if c.WordPress != 1 || c.WithIssues != 1 || c.DBInfected != 3 {
		t.Fatalf("counts %+v", c)
	}
	// Archive hides a finding.
	if k, _ := m.ArchiveDBFindings([]int64{rows[0].ID}); k != 1 {
		t.Fatal("archive")
	}
	if _, n3, _ := m.DBFindings("detected", "", 50, 0); n3 != 2 {
		t.Fatalf("after archive %d", n3)
	}
	// An archived finding stays archived on the next scan and is not re-notified.
	if err := m.scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, n4, _ := m.DBFindings("detected", "", 50, 0); n4 != 2 || len(notified) != 3 {
		t.Fatalf("after rescan: %d detected, %d notifications", n4, len(notified))
	}
}

func TestReadWPConfigVariants(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "wp-config.php"), `<?php
define("DB_NAME","shop_db");
define( 'DB_USER', 'shop_u' );
define('DB_PASSWORD', 'p\'ss');
define('DB_HOST', 'localhost:/var/lib/mysql/mysql.sock');
$table_prefix  = 'xyz_';`)
	c, err := ReadWPConfig(dir)
	if err != nil || c.Name != "shop_db" || c.User != "shop_u" || c.Password != "p'ss" || c.Prefix != "xyz_" || c.Host != "localhost:/var/lib/mysql/mysql.sock" {
		t.Fatalf("%+v %v", c, err)
	}
}

func TestCompareVersions(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{{"6.5.2", "6.8.3", -1}, {"6.8", "6.8.0", 0}, {"10.0", "9.9.9", 1}, {"5.0-beta", "5.0", 0}} {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("%s vs %s = %d", c.a, c.b, got)
		}
	}
}

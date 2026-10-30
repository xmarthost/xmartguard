package cms

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xmarthost/xmartguard/agent/internal/store"
)

// A backdoor added to a real plugin's file, or a PHP file dropped into its
// folder, is reported against the wordpress.org release; an untouched
// plugin and its cache folder are not; nothing is cleaned.
func TestPluginIntegrity(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XG_STATE_DIR", filepath.Join(dir, "state"))
	t.Setenv("XG_CONFIG_DIR", filepath.Join(dir, "conf"))
	db, err := store.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	sum := func(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
	files := map[string]string{"hello.php": "<?php /* Plugin Name: Hello */ echo 'hi';", "inc/a.php": "<?php function a() {}"}
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/plugin-checksums/hello/1.0.json" {
			http.NotFound(w, r)
			return
		}
		var parts []string
		for p, c := range files {
			parts = append(parts, fmt.Sprintf(`%q:{"md5":"x","sha256":%q}`, p, sum(c)))
		}
		io.WriteString(w, `{"plugin":"hello","version":"1.0","files":{`+strings.Join(parts, ",")+`}}`)
	}))
	defer srv.Close()
	old := DownloadsAPI
	DownloadsAPI = srv.URL
	defer func() { DownloadsAPI = old }()

	site := filepath.Join(dir, "public_html")
	for p, c := range files {
		os.MkdirAll(filepath.Dir(filepath.Join(site, "wp-content/plugins/hello", p)), 0o755)
		os.WriteFile(filepath.Join(site, "wp-content/plugins/hello", p), []byte(c), 0o644)
	}
	os.MkdirAll(filepath.Join(site, "wp-content/plugins/hello/cache"), 0o755)
	os.WriteFile(filepath.Join(site, "wp-content/plugins/hello/cache/page.php"), []byte("<?php // cache"), 0o644)
	m := &Manager{DB: db, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Versions: NewVersions(db)}
	s := Site{Type: WordPress, Path: site, User: "u", Plugins: []Component{{Slug: "hello", Name: "Hello", Version: "1.0", Latest: "1.0"}, {Slug: "premium", Version: "2.0"}}}
	cache := filepath.Join(dir, "sigs")
	count := func() (n int, snippet string) {
		rows, _ := db.Query(`SELECT snippet FROM db_findings WHERE category = ? AND status = 'detected'`, IntegrityCategory)
		for rows.Next() {
			n++
			rows.Scan(&snippet)
		}
		rows.Close()
		return
	}
	m.checkIntegrity(context.Background(), s, cache)
	if n, sn := count(); n != 0 {
		t.Fatalf("untouched plugin reported: %s", sn)
	}
	os.WriteFile(filepath.Join(site, "wp-content/plugins/hello/inc/a.php"), []byte("<?php function a() {} /* added line, inert */"), 0o644)
	os.WriteFile(filepath.Join(site, "wp-content/plugins/hello/inc/x.php"), []byte("<?php // dropped, inert"), 0o644)
	m.checkIntegrity(context.Background(), s, cache)
	n, sn := count()
	if n != 1 || !strings.Contains(sn, "inc/a.php") || !strings.Contains(sn, "inc/x.php") || strings.Contains(sn, "cache/page.php") {
		t.Fatalf("modified plugin: %d %s", n, sn)
	}
	if calls != 1 {
		t.Errorf("checksums fetched %d times (cached after the first)", calls)
	}
	// The database scan of the same site leaves the watch's rows alone:
	// they were marked cleaned and notified again on every scan.
	m.markDBGone(site, "cleaned")
	notified := 0
	m.OnFinding = func(Site, DBFinding) { notified++ }
	m.checkIntegrity(context.Background(), s, cache)
	if n, _ := count(); n != 1 || notified != 0 {
		t.Fatalf("after a database scan: %d rows, %d notifications", n, notified)
	}
	m.OnFinding = nil
	// wordpress.org down: the finding stays (it is not "cleaned").
	os.RemoveAll(cache)
	DownloadsAPI = "http://127.0.0.1:1"
	m.checkIntegrity(context.Background(), s, cache)
	if n, _ := count(); n != 1 {
		t.Fatalf("finding dropped while wordpress.org was down: %d", n)
	}
	DownloadsAPI = srv.URL
	// Watch rows are no infected database.
	db.Exec(`INSERT INTO db_findings (at, site_path, db_name, tbl, row_ref, signature, status, category) VALUES (1, ?, 'x', 'wp_users', 'ID=9', 'WP.Admin.New', 'detected', 'admin')`, site)
	if c := m.Counts(); c.DBInfected != 0 {
		t.Errorf("watch rows counted as infections: %d", c.DBInfected)
	}
	var id int64
	db.QueryRow(`SELECT id FROM db_findings WHERE category = ?`, IntegrityCategory).Scan(&id)
	if res := m.CleanDBFindings(context.Background(), []int64{id}); len(res) != 1 || res[0].Error == "" {
		t.Fatalf("integrity finding cleaned: %+v", res)
	}
	// Reinstalled: the finding goes.
	os.WriteFile(filepath.Join(site, "wp-content/plugins/hello/inc/a.php"), []byte(files["inc/a.php"]), 0o644)
	os.Remove(filepath.Join(site, "wp-content/plugins/hello/inc/x.php"))
	m.checkIntegrity(context.Background(), s, cache)
	if n, sn := count(); n != 0 {
		t.Fatalf("after reinstall: %s", sn)
	}
}

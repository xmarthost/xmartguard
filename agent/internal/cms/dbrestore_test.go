package cms

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xmarthost/xmartguard/agent/internal/settings"
	"github.com/xmarthost/xmartguard/agent/internal/store"
)

// A saved value goes back only into the database it came from: a site that
// now points at another database (staging clone, migration) is refused
// before any connection is made (A5 F21).
func TestRestoreRefusesOtherDatabase(t *testing.T) {
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
	os.WriteFile(filepath.Join(site, "wp-config.php"), []byte("<?php\ndefine('DB_NAME', 'staging_db');\ndefine('DB_USER', 'u');\ndefine('DB_PASSWORD', 'p');\ndefine('DB_HOST', '127.0.0.1:1');\n"), 0o644)
	if _, err := sdb.Exec(`INSERT INTO db_clean_backup (finding_id, at, site_path, db_name, tbl, key_col, key_val, col, old_value) VALUES (7, 1, ?, 'live_db', 'wp_posts', 'ID', '10', 'post_content', 'inert old value')`, site); err != nil {
		t.Fatal(err)
	}
	res := m.RestoreDBFindings(context.Background(), []int64{7})
	if len(res) != 1 || res[0].OK || !strings.Contains(res[0].Error, "live_db") {
		t.Fatalf("%+v", res)
	}
}

package store

import (
	"os"
	"path/filepath"
	"testing"
)

// Moves real directories, so it only runs when explicitly requested on a
// disposable machine: XG_DESTRUCTIVE_TESTS=1 go test ./internal/store
func TestLegacyMigration(t *testing.T) {
	if os.Getenv("XG_DESTRUCTIVE_TESTS") != "1" || os.Geteuid() != 0 {
		t.Skip("set XG_DESTRUCTIVE_TESTS=1 (as root) to run")
	}
	for _, d := range []string{HomeDir, LegacyStateDir} {
		if _, err := os.Stat(d); err == nil {
			t.Skipf("%s exists", d)
		}
	}
	t.Cleanup(func() { os.RemoveAll(HomeDir); os.RemoveAll(LegacyStateDir) })
	os.MkdirAll(filepath.Join(LegacyStateDir, "quarantine"), 0o700)
	os.WriteFile(filepath.Join(LegacyStateDir, "quarantine", "1.bin"), []byte("x"), 0o600)
	os.WriteFile(filepath.Join(LegacyStateDir, "manifest"), []byte("dir /var/lib/xmartguard\n"), 0o600)
	old, err := OpenPath(filepath.Join(LegacyStateDir, "agent.db"))
	if err != nil {
		t.Fatal(err)
	}
	old.Exec(`INSERT INTO findings (source, path, category, signature, status, created_at, updated_at, qpath) VALUES ('manual','/home/a/x.php','virus','X','quarantined',1,1,?)`,
		filepath.Join(LegacyStateDir, "quarantine", "1.bin"))
	old.Close()

	db, err := Open()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if StateDir() != DefaultStateDir {
		t.Fatalf("state dir %s", StateDir())
	}
	var q string
	db.QueryRow(`SELECT qpath FROM findings`).Scan(&q)
	if q != filepath.Join(DefaultStateDir, "quarantine", "1.bin") {
		t.Fatalf("qpath not rewritten: %s", q)
	}
	if _, err := os.Stat(q); err != nil {
		t.Fatal("quarantined file not moved")
	}
	if _, err := os.Stat(filepath.Join(LegacyStateDir, "manifest")); err != nil {
		t.Fatal("legacy manifest must stay for the old uninstaller")
	}
}

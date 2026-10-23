package store

import (
	"path/filepath"
	"testing"
)

// A database of an earlier version gets the columns the code reads.
func TestColumnsAddedOnOpen(t *testing.T) {
	p := filepath.Join(t.TempDir(), "agent.db")
	db, err := OpenPath(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`ALTER TABLE findings DROP COLUMN note`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	db, err = OpenPath(p)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`SELECT note FROM findings`); err != nil {
		t.Fatalf("note column missing: %v", err)
	}
}

// WAL with synchronous NORMAL: the agent's logs are written without waiting
// for the disk on every row (FULL, the default, did).
func TestDatabaseSynchronousNormal(t *testing.T) {
	db, err := OpenPath(filepath.Join(t.TempDir(), "agent.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var mode int
	var journal string
	db.QueryRow(`PRAGMA synchronous`).Scan(&mode)
	db.QueryRow(`PRAGMA journal_mode`).Scan(&journal)
	if mode != 1 || journal != "wal" {
		t.Fatalf("synchronous %d, journal %s", mode, journal)
	}
}

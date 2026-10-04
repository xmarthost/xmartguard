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

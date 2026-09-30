package firewall

import (
	"path/filepath"
	"testing"

	"github.com/xmarthost/xmartguard/agent/internal/store"
)

// Kernel counters survive an agent restart: the first reading is a
// baseline, not new hits.
func TestIPDBHitsNotCountedTwiceAfterRestart(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XG_STATE_DIR", filepath.Join(dir, "state"))
	db, err := store.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	total := func() (n int64) {
		db.QueryRow(`SELECT coalesce(sum(hits),0) FROM ipdb_country`).Scan(&n)
		return
	}
	l := &IPDB{}
	// Agent started while the kernel already counted 8,000 drops.
	l.recordHits(db, map[string]uint64{"198.51.100.0/24": 8000})
	if n := total(); n != 0 {
		t.Fatalf("baseline counted as hits: %d", n)
	}
	l.recordHits(db, map[string]uint64{"198.51.100.0/24": 8120, "203.0.113.7": 5})
	if n := total(); n != 125 {
		t.Fatalf("after new drops: %d, want 125 (120 + a new entry's 5)", n)
	}
	// Counters reset (the set was reloaded): the new count is all new.
	l.recordHits(db, map[string]uint64{"198.51.100.0/24": 30, "203.0.113.7": 5})
	if n := total(); n != 155 {
		t.Fatalf("after a counter reset: %d, want 155", n)
	}
	// A restart: a new process starts from a baseline again.
	l2 := &IPDB{}
	l2.recordHits(db, map[string]uint64{"198.51.100.0/24": 30, "203.0.113.7": 5})
	if n := total(); n != 155 {
		t.Fatalf("restart counted old drops again: %d", n)
	}
}

// An empty first reading (no drops yet) is the baseline too: the first drops
// afterwards count.
func TestIPDBHitsAfterEmptyBaseline(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XG_STATE_DIR", filepath.Join(dir, "state"))
	db, _ := store.Open()
	defer db.Close()
	l := &IPDB{}
	l.recordHits(db, map[string]uint64{})
	l.recordHits(db, map[string]uint64{"203.0.113.7": 3})
	var n int64
	db.QueryRow(`SELECT coalesce(sum(hits),0) FROM ipdb_country`).Scan(&n)
	if n != 3 {
		t.Fatalf("hits %d, want 3", n)
	}
}

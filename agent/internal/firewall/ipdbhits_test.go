package firewall

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

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

// The counters' keys must not point into the `ipset list` output: one
// remembered entry kept the whole output (megabytes) alive, and a busy
// server's agent grew to 3 GB in IPTables.IPDBCounters (business200).
func TestIPSetCounterKeysAreCopies(t *testing.T) {
	var b strings.Builder
	b.WriteString("Name: xg_ipdb4\nType: hash:net\nMembers:\n")
	for i := 0; i < 2000; i++ {
		fmt.Fprintf(&b, "10.%d.%d.0/24 packets %d bytes 600\n", i/250, i%250, i+1)
	}
	raw := b.String()
	out := map[string]uint64{}
	parseIPSetCounters(raw, out)
	if len(out) != 2000 {
		t.Fatalf("parsed %d entries, want 2000", len(out))
	}
	lo := uintptr(unsafe.Pointer(unsafe.StringData(raw)))
	hi := lo + uintptr(len(raw))
	for k := range out {
		if p := uintptr(unsafe.Pointer(unsafe.StringData(k))); p >= lo && p < hi {
			t.Fatalf("key %q shares the ipset output's memory", k)
		}
	}
}

// Entries no longer counted are forgotten (the remembered map does not
// grow with every entry ever seen), and a failed reading changes nothing.
func TestIPDBHitsForgetsOldEntries(t *testing.T) {
	db := testDB(t)
	l := &IPDB{}
	l.recordHits(db, map[string]uint64{"198.51.100.0/24": 10, "203.0.113.7": 5})
	l.recordHits(db, map[string]uint64{"198.51.100.0/24": 12})
	if _, ok := l.last["203.0.113.7"]; ok || len(l.last) != 1 {
		t.Fatalf("remembered %v, want only the entry counted now", l.last)
	}
	l.recordHits(db, nil)
	if l.last["198.51.100.0/24"] != 12 {
		t.Fatalf("an empty reading changed the remembered counters: %v", l.last)
	}
}

func testDB(t *testing.T) *sql.DB {
	t.Setenv("XG_STATE_DIR", filepath.Join(t.TempDir(), "state"))
	db, err := store.Open()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

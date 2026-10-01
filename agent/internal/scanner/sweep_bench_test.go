package scanner

import (
	"context"
	"io/fs"
	"os"
	"testing"
	"time"
)

// TestSweepCost measures one sweep of a big tree (XG_SWEEP_TREE) with a tiny
// watch limit, so nearly every folder is swept.
func TestSweepCost(t *testing.T) {
	root := os.Getenv("XG_SWEEP_TREE")
	if root == "" {
		t.Skip("XG_SWEEP_TREE not set")
	}
	s := newScanner(t)
	old := MaxWatches
	MaxWatches = 50
	defer func() { MaxWatches = old }()
	rt := &Realtime{S: s, Roots: func() []string { return []string{root} }}
	if err := rt.init([]string{root}); err != nil {
		t.Skip(err)
	}
	t.Logf("watches %d, unwatched folders %d", rt.Watches(), rt.Unwatched())
	for i := 0; i < 2; i++ {
		t0 := time.Now()
		rt.sweep()
		t.Logf("sweep %d: %v", i, time.Since(t0))
	}
}

// TestScanTreeCost scans XG_SCAN_TREE in-process (run with -cpuprofile to
// see where scan time goes).
func TestScanTreeCost(t *testing.T) {
	root := os.Getenv("XG_SCAN_TREE")
	if root == "" {
		t.Skip("XG_SCAN_TREE not set")
	}
	s := newScanner(t)
	cfg := s.Settings.Get().Scanner
	cfg.YARA = false
	var files int64
	t0 := time.Now()
	n, err := s.scanTree(context.Background(), []string{root}, time.Time{}, cfg, treeHooks{
		total: func(int64) {}, progress: func(int64, string) {},
		hit: func(string, fs.FileInfo, Detection) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	files = n
	d := time.Since(t0)
	t.Logf("%d files in %v: %.0f files/s", files, d, float64(files)/d.Seconds())
}

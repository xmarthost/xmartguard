package scanner

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

// TestRuleCost times each signature rule over the script files of
// XG_SCAN_TREE (a tool for keeping scans fast).
func TestRuleCost(t *testing.T) {
	root := os.Getenv("XG_SCAN_TREE")
	if root == "" {
		t.Skip("XG_SCAN_TREE not set")
	}
	type file struct {
		ext       string
		data, low []byte
	}
	var files []file
	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() && ScriptExts[extOf(d.Name())] {
			if b, err := os.ReadFile(p); err == nil && len(b) < 4<<20 {
				files = append(files, file{extOf(d.Name()), b, lowerASCII(b)})
			}
		}
		return nil
	})
	cost := map[string]time.Duration{}
	for i := range Rules {
		r := &Rules[i]
		t0 := time.Now()
		for _, f := range files {
			if len(r.Exts) > 0 && !hasExt(r.Exts, f.ext) {
				continue
			}
			if r.lit != nil {
				_ = bytes.Contains(f.data, r.lit)
				continue
			}
			if may(r.re, f.low) {
				r.re.Match(f.data)
			}
		}
		cost[r.ID] += time.Since(t0)
	}
	ids := make([]string, 0, len(cost))
	for id := range cost {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return cost[ids[i]] > cost[ids[j]] })
	for _, id := range ids[:min(12, len(ids))] {
		t.Logf("%-28s %v", id, cost[id])
	}
}

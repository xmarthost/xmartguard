package scanner

import (
	"crypto/md5"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestVerdictDump writes the verdict of every distinct script file under
// XG_SCAN_TREE to XG_VERDICT_OUT, to compare detection before and after a
// speed change.
func TestVerdictDump(t *testing.T) {
	root, out := os.Getenv("XG_SCAN_TREE"), os.Getenv("XG_VERDICT_OUT")
	if root == "" || out == "" {
		t.Skip("XG_SCAN_TREE / XG_VERDICT_OUT not set")
	}
	seen := map[[16]byte]bool{}
	var lines []string
	for _, r := range strings.Split(root, ":") {
		filepath.WalkDir(r, func(p string, d fs.DirEntry, err error) error {
			if err != nil || !d.Type().IsRegular() {
				return nil
			}
			b, err := os.ReadFile(p)
			if err != nil || len(b) > 8<<20 {
				return nil
			}
			sum := md5.Sum(b)
			if seen[sum] {
				return nil
			}
			seen[sum] = true
			ext := extOf(d.Name())
			v := "-"
			if rl := Match(ext, b); rl != nil {
				v = rl.ID
			} else if dd := analyze(ext, b); dd != nil {
				v = dd.Signature
			}
			lines = append(lines, fmt.Sprintf("%x %s", sum, v))
			return nil
		})
	}
	sort.Strings(lines)
	os.WriteFile(out, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
	t.Logf("%d distinct files", len(lines))
}

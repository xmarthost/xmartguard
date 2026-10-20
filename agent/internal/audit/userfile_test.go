package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A huge sparse wp-config.php (no quota used) does not make the audit
// allocate its size and kill the agent (A5 F2).
func TestWordPressChecksSparseConfig(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "wp-content", "index.php"), "<?php\n")
	f, err := os.Create(filepath.Join(dir, "wp-config.php"))
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("<?php\ndefine('WP_DEBUG', true);\n")
	if err := f.Truncate(10 << 30); err != nil {
		t.Skip("no sparse files here:", err)
	}
	f.Close()
	for _, it := range wordpressChecks(dir) {
		if it.Check == "wp_debug" && strings.Contains(it.Title, "shows errors") {
			t.Fatal("parsed a 10 GB wp-config.php")
		}
	}
	// A normal one is still checked.
	write(t, filepath.Join(dir, "wp-config.php"), "<?php\ndefine('WP_DEBUG', true);\n")
	found := false
	for _, it := range wordpressChecks(dir) {
		found = found || it.Check == "wp_debug" && strings.Contains(it.Title, "shows errors")
	}
	if !found {
		t.Fatal("debug mode not reported")
	}
}

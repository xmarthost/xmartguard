package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 2026-11-11: from accounts CageFS did not jail, the attacker read other
// sites' wp-config.php (644 in a 755 public_html) and took over 130
// WordPress administrators. Both are reported now.
func TestCrossAccountPivotReported(t *testing.T) {
	home := t.TempDir()
	// The test's own folders let others through, like /home2/<user>.
	for d := home; strings.HasPrefix(d, os.TempDir()) && d != os.TempDir(); d = filepath.Dir(d) {
		os.Chmod(d, 0o711)
	}
	site := filepath.Join(home, "public_html")
	os.MkdirAll(filepath.Join(site, "wp-content"), 0o755)
	os.Chmod(site, 0o755)
	cfg := filepath.Join(site, "wp-config.php")
	os.WriteFile(cfg, []byte("<?php define('DB_PASSWORD', 'inert');"), 0o644)
	found := func() bool {
		for _, it := range wordpressChecks(site) {
			if it.Check == "wp_config_readable" && it.Severity == "high" {
				return true
			}
		}
		return false
	}
	// t.TempDir's parents may not let others through on this machine.
	if !otherReadable(cfg) {
		t.Skip("temporary folder not reachable by others here")
	}
	if !found() {
		t.Fatal("readable wp-config.php not reported")
	}
	os.Chmod(cfg, 0o600)
	if found() {
		t.Error("owner-only wp-config.php reported")
	}
	os.Chmod(cfg, 0o644)
	os.Chmod(site, 0o750) // cPanel's default: group nobody, no one else
	if found() {
		t.Error("wp-config.php behind a closed public_html reported")
	}

	a := &Auditor{StackRoot: t.TempDir(), CageFSDisabled: func() []string { return []string{"trionmar", "fillvent"} }}
	items := a.cagefsDisabled()
	if len(items) != 1 || items[0].Severity != "high" || !strings.Contains(items[0].Detail, "fillvent, trionmar") {
		t.Fatalf("%+v", items)
	}
	a.CageFSDisabled = func() []string { return nil }
	if len(a.cagefsDisabled()) != 0 {
		t.Error("reported with every account jailed")
	}
	// No CageFS on the server: nothing to say.
	if (&Auditor{StackRoot: t.TempDir()}).cagefsDisabled() != nil {
		t.Error("reported without CageFS")
	}
}

package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The panel, web server, mail server and webmail releases with the
// exploited holes of 2026 are reported; patched ones and OpenLiteSpeed
// are not.
func TestStackCVEs(t *testing.T) {
	root := t.TempDir()
	put := func(p, body string) {
		os.MkdirAll(filepath.Dir(filepath.Join(root, p)), 0o755)
		os.WriteFile(filepath.Join(root, p), []byte(body), 0o644)
	}
	put("usr/local/cpanel/version", "11.134.0.20\n")
	put("usr/local/lsws/VERSION", "6.3.4\n")
	put("usr/local/cpanel/base/3rdparty/roundcube/program/include/iniset.php", "<?php\ndefine('RCMAIL_VERSION', '1.6.10');\n")
	a := &Auditor{StackRoot: root, EximVersion: func() string { return "Exim version 4.98 #2 built 01-Jan-2026\n" }}
	items := a.stackCVEs()
	var titles []string
	for _, it := range items {
		titles = append(titles, it.Title)
		if it.Severity != "high" || it.Check != "stack_cve" {
			t.Errorf("%+v", it)
		}
	}
	if len(items) != 4 {
		t.Fatalf("old releases: %v", titles)
	}

	put("usr/local/cpanel/version", "11.136.0.32\n")
	put("usr/local/lsws/VERSION", "1.8.3\n") // OpenLiteSpeed
	put("usr/local/cpanel/base/3rdparty/roundcube/program/include/iniset.php", "<?php\ndefine('RCMAIL_VERSION', '1.5.10');\n")
	a.EximVersion = func() string { return "Exim version 4.99.2 #2 built\n" }
	if items := a.stackCVEs(); len(items) != 0 {
		t.Fatalf("patched releases reported: %+v", items)
	}
	put("usr/local/lsws/VERSION", "6.3.7\n")
	a.EximVersion = func() string { return "" }
	if items := a.stackCVEs(); len(items) != 0 {
		t.Fatalf("%+v", items)
	}
	if !strings.Contains(cpanelFix.why, "41940") {
		t.Error("cPanel reason")
	}
}

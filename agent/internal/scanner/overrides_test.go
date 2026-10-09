package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The portal's AI Learning decisions: a signature on review reports its
// matches as suspicious (the AI decides), one turned off reports nothing.
func TestSignatureOverrides(t *testing.T) {
	s := newScanner(t)
	root := writeTree(t, map[string]string{"a.php": "<?php\n// header\n" + malicious["wso.php"] + "\n$x = 1;\n"})
	p := filepath.Join(root, "a.php")
	info, _ := os.Stat(p)
	cfg := s.Settings.Get().Scanner
	d, _ := s.CheckFile(p, info, cfg)
	if d == nil || d.Category != CatVirus {
		t.Fatalf("detection %+v", d)
	}
	sig := d.Signature

	content, _ := os.ReadFile(p)
	line, code := Locate(sig, content)
	if line != 3 || !strings.Contains(code, "default_action") || !strings.HasPrefix(code, "<?php") {
		t.Fatalf("located line %d: %q", line, code)
	}
	if l, c := Locate("No.Such.Signature", content); l != 0 || c != "" {
		t.Fatal("unknown signature located")
	}

	if err := SetOverrides(map[string]string{sig: OverrideReview, "x": "bogus"}); err != nil {
		t.Fatal(err)
	}
	if d, _ := s.CheckFile(p, info, cfg); d == nil || d.Category != CatSuspicious || d.Signature != sig {
		t.Fatalf("review: %+v", d)
	}
	if !InReview(sig) || len(Overrides()) != 1 {
		t.Fatalf("overrides %v", Overrides())
	}
	SetOverrides(map[string]string{sig: OverrideOff})
	if d, _ := s.CheckFile(p, info, cfg); d != nil {
		t.Fatalf("off: %+v", d)
	}
	// Kept on disk for the scan engine process.
	overrides.mu.Lock()
	overrides.loaded = false
	overrides.mu.Unlock()
	if Overrides()[sig] != OverrideOff {
		t.Fatal("decisions not saved")
	}
	SetOverrides(nil)
	if d, _ := s.CheckFile(p, info, cfg); d == nil || d.Category != CatVirus {
		t.Fatalf("cleared: %+v", d)
	}
}

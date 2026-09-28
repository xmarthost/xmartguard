package firewall

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCSFCompat(t *testing.T) {
	root := t.TempDir()
	csfRoot = root
	defer func() { csfRoot = "" }()
	if DetectCSF().Installed {
		t.Fatal("no CSF expected")
	}
	os.MkdirAll(filepath.Join(root, "etc/csf"), 0o755)
	os.WriteFile(filepath.Join(root, csfConf), []byte("TESTING = \"1\"\nTCP_IN = \"22,80,443\"\n"), 0o600)
	os.WriteFile(filepath.Join(root, csfAllow), []byte("# comment\n162.55.6.159 # XMart Guard portal\n10.0.0.0/8\ntcp|in|d=22|s=198.51.100.7\nInclude /etc/csf/extra.allow\n"), 0o600)
	os.WriteFile(filepath.Join(root, "etc/csf/extra.allow"), []byte("203.0.113.5\n"), 0o600)
	os.WriteFile(filepath.Join(root, csfIgnore), []byte("192.0.2.1\n162.55.6.159\n"), 0o600)
	c := DetectCSF()
	if !c.Installed || !c.Enabled || !c.Testing || !c.PortFilter {
		t.Fatalf("detect: %+v", c)
	}
	got := strings.Join(CSFExempt(), ",")
	if got != "162.55.6.159,10.0.0.0/8,203.0.113.5,192.0.2.1" {
		t.Fatalf("exempt = %s", got)
	}
	// csf -x disables CSF: our port filter comes back.
	os.WriteFile(filepath.Join(root, csfDisable), nil, 0o600)
	if DetectCSF().Enabled {
		t.Fatal("disabled CSF reported enabled")
	}
	// Hook: added once next to an existing csfpost.sh, removed cleanly.
	os.MkdirAll(filepath.Join(root, "usr/local/csf/bin"), 0o755)
	os.WriteFile(filepath.Join(root, csfPost), []byte("#!/bin/sh\n/usr/local/bin/other-script\n"), 0o700)
	if EnsureCSFHook() != nil || EnsureCSFHook() != nil {
		t.Fatal("hook")
	}
	b, _ := os.ReadFile(filepath.Join(root, csfPost))
	if strings.Count(string(b), csfHookTag) != 1 || !strings.Contains(string(b), "other-script") {
		t.Fatalf("csfpost.sh = %q", b)
	}
	RemoveCSFHook()
	b, _ = os.ReadFile(filepath.Join(root, csfPost))
	if strings.Contains(string(b), csfHookTag) || !strings.Contains(string(b), "other-script") {
		t.Fatalf("after remove: %q", b)
	}
	// A csfpost.sh we created alone is deleted again.
	os.Remove(filepath.Join(root, csfPost))
	EnsureCSFHook()
	RemoveCSFHook()
	if _, err := os.Stat(filepath.Join(root, csfPost)); err == nil {
		t.Fatal("empty csfpost.sh left behind")
	}
}

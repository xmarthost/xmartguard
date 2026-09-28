package mail

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEximRBLs(t *testing.T) {
	root := t.TempDir()
	eximRoot = root
	defer func() { eximRoot = "" }()
	if a, _ := EnsureEximRBLs(); a != nil {
		t.Fatal("added RBLs on a server without cPanel")
	}
	os.MkdirAll(filepath.Join(root, "usr/local/cpanel"), 0o755)
	os.WriteFile(filepath.Join(root, "usr/local/cpanel/cpanel"), nil, 0o755)
	os.MkdirAll(filepath.Join(root, rblDir), 0o755)
	os.MkdirAll(filepath.Join(root, "etc"), 0o755)
	// Another product already defined barracuda; the admin enabled it.
	os.WriteFile(filepath.Join(root, rblDir, "barracuda.yaml"), []byte("---\n\"name\": 'barracuda'\n"), 0o644)
	os.WriteFile(filepath.Join(root, eximLocalOpt), []byte("acl_barracuda_rbl=1\nacl_spamhaus_rbl=1"), 0o644)
	added, err := EnsureEximRBLs()
	if err != nil || strings.Join(added, ",") != "spameatingmonkey,abuseat,psbl,mailspike" {
		t.Fatalf("added %v %v", added, err)
	}
	if again, _ := EnsureEximRBLs(); len(again) != 0 {
		t.Fatalf("added twice: %v", again)
	}
	opts, _ := os.ReadFile(filepath.Join(root, eximLocalOpt))
	if !strings.Contains(string(opts), "acl_spamhaus_rbl=1\nacl_spameatingmonkey_rbl=0\n") || strings.Count(string(opts), "acl_barracuda_rbl") != 1 {
		t.Fatalf("localopts = %q", opts)
	}
	y, _ := os.ReadFile(filepath.Join(root, rblDir, "psbl.yaml"))
	if !strings.Contains(string(y), "  - 'psbl.surriel.com'") {
		t.Fatalf("yaml = %q", y)
	}
	st := EximRBLStatus()
	if len(st) != 5 || !st[0].Enabled || st[1].Enabled {
		t.Fatalf("status %+v", st)
	}
	removed := RemoveEximRBLs()
	if len(removed) != 4 {
		t.Fatalf("removed %v", removed)
	}
	if _, err := os.Stat(filepath.Join(root, rblDir, "barracuda.yaml")); err != nil {
		t.Fatal("foreign definition removed")
	}
	opts, _ = os.ReadFile(filepath.Join(root, eximLocalOpt))
	if string(opts) != "acl_barracuda_rbl=1\nacl_spamhaus_rbl=1\n" {
		t.Fatalf("after remove localopts = %q", opts)
	}
}

package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInsecureSymlink(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to own files as another user")
	}
	dir := t.TempDir()
	other := filepath.Join(dir, "other")
	mine := filepath.Join(dir, "mine")
	os.MkdirAll(other, 0o755)
	os.MkdirAll(mine, 0o755)
	secret := filepath.Join(other, "wp-config.php")
	os.WriteFile(secret, []byte("<?php // db password"), 0o640)
	os.Chown(other, 65534, 65534)
	os.Chown(secret, 65534, 65534)
	public := filepath.Join(dir, "public.txt")
	os.WriteFile(public, []byte("x"), 0o644)
	os.Chown(public, 65534, 65534)

	link := filepath.Join(mine, "cfg.txt")
	os.Symlink(secret, link)
	homes := map[uint32]string{65534: other, 0: mine}
	if target, bad := InsecureSymlink(link, homes); !bad || target != secret {
		t.Fatalf("link into another home not flagged: %q %v", target, bad)
	}
	ok := filepath.Join(mine, "pub.txt")
	os.Symlink(public, ok)
	if _, bad := InsecureSymlink(ok, homes); bad {
		t.Fatal("link to a world-readable file outside homes flagged")
	}
	dangling := filepath.Join(mine, "gone")
	os.Symlink(filepath.Join(dir, "missing"), dangling)
	if _, bad := InsecureSymlink(dangling, homes); bad {
		t.Fatal("dangling link flagged")
	}
}

func TestYARAScan(t *testing.T) {
	if YARABin() == "" {
		t.Skip("yara not installed")
	}
	dir := t.TempDir()
	t.Setenv("XG_CONFIG_DIR", dir)
	os.MkdirAll(YARADir(), 0o755)
	os.WriteFile(filepath.Join(YARADir(), "test.yar"), []byte(`rule XG_Test_Marker { strings: $a = "XG-TEST-MARKER-7f3a" condition: $a }`), 0o644)
	hit := filepath.Join(dir, "a.php")
	miss := filepath.Join(dir, "b.php")
	os.WriteFile(hit, []byte("<?php // XG-TEST-MARKER-7f3a"), 0o644)
	os.WriteFile(miss, []byte("<?php echo 1;"), 0o644)
	got := yaraScan(t.Context(), []string{hit, miss})
	if got[hit] != "XG_Test_Marker" || len(got) != 1 {
		t.Fatalf("yara: %v", got)
	}
}

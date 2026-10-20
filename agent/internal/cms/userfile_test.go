package cms

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

const inertWPConfig = "<?php\ndefine('DB_NAME','site_db');\ndefine('DB_USER','site_user');\ndefine('DB_PASSWORD','pw');\n"

// A huge sparse wp-config.php is refused without allocating its size: the
// account must not be able to stop the agent with "out of memory" (A5 F2).
func TestSparseWPConfigRefused(t *testing.T) {
	site := t.TempDir()
	f, err := os.Create(filepath.Join(site, "wp-config.php"))
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(inertWPConfig)
	if err := f.Truncate(10 << 30); err != nil { // 10 GB, sparse
		t.Skip("no sparse files here:", err)
	}
	f.Close()
	if _, err := ReadWPConfig(site); err == nil {
		t.Fatal("10 GB wp-config.php was read")
	}
	if _, err := EnsureRealCron(site, "nobody", 12); err == nil {
		t.Fatal("EnsureRealCron read a 10 GB wp-config.php")
	}
	if _, err := ReadUserFile(filepath.Join(site, "wp-config.php"), MaxConfigSize); err == nil {
		t.Fatal("ReadUserFile")
	}
	// A normal one still works.
	os.WriteFile(filepath.Join(site, "wp-config.php"), []byte(inertWPConfig), 0o640)
	if c, err := ReadWPConfig(site); err != nil || c.Name != "site_db" {
		t.Fatalf("%+v %v", c, err)
	}
}

// A wp-config.php that is a symlink to another account's file is not read
// (no DB scan or clean of that account's database) and not rewritten (A5 F7).
func TestSymlinkedWPConfigSkipped(t *testing.T) {
	base := t.TempDir()
	other := filepath.Join(base, "b", "public_html")
	site := filepath.Join(base, "a", "public_html")
	os.MkdirAll(other, 0o755)
	os.MkdirAll(site, 0o755)
	target := filepath.Join(other, "wp-config.php")
	os.WriteFile(target, []byte(inertWPConfig), 0o640)
	if err := os.Symlink(target, filepath.Join(site, "wp-config.php")); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadWPConfig(site); err == nil {
		t.Fatal("symlinked wp-config.php was read")
	}
	if _, err := EnsureRealCron(site, "nobody", 12); err == nil {
		t.Fatal("EnsureRealCron followed the symlink")
	}
	if _, err := RemoveRealCron(site, "nobody"); err != nil {
		_ = err // no crontab is fine; the file must stay unchanged
	}
	if b, _ := os.ReadFile(target); string(b) != inertWPConfig {
		t.Fatalf("the other account's file changed: %q", b)
	}
}

// Files owned by another account (a hard link), or reached through a folder
// of the account swapped for a symlink to another account's folder, are not
// the account's own (A5 F7).
func TestAccountFileOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to set owners")
	}
	const a, b = 61001, 61002
	base := t.TempDir() // owned by root
	home := filepath.Join(base, "a")
	site := filepath.Join(home, "public_html")
	os.MkdirAll(site, 0o755)
	cfg := filepath.Join(site, "wp-config.php")
	os.WriteFile(cfg, []byte(inertWPConfig), 0o640)
	for _, p := range []string{home, site, cfg} {
		os.Lchown(p, a, a)
	}
	if _, err := ReadWPConfig(site); err != nil {
		t.Fatalf("own file: %v", err)
	}
	if err := writeAccountFile(cfg, []byte(inertWPConfig+"// x\n")); err != nil {
		t.Fatalf("write own file: %v", err)
	}
	// The file belongs to another account.
	os.Lchown(cfg, b, b)
	if _, err := ReadWPConfig(site); err == nil {
		t.Fatal("another account's file was read")
	}
	if err := writeAccountFile(cfg, []byte("x")); err == nil {
		t.Fatal("another account's file was written")
	}
	// The site folder is reached through the account's symlink to
	// another account's folder.
	otherHome := filepath.Join(base, "b")
	otherSite := filepath.Join(otherHome, "public_html", "sub")
	os.MkdirAll(otherSite, 0o755)
	os.WriteFile(filepath.Join(otherSite, "wp-config.php"), []byte(inertWPConfig), 0o640)
	for _, p := range []string{otherHome, filepath.Join(otherHome, "public_html"), otherSite, filepath.Join(otherSite, "wp-config.php")} {
		os.Lchown(p, b, b)
	}
	os.RemoveAll(site)
	os.Symlink(filepath.Join(otherHome, "public_html"), site)
	os.Lchown(site, a, a)
	if _, err := ReadWPConfig(filepath.Join(site, "sub")); err == nil {
		t.Fatal("read through a swapped folder symlink")
	}
}

// A FIFO among the plugins or in place of a core file does not block the
// CMS scan forever (A5 F8).
func TestFIFOInSiteDoesNotBlock(t *testing.T) {
	root := t.TempDir()
	plug := filepath.Join(root, "wp-content", "plugins", "x")
	os.MkdirAll(plug, 0o755)
	os.MkdirAll(filepath.Join(root, "wp-admin"), 0o755)
	if err := syscall.Mkfifo(filepath.Join(plug, "a.php"), 0o644); err != nil {
		t.Skip("mkfifo:", err)
	}
	syscall.Mkfifo(filepath.Join(root, "wp-content", "plugins", "b.php"), 0o644)
	syscall.Mkfifo(filepath.Join(root, "wp-admin", "about.php"), 0o644)
	os.Symlink(filepath.Join(plug, "a.php"), filepath.Join(root, "wp-admin", "linked.php"))
	done := make(chan struct{})
	go func() {
		Plugins(root)
		VerifyCore(root, map[string]string{"wp-admin/about.php": "00", "wp-admin/linked.php": "00"})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the scan blocked on a FIFO")
	}
}

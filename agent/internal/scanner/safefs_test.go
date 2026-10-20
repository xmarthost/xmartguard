package scanner

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// accountLink makes a symbolic link owned by an account (uid 65534), as a
// customer or a web shell running as the account would plant it.
func accountLink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := os.Lchown(link, 65534, 65534); err != nil {
		t.Skipf("lchown: %v", err)
	}
}

// recordInert records an inert file as a finding (no real malware needed:
// the actions only care about the row and the file).
func recordInert(t *testing.T, s *Scanner, p string) int64 {
	t.Helper()
	info, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	f, err := s.Record(0, "manual", p, info, Detection{CatVirus, "XG-TEST.Inert"})
	if err != nil {
		t.Fatal(err)
	}
	return f.ID
}

// A2 F2 / A1 F2: once the account swaps a folder on a finding's path for a
// link to a root folder, restore, delete, quarantine and disable must not
// act in that folder.
func TestFileActionsRefuseAccountLinkInPath(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	s := newScanner(t)
	base := t.TempDir()
	web := filepath.Join(base, "home", "acct", "public_html")
	outside := filepath.Join(base, "etc-like") // stands for a root folder
	os.MkdirAll(web, 0o755)
	os.MkdirAll(outside, 0o755)

	// Restore: quarantined, then public_html becomes a link to outside.
	p := filepath.Join(web, "x.php")
	os.WriteFile(p, []byte("<?php echo 1;"), 0o644)
	id := recordInert(t, s, p)
	if err := s.Quarantine(id); err != nil {
		t.Fatal(err)
	}
	os.Remove(web)
	accountLink(t, outside, web)
	if err := s.Restore(id); !errors.Is(err, ErrLinkInPath) {
		t.Fatalf("restore through a link: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(outside, "x.php")); err == nil {
		t.Fatal("restore wrote into the linked folder")
	}

	// Delete, quarantine and disable of a detected file whose folder now
	// links to a folder holding a root file of the same name.
	os.Remove(web)
	os.MkdirAll(web, 0o755)
	p2 := filepath.Join(web, "conf")
	os.WriteFile(p2, []byte("<?php echo 2;"), 0o644)
	id2 := recordInert(t, s, p2)
	victim := filepath.Join(outside, "conf")
	os.WriteFile(victim, []byte("root's file"), 0o640)
	os.RemoveAll(web)
	accountLink(t, outside, web)
	if err := s.Disable(id2); !errors.Is(err, ErrLinkInPath) {
		t.Fatalf("disable through a link: %v", err)
	}
	if err := s.Quarantine(id2); !errors.Is(err, ErrLinkInPath) {
		t.Fatalf("quarantine through a link: %v", err)
	}
	if err := s.Delete(id2); !errors.Is(err, ErrLinkInPath) {
		t.Fatalf("delete through a link: %v", err)
	}
	if b, _, err := s.Content(id2, 100); err == nil {
		t.Fatalf("content read through a link: %q", b)
	}
	if st, err := os.Stat(victim); err != nil || st.Mode().Perm() != 0o640 {
		t.Fatalf("root file touched: %v %v", st, err)
	}

	// A disabled file swapped for a link: restore's chmod does not follow it.
	os.Remove(web)
	os.MkdirAll(web, 0o755)
	p3 := filepath.Join(web, "y.php")
	os.WriteFile(p3, []byte("<?php echo 3;"), 0o644)
	id3 := recordInert(t, s, p3)
	if err := s.Disable(id3); err != nil {
		t.Fatal(err)
	}
	os.Remove(p3)
	accountLink(t, victim, p3)
	if err := s.Restore(id3); err == nil {
		t.Fatal("restore of a disabled file followed a link")
	}
	if st, _ := os.Stat(victim); st.Mode().Perm() != 0o640 {
		t.Fatalf("root file chmod'ed through a link: %v", st.Mode())
	}
}

// A root-owned link on the path (a server with /home linked to /home2) is
// the administrator's and is followed.
func TestFileActionsFollowRootLinks(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	s := newScanner(t)
	base := t.TempDir()
	os.MkdirAll(filepath.Join(base, "home2", "acct", "public_html"), 0o755)
	os.Symlink("home2", filepath.Join(base, "home"))
	p := filepath.Join(base, "home", "acct", "public_html", "x.php")
	os.WriteFile(p, []byte("<?php echo 1;"), 0o640)
	id := recordInert(t, s, p)
	if err := s.Quarantine(id); err != nil {
		t.Fatal(err)
	}
	if err := s.Restore(id); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(p); err != nil || st.Mode().Perm() != 0o640 {
		t.Fatalf("restored: %v %v", st, err)
	}
}

// A2 F1: Trim and the cleaners write the new content as root; a link the
// account planted at the old fixed temporary name (".<name>.xg-new") or in
// place of the folder must not receive it.
func TestReplaceLiveIgnoresPlantedLinks(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	s := newScanner(t)
	base := t.TempDir()
	web := filepath.Join(base, "public_html")
	outside := filepath.Join(base, "outside")
	os.MkdirAll(web, 0o755)
	os.MkdirAll(outside, 0o755)
	victim := filepath.Join(outside, "victim")
	os.WriteFile(victim, []byte("root's file"), 0o600)

	p := filepath.Join(web, "index.php")
	os.WriteFile(p, []byte("<?php echo 'infected';"), 0o644)
	os.Chown(p, 65534, 65534)
	id := recordInert(t, s, p)
	accountLink(t, victim, filepath.Join(web, ".index.php.xg-new"))
	if err := s.ReplaceWithOfficial(id, []byte("<?php echo 'official';")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "root's file" {
		t.Fatalf("root wrote through the planted link: %q", b)
	}
	st, err := os.Lstat(p)
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0o644 || st.Sys().(*syscall.Stat_t).Uid != 65534 {
		t.Fatalf("replaced file: %v %v", st, err)
	}
	if b, _ := os.ReadFile(p); string(b) != "<?php echo 'official';" {
		t.Fatalf("content %q", b)
	}
	if left, _ := filepath.Glob(filepath.Join(web, ".xg-*")); len(left) != 0 {
		t.Fatalf("temporary files left: %v", left)
	}

	// The folder swapped for a link to outside: refused.
	p2 := filepath.Join(web, "b.php")
	os.WriteFile(p2, []byte("<?php echo 'b';"), 0o644)
	id2 := recordInert(t, s, p2)
	moved := filepath.Join(base, "moved")
	os.Rename(web, moved)
	accountLink(t, outside, web)
	if err := s.ReplaceWithOfficial(id2, []byte("<?php echo 'x';")); err == nil {
		t.Fatal("replace through a linked folder")
	}
	if _, err := os.Lstat(filepath.Join(outside, "b.php")); err == nil {
		t.Fatal("wrote into the linked folder")
	}
}

// A2 F10: a finding's path that became a FIFO is refused at once instead of
// blocking a worker; the scan read does not follow a link put at the name.
func TestReadsRefuseSpecialFiles(t *testing.T) {
	s := newScanner(t)
	dir := t.TempDir()
	p := filepath.Join(dir, "x.php")
	os.WriteFile(p, []byte("<?php echo 1;"), 0o644)
	id := recordInert(t, s, p)
	info, _ := os.Lstat(p)
	os.Remove(p)
	if err := syscall.Mkfifo(p, 0o644); err != nil {
		t.Skip(err)
	}
	done := make(chan error, 1)
	go func() {
		_, _, err := s.Content(id, 100)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "regular") {
			t.Fatalf("FIFO read: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reading a FIFO blocked")
	}
	if _, err := s.CheckFile(p, info, s.Settings.Get().Scanner); err == nil {
		t.Fatal("scan read a FIFO in place of the stat'ed file")
	}
	if sha256File(p) != "" {
		t.Fatal("hashed a FIFO")
	}
	os.Remove(p)
	other := filepath.Join(dir, "other")
	os.WriteFile(other, []byte("<?php echo 2;"), 0o644)
	os.Symlink(other, p)
	if _, err := s.CheckFile(p, info, s.Settings.Get().Scanner); err == nil {
		t.Fatal("scan read through a link")
	}
}

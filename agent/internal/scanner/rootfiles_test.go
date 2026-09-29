package scanner

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// Tests run as root: their files are root's, so the scanner must look at them.
func TestMain(m *testing.M) {
	ScanRootFiles = true
	os.Exit(m.Run())
}

// system switches off ScanRootFiles for one test, as on a real server.
func system(t *testing.T) {
	ScanRootFiles = false
	t.Cleanup(func() { ScanRootFiles = true })
}

// compile builds a relocatable object and a program from a tiny C file.
func compile(t *testing.T, dir string) (obj, prog string) {
	t.Helper()
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("no C compiler")
	}
	src := filepath.Join(dir, "x.c")
	os.WriteFile(src, []byte("int main(void){return 0;}\n"), 0o644)
	obj, prog = filepath.Join(dir, "scanner1.o"), filepath.Join(dir, "prog")
	if out, err := exec.Command(cc, "-c", "-o", obj, src).CombinedOutput(); err != nil {
		t.Skipf("cc: %v %s", err, out)
	}
	if out, err := exec.Command(cc, "-o", prog, src).CombinedOutput(); err != nil {
		t.Skipf("cc: %v %s", err, out)
	}
	os.Remove(src)
	return obj, prog
}

// SpamAssassin's sa-compile leaves relocatable objects (.o) in /var/tmp:
// they cannot run and are not flagged as binaries; programs still are.
func TestObjectFilesAreNotBinaries(t *testing.T) {
	s := newScanner(t)
	dir := filepath.Join(t.TempDir(), "tmp", "Mail-SpamAssassin-CompiledRegexps-body_0")
	os.MkdirAll(dir, 0o755)
	obj, prog := compile(t, dir)
	cfg := s.Settings.Get().Scanner
	for _, c := range []struct {
		path string
		want bool
	}{{obj, false}, {prog, true}} {
		info, _ := os.Stat(c.path)
		d, _ := s.CheckFile(c.path, info, cfg)
		if (d != nil) != c.want {
			t.Errorf("%s: detection %+v, want flagged=%v", filepath.Base(c.path), d, c.want)
		}
	}
}

// Root's files are the system's: never scanned.
func TestRootFilesAreSkipped(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root-owned files")
	}
	s := newScanner(t)
	s.Settings.Patch([]byte(`{"scanner":{"binary_action":"quarantine"}}`))
	dir := filepath.Join(t.TempDir(), "public_html")
	os.MkdirAll(dir, 0o755)
	_, prog := compile(t, dir)
	os.WriteFile(filepath.Join(dir, "x.php"), []byte(`<?php eval(base64_decode($_POST["x"]));`), 0o644)
	system(t)
	for _, p := range []string{prog, filepath.Join(dir, "x.php")} {
		info, _ := os.Stat(p)
		if d, err := s.CheckFile(p, info, s.Settings.Get().Scanner); d != nil || err != ErrTrusted {
			t.Fatalf("root's %s: %+v %v", filepath.Base(p), d, err)
		}
	}
}

// Findings quarantined by the older rules are put back at start.
func TestRestoreSystemFiles(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root-owned files")
	}
	s := newScanner(t)
	s.Settings.Patch([]byte(`{"scanner":{"binary_action":"quarantine"}}`))
	dir := filepath.Join(t.TempDir(), "tmp")
	os.MkdirAll(dir, 0o755)
	_, prog := compile(t, dir)
	gone := filepath.Join(t.TempDir(), "tmp", "cpanel.TMP.work.x", "prog")
	os.MkdirAll(filepath.Dir(gone), 0o755)
	data, _ := os.ReadFile(prog)
	os.WriteFile(gone, data, 0o755)
	for _, p := range []string{prog, gone} {
		info, _ := os.Stat(p)
		f, err := s.Record(0, "realtime", p, info, Detection{CatBinary, "Binary.ELF.InWebOrTempDir"})
		if err != nil || f.Status != "quarantined" {
			t.Fatalf("setup %s: %+v %v", p, f, err)
		}
	}
	os.RemoveAll(filepath.Dir(gone)) // the build folder was cleaned up
	system(t)
	if n := s.RestoreSystemFiles(); n != 2 {
		t.Fatalf("handled %d, want 2", n)
	}
	if _, err := os.Stat(prog); err != nil {
		t.Fatal("program not restored")
	}
	if _, err := os.Stat(filepath.Dir(gone)); err == nil {
		t.Fatal("a removed build folder was recreated")
	}
	fs, _, _ := s.ListFindings(FindingFilter{})
	for _, f := range fs {
		if f.Status == "quarantined" {
			t.Fatalf("still quarantined: %+v", f)
		}
	}
}

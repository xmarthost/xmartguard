package scanner

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
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

func TestScanThreads(t *testing.T) {
	for _, c := range []struct {
		speed string
		cpus  int
		want  int
	}{{"low", 32, 1}, {"auto", 2, 1}, {"auto", 12, 6}, {"fast", 16, 8}, {"auto", 128, 32}} {
		if got := maxWorkers(c.speed, c.cpus); got != c.want {
			t.Errorf("%s/%d cpus: %d, want %d", c.speed, c.cpus, got, c.want)
		}
	}
	// Auto on 12 CPUs (at most 6 threads; the scan may bring the server to 9 cores).
	for _, c := range []struct {
		cur    int
		others float64
		mem    float64
		want   int
	}{
		{1, 0.5, 0.5, 2},  // quiet: grow one at a time
		{5, 0.5, 0.5, 6},  // up to the most
		{6, 0.5, 0.5, 6},  // capped
		{6, 7.5, 0.5, 1},  // websites busy: drop at once
		{6, 11.5, 0.5, 1}, // overloaded: still one, so the scan ends
		{4, 5.2, 0.5, 3},  // 3.8 cores free: 3 threads
		{6, 0.5, 0.05, 1}, // little RAM left
	} {
		if got := nextWorkers(c.cur, 6, 12, c.others, c.mem); got != c.want {
			t.Errorf("cur %d, others %.1f, mem %.2f: %d, want %d", c.cur, c.others, c.mem, got, c.want)
		}
	}
	if m := memAvailable(); m <= 0 || m > 1 {
		t.Errorf("memAvailable %v", m)
	}
	a, ok1 := readCPU()
	x := 0
	for i := 0; i < 5e7; i++ {
		x += i
	}
	b, ok2 := readCPU()
	if !ok1 || !ok2 || b.self < a.self || b.total <= a.total {
		t.Errorf("readCPU: %+v %+v %d", a, b, x)
	}
}

// Scan threads run at nice 19.
func TestLowPriorityThread(t *testing.T) {
	done := make(chan int)
	go func() {
		lowPriorityThread()
		p, err := unix.Getpriority(unix.PRIO_PROCESS, unix.Gettid())
		if err != nil {
			p = -1
		}
		done <- p
	}()
	// Getpriority returns 20 - nice.
	if p := <-done; p != 1 {
		t.Fatalf("priority %d, want 1 (nice 19)", p)
	}
}

func TestScheduleZone(t *testing.T) {
	pkt := ScheduleZone("")
	// 19:30 UTC is 00:30 the next day in Pakistan: inside the nightly window.
	at := time.Date(2026, 9, 29, 19, 30, 0, 0, time.UTC).In(pkt)
	if at.Hour() != 0 || at.Day() != 30 {
		t.Fatalf("PKT: %s", at)
	}
	if ScheduleZone("Nowhere/Invalid").String() != DefaultScheduleTZ || ScheduleZone("Europe/Berlin").String() != "Europe/Berlin" {
		t.Fatal("zones")
	}
}

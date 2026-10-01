package scanner

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func useEngine(t *testing.T) {
	t.Helper()
	EngineCommand = func() *exec.Cmd {
		cmd := exec.Command(os.Args[0])
		cmd.Args[0] = "xpguard-scan"
		cmd.Env = append(os.Environ(), "XG_TEST_SCAN_ENGINE=1")
		return cmd
	}
	t.Cleanup(func() { EngineCommand = nil })
}

// A scan runs in its own process at the lowest priority, finds the same
// files, and what the agent cleared is not reported again.
func TestScanInEngineProcess(t *testing.T) {
	useEngine(t)
	s := newScanner(t)
	root := writeTree(t, map[string]string{
		"public_html/index.php":           "<?php echo 'hello';",
		"public_html/wp-content/x.php":    malicious["exec.php"],
		"public_html/uploads/y.php":       malicious["eval.php"],
		"public_html/uploads/cleared.php": malicious["eval.php"] + "// cleared",
	})
	cleared := sha256File(filepath.Join(root, "public_html/uploads/cleared.php"))
	s.Cleared = func(sha string) bool { return sha == cleared }
	id, err := s.Start("path", root, "test")
	if err != nil {
		t.Fatal(err)
	}
	// The engine shows in the process list while it runs, at nice 19.
	seen := false
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) && !seen {
		seen = engineAtNice19(t)
		if sc, _ := s.GetScan(id); sc.Status == "completed" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	sc := waitScan(t, s, id)
	if sc.Status != "completed" || sc.Files != 4 || sc.Infected != 2 {
		t.Fatalf("%+v", sc)
	}
	fs, n, _ := s.ListFindings(FindingFilter{Limit: 10})
	if n != 2 {
		t.Fatalf("%d findings: %+v", n, fs)
	}
	for _, f := range fs {
		if strings.Contains(f.Path, "cleared") {
			t.Fatal("cleared file reported")
		}
	}
	t.Logf("engine process seen at nice 19: %v", seen)
}

// engineAtNice19 looks for the engine process and checks every thread's
// nice value (field 19 of /proc/PID/task/TID/stat).
func engineAtNice19(t *testing.T) bool {
	procs, _ := filepath.Glob("/proc/[0-9]*/cmdline")
	for _, p := range procs {
		b, _ := os.ReadFile(p)
		if !strings.HasPrefix(string(b), "xpguard-scan\x00") {
			continue
		}
		dir := filepath.Dir(p)
		tasks, _ := filepath.Glob(dir + "/task/*/stat")
		if len(tasks) == 0 {
			return false
		}
		for _, ts := range tasks {
			st, _ := os.ReadFile(ts)
			f := strings.Fields(string(st[strings.LastIndexByte(string(st), ')')+1:]))
			if len(f) < 17 {
				return false
			}
			if n, _ := strconv.Atoi(f[16]); n != 19 {
				t.Errorf("engine thread %s at nice %d", ts, n)
			}
		}
		return true
	}
	return false
}

// Stopping a scan ends the engine process.
func TestStopEngineScan(t *testing.T) {
	useEngine(t)
	s := newScanner(t)
	files := map[string]string{}
	for i := 0; i < 4000; i++ {
		files[filepath.Join("d", strconv.Itoa(i%40), "f"+strconv.Itoa(i)+".php")] = "<?php echo 1;"
	}
	root := writeTree(t, files)
	id, _ := s.Start("path", root, "test")
	time.Sleep(200 * time.Millisecond)
	s.Stop(id)
	if sc := waitScan(t, s, id); sc.Status != "stopped" && sc.Status != "completed" {
		t.Fatalf("status %s", sc.Status)
	}
	time.Sleep(300 * time.Millisecond)
	if engineAtNice19(t) {
		t.Fatal("engine still running after stop")
	}
}

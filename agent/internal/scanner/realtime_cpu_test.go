package scanner

import (
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"
)

// Busy sites append to their error_log on every request: the realtime
// scanner leaves logs to the scheduled scans, but never a script.
func TestRealtimeSkipsLogs(t *testing.T) {
	for _, n := range []string{"error_log", "php.error.log", "debug.log", "access_log", "laravel-2026-10-17.log", "error.log.1", "sess_abc123", "db.sqlite-journal"} {
		if !logLike(n) {
			t.Errorf("%s scanned on every write", n)
		}
	}
	for _, n := range []string{"index.php", "shell.log.php", "error_log.php", ".htaccess", "x.js", "wp-config.php", "upload.phtml", "readme.txt"} {
		if logLike(n) {
			t.Errorf("%s skipped", n)
		}
	}
}

// A file rewritten all the time is handed to the workers once per RescanGap.
func TestRealtimeRescanGap(t *testing.T) {
	old := RescanGap
	RescanGap = time.Hour
	t.Cleanup(func() { RescanGap = old })
	r := &Realtime{pending: map[string]time.Time{}, work: make(chan string, 10)}
	for i := 0; i < 3; i++ {
		r.pending["/home/u/public_html/cache.json"] = time.Now().Add(-time.Second)
		r.flushPending()
	}
	if n := len(r.work); n != 1 {
		t.Fatalf("handed to workers %d times, want once", n)
	}
	if _, waiting := r.pending["/home/u/public_html/cache.json"]; !waiting {
		t.Fatal("the latest change was dropped instead of waiting for the gap")
	}
}

// Overflows in a burst start one catch-up walk, not one per overflow.
func TestRealtimeCatchUpCoalesces(t *testing.T) {
	old := CatchUpGap
	CatchUpGap = time.Hour
	t.Cleanup(func() { CatchUpGap = old })
	var walks atomic.Int32
	r := &Realtime{S: &Scanner{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}, Roots: func() []string { walks.Add(1); return nil }}
	for i := 0; i < 50; i++ {
		r.requestCatchUp(time.Now().Add(-time.Duration(i) * time.Minute))
	}
	deadline := time.Now().Add(5 * time.Second)
	for walks.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	if n := walks.Load(); n != 1 {
		t.Fatalf("%d catch-up walks for one burst", n)
	}
	// Another overflow right after waits for the gap.
	r.requestCatchUp(time.Now())
	time.Sleep(100 * time.Millisecond)
	if n := walks.Load(); n != 1 {
		t.Fatalf("catch-up ran again within the gap (%d)", n)
	}
	r.catchMu.Lock()
	r.catchTimer.Stop()
	r.catchMu.Unlock()
}

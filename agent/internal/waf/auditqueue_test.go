package waf

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// Audit A3 F13: concurrent audit log entries are read by one worker from a
// bounded queue; a flood of index lines no longer starts a goroutine (and
// opens a file) per line. Entries beyond the queue are dropped and counted.
func TestAuditEntriesBounded(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entry := `--9a1b2c3d-A--
[27/Sep/2026:00:30:11.123456 +0500] ZqueueUNIQUE 198.51.100.4 51234 10.0.0.5 443
--9a1b2c3d-B--
GET /xg-test HTTP/1.1
Host: shop.example

--9a1b2c3d-H--
Message: Access denied with code 403 (phase 2). [id "7700601"] [msg "xPGuard - test"]
Action: Intercepted (phase 2)

--9a1b2c3d-Z--
`
	f := filepath.Join(t.TempDir(), "entry")
	os.WriteFile(f, []byte(entry), 0o644)
	out := make(chan auditHit) // nobody reads: the worker blocks on the first hit
	queue := entryWorker(ctx, out, 8, 0)
	before := runtime.NumGoroutine()
	dropped := AuditEntriesDropped.Load()
	accepted := 0
	for i := 0; i < 1000; i++ {
		if queue(f) {
			accepted++
		}
	}
	if accepted > 9 || AuditEntriesDropped.Load()-dropped < 990 {
		t.Fatalf("accepted %d of 1000 with a queue of 8", accepted)
	}
	if n := runtime.NumGoroutine(); n > before+2 {
		t.Fatalf("goroutines grew from %d to %d", before, n)
	}
	select {
	case h := <-out:
		if h.uid != "ZqueueUNIQUE" || h.e.RuleID != 7700601 {
			t.Fatalf("hit %+v", h)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("queued entry not read")
	}
}

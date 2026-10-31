package core

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/store"
)

// A server dashboard opened after a while came up only once all its tables
// were counted (10 s and more on busy servers): the answer is kept, served
// at once, and counted again in the background when older than a minute.
func TestDashboardKeptAndRefreshed(t *testing.T) {
	var c dashCache
	var runs atomic.Int32
	compute := func(days int) map[string]any {
		time.Sleep(20 * time.Millisecond)
		return map[string]any{"days": days, "run": runs.Add(1)}
	}
	// Two pages opening a cold server count once.
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); c.get(30, compute) }()
	}
	wg.Wait()
	if runs.Load() != 1 {
		t.Fatalf("%d counts for 5 cold opens", runs.Load())
	}
	for i := 0; i < 20; i++ {
		if v := c.get(30, compute); v["run"] != int32(1) {
			t.Fatalf("open %d: %v", i, v)
		}
	}
	// Each period has its own answer.
	if v := c.get(7, compute); v["days"] != 7 || runs.Load() != 2 {
		t.Fatalf("7 days: %v, %d counts", v, runs.Load())
	}
	// Stale: the kept answer at once, the new one on the next open.
	e := c.entry(30)
	c.mu.Lock()
	e.at = time.Now().Add(-dashFresh - time.Second)
	c.mu.Unlock()
	start := time.Now()
	if v := c.get(30, compute); v["run"] != int32(1) || time.Since(start) > 10*time.Millisecond {
		t.Fatalf("stale answer not served at once: %v after %v", v, time.Since(start))
	}
	for i := 0; i < 100 && c.get(30, compute)["run"] == int32(1); i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if v := c.get(30, compute); v["run"] != int32(3) || runs.Load() != 3 {
		t.Fatalf("refresh: %v, %d counts", v, runs.Load())
	}
	// The warm loop's count is used by the next open.
	c.refresh(30, compute)
	if v := c.get(30, compute); v["run"] != int32(4) {
		t.Fatalf("warmed: %v", v)
	}
}

// The real dashboard says when it was counted, and its all-time totals
// come from the server card without going below the windows.
func TestDashboardUpdatedAt(t *testing.T) {
	a := newTestAgent(t, `{"firewall":{"enabled":false}}`)
	a.summary.get(a.heavySummary) // card counted before the findings below
	now := store.Now()
	a.DB.Exec(`INSERT INTO findings (source, path, owner, category, signature, status, created_at, updated_at) VALUES ('manual','/home/a/x','alice','virus','X','detected',?,?)`, now-10, now-10)
	d := a.Dashboard(30)
	if at, _ := d["updated_at"].(int64); at < now-5 {
		t.Fatalf("updated_at %v", d["updated_at"])
	}
	if th := d["threats"].(periodCount); th.Current != 1 || th.Overall != 1 {
		t.Fatalf("threats %+v", th)
	}
	if d2 := a.Dashboard(99); d2["days"] != 30 {
		t.Fatalf("unknown period %v", d2["days"])
	}
}

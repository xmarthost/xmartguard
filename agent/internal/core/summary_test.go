package core

import (
	"sync/atomic"
	"testing"
	"time"
)

// Audit A1 F10: the table counts behind the metrics summary run once per
// summaryEvery, not on every (5-second) sample, and are refreshed in the
// background when stale.
func TestSummaryCountsCached(t *testing.T) {
	var c summaryCache
	var runs atomic.Int32
	compute := func() heavySummary { runs.Add(1); return heavySummary{listed: int(runs.Load())} }
	for i := 0; i < 20; i++ {
		if v := c.get(compute); v.listed != 1 {
			t.Fatalf("sample %d: %+v", i, v)
		}
	}
	if runs.Load() != 1 {
		t.Fatalf("%d computations for 20 samples", runs.Load())
	}
	c.mu.Lock()
	c.at = time.Now().Add(-summaryEvery - time.Second)
	c.mu.Unlock()
	if v := c.get(compute); v.listed != 1 {
		t.Fatal("stale value not served while refreshing")
	}
	for i := 0; i < 100 && c.get(compute).listed != 2; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if runs.Load() != 2 {
		t.Fatalf("refresh: %d computations", runs.Load())
	}
	// The real summary still answers.
	a := newTestAgent(t, `{"firewall":{"enabled":false}}`)
	if m, ok := a.SecuritySummary().(map[string]any); !ok || m["card"] == nil {
		t.Fatalf("summary %v", a.SecuritySummary())
	}
}

package waf

import (
	"testing"

	"github.com/xmarthost/xmartguard/agent/internal/store"
)

// Audit A1 F16/F17: the WAF log keeps 32 days (the monthly report on the
// 1st reads the whole last month) and is pruned every 512th insert, not on
// every one.
func TestRecordPrunesEvery512th(t *testing.T) {
	m := learnManager(t)
	now := store.Now()
	count := func() (n int) {
		m.DB.QueryRow(`SELECT count(*) FROM waf_events WHERE at < ?`, now-86400).Scan(&n)
		return
	}
	m.record(Event{At: now - 31*86400, IP: "198.51.100.1", Msg: "last month"})
	m.record(Event{At: now - 40*86400, IP: "198.51.100.1", Msg: "too old"})
	m.record(Event{At: now, IP: "198.51.100.1", Msg: "x"})
	if n := count(); n != 2 {
		t.Fatalf("%d old events left after 3 inserts, want 2 (no prune yet)", n)
	}
	for i := 3; i < 512; i++ {
		m.record(Event{At: now, IP: "198.51.100.1", Msg: "x"})
	}
	if n := count(); n != 1 {
		t.Fatalf("%d old events after the 512th insert, want the 31-day one", n)
	}
}

func TestSpikes(t *testing.T) {
	m := learnManager(t)
	now := store.Now()
	add := func(rule, n int, at int64, action string) {
		for i := 0; i < n; i++ {
			m.record(Event{At: at, IP: "198.51.100.1", Host: "a.example", RuleID: rule, Msg: "x", Action: action})
		}
	}
	add(7700100, 250, now-60, "Access denied with code 403") // new spike
	add(7700200, 250, now-60, "Access denied with code 403") // busy every hour: usual
	add(7700200, 7*24*30, now-86400, "Access denied with code 403")
	add(7700300, 50, now-60, "Access denied with code 403") // too few
	add(7700400, 300, now-60, "Logged")                     // watching: not a block
	got := m.Spikes()
	if len(got) != 1 || got[0].RuleID != 7700100 || got[0].LastHour != 250 {
		t.Fatalf("spikes %+v", got)
	}
}

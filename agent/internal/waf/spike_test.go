package waf

import (
	"testing"

	"github.com/xmarthost/xmartguard/agent/internal/store"
)

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

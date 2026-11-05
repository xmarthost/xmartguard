package scanner

import (
	"testing"
	"time"
)

// business500 and s1 (2026-11-05): a daily scan cut short by the agent's
// restart left that day's changed files to no scheduled scan; the next
// daily only looked one day back. It now starts at the last finished one.
func TestDailyScanCoversAnInterruptedDay(t *testing.T) {
	s := newScanner(t)
	now := time.Now()
	add := func(kind, status string, ago time.Duration) {
		if _, err := s.DB.Exec(`INSERT INTO scans (kind, target, status, initiator, started_at) VALUES (?,?,?,?,?)`,
			kind, "x", status, "scheduler", now.Add(-ago).Unix()); err != nil {
			t.Fatal(err)
		}
	}
	// No finished scan yet: one day.
	if since, days := s.sweepSince("daily", now); days != 1 || now.Sub(since) != 24*time.Hour {
		t.Fatalf("first: %v %d", since, days)
	}
	add("daily", "completed", 49*time.Hour)
	add("daily", "failed", 25*time.Hour) // interrupted by a restart
	since, days := s.sweepSince("daily", now)
	if d := now.Sub(since); days != 3 || d < 49*time.Hour || d > 49*time.Hour+time.Second {
		t.Fatalf("after an interrupted scan: %v (%d days)", now.Sub(since), days)
	}
	// Never more than a week back.
	if _, err := s.DB.Exec(`DELETE FROM scans`); err != nil {
		t.Fatal(err)
	}
	add("full", "completed", 30*24*time.Hour)
	if since, days := s.sweepSince("daily", now); days != 7 || now.Sub(since) > 7*24*time.Hour+time.Second {
		t.Fatalf("capped: %v %d", now.Sub(since), days)
	}
	// A recent finished scan: the usual day.
	add("daily", "completed", 2*time.Hour)
	if _, days := s.sweepSince("daily", now); days != 1 {
		t.Fatalf("recent: %d", days)
	}
}

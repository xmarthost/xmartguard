package mail

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func fakeCPanelUsers(t *testing.T, users ...string) {
	t.Helper()
	dir := t.TempDir()
	for _, u := range users {
		os.WriteFile(filepath.Join(dir, u), []byte("USER="+u+"\n"), 0o600)
	}
	old := CPanelUsersDir
	CPanelUsersDir = dir
	t.Cleanup(func() { CPanelUsersDir = old })
}

// A script in account A that sends with -f x@b.example is held as A, not
// as the account that owns b.example (A5 F5).
func TestOSMLocalScriptAccountFromU(t *testing.T) {
	fakeCPanelUsers(t, "usera", "userb")
	m, calls := newMonitor(t)
	m.Owner = func(s string) string { return "userb" } // b.example belongs to userb
	m.Settings.Patch([]byte(`{"osm":{"per_minute":5,"per_hour":100,"action":"hold"}}`))
	base := time.Date(2026, 9, 24, 16, 0, 0, 0, time.Local)
	for i := 0; i < 5; i++ {
		m.Observe(Message{At: base.Add(time.Duration(i) * time.Second), ID: fmt.Sprint("1x-", i), Sender: "x@b.example", LocalU: "usera"})
	}
	evs, _, _ := m.Events(EventFilter{})
	if len(evs) != 1 || evs[0].User != "usera" {
		t.Fatalf("%+v", evs)
	}
	if len(*calls) != 1 || (*calls)[0] != "hold_outgoing_email user=usera" {
		t.Fatalf("calls %v", *calls)
	}
	// The summary shows the account the script ran as, too.
	for _, s := range m.Summary(10).Top {
		if s.User != "usera" {
			t.Fatalf("summary %+v", s)
		}
	}
}

// Rotating the envelope sender does not evade the per-minute limit of an
// account (A5 F6).
func TestOSMRotatingSendersCounted(t *testing.T) {
	fakeCPanelUsers(t, "usera")
	m, _ := newMonitor(t)
	m.Settings.Patch([]byte(`{"osm":{"per_minute":50,"per_hour":1000}}`))
	base := time.Date(2026, 9, 24, 16, 0, 0, 0, time.Local)
	for i := 0; i < 60; i++ {
		m.Observe(Message{At: base.Add(time.Duration(i) * 500 * time.Millisecond), ID: fmt.Sprint("1x-", i),
			Sender: fmt.Sprintf("r%d@random%d.example", i, i), LocalU: "usera"})
	}
	evs, _, _ := m.Events(EventFilter{})
	if len(evs) != 1 || evs[0].Interval != "50/m" {
		t.Fatalf("%+v", evs)
	}
	// System users stay counted per sender (their scripts are not one account).
	m2, _ := newMonitor(t)
	m2.Settings.Patch([]byte(`{"osm":{"per_minute":50,"per_hour":1000}}`))
	for i := 0; i < 60; i++ {
		m2.Observe(Message{At: base.Add(time.Duration(i) * 500 * time.Millisecond), ID: fmt.Sprint("1x-", i),
			Sender: fmt.Sprintf("r%d@site%d.example", i, i), LocalU: "nobody"})
	}
	if _, total, _ := m2.Events(EventFilter{}); total != 0 {
		t.Fatalf("nobody's senders were counted together: %d", total)
	}
}

// Counters of senders that went quiet are forgotten, and "recipients in
// the last 24 hours" only counts the last 24 hours (A5 F17).
func TestOSMCountersPruned(t *testing.T) {
	m, _ := newMonitor(t)
	m.Settings.Patch([]byte(`{"osm":{"per_minute":1000,"per_hour":100000}}`))
	base := time.Now().Add(-30 * time.Hour)
	for i := 0; i < 600; i++ {
		m.Observe(Message{At: base, ID: fmt.Sprint("1x-", i), Sender: fmt.Sprintf("s%d@x.example", i), Auth: fmt.Sprintf("s%d@x.example", i), Rcpts: 3})
	}
	m.Observe(Message{At: base.Add(2 * time.Hour), ID: "late", Sender: "s0@x.example", Auth: "s0@x.example", Rcpts: 3})
	m.mu.Lock()
	m.pruneLimits(base.Add(2 * time.Hour))
	n := len(m.counts)
	m.mu.Unlock()
	if n != 1 {
		t.Fatalf("%d counters kept", n)
	}
	// One sender: messages 30 h ago and now; only today's recipients count.
	m.Observe(Message{At: time.Now(), ID: "now", Sender: "s0@x.example", Auth: "s0@x.example", Rcpts: 2})
	for _, s := range m.Summary(10).Top {
		if s.Sender == "s0@x.example" && s.Rcpts != 2 {
			t.Fatalf("rcpts %d", s.Rcpts)
		}
	}
}

package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

// A quarantined file written again and again (a dropper every few seconds)
// stays one finding with a count, is removed each time, and alerts once.
func TestReinfectionCounted(t *testing.T) {
	s := newScanner(t)
	if _, err := s.Settings.Patch([]byte(`{"scanner":{"virus_action":"quarantine"}}`)); err != nil {
		t.Fatal(err)
	}
	alerts := 0
	s.OnReinfection = func(f Finding) { alerts++ }
	findings := 0
	s.OnFinding = func(Finding) { findings++ }
	dir := t.TempDir()
	p := filepath.Join(dir, "mu-plugins", "login-session.php")
	os.MkdirAll(filepath.Dir(p), 0o755)
	for i := 0; i < 5; i++ {
		os.WriteFile(p, []byte(malicious["eval.php"]), 0o644)
		s.ScanFile(p)
		if _, err := os.Stat(p); err == nil {
			t.Fatalf("round %d: file still on disk", i)
		}
	}
	list, n, _ := s.ListFindings(FindingFilter{Limit: 10})
	if n != 1 || list[0].Repeats != 4 || list[0].Status != "quarantined" {
		t.Fatalf("want one quarantined finding with 4 returns, got %d: %+v", n, list)
	}
	if findings != 1 || alerts != 1 {
		t.Fatalf("notifications %d, reinfection alerts %d", findings, alerts)
	}
	// Different content at the same path is a new finding.
	os.WriteFile(p, []byte(malicious["exec.php"]), 0o644)
	s.ScanFile(p)
	if _, n, _ := s.ListFindings(FindingFilter{Limit: 10}); n != 2 {
		t.Fatalf("new content: %d findings", n)
	}
}

// A file that comes back is the latest activity: with Recent it is listed
// first, above findings recorded after it.
func TestRecentListsReturnsFirst(t *testing.T) {
	s := newScanner(t)
	if _, err := s.Settings.Patch([]byte(`{"scanner":{"virus_action":"quarantine"}}`)); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	old := filepath.Join(dir, "old.php")
	os.WriteFile(old, []byte(malicious["eval.php"]), 0o644)
	s.ScanFile(old)
	_, _ = s.DB.Exec(`UPDATE findings SET created_at = created_at - 3600, updated_at = updated_at - 3600`)
	other := filepath.Join(dir, "other.php")
	os.WriteFile(other, []byte(malicious["exec.php"]), 0o644)
	s.ScanFile(other)
	_, _ = s.DB.Exec(`UPDATE findings SET updated_at = updated_at - 60 WHERE path = ?`, other)
	// old.php is written again.
	os.WriteFile(old, []byte(malicious["eval.php"]), 0o644)
	s.ScanFile(old)
	list, _, _ := s.ListFindings(FindingFilter{Limit: 10, Recent: true})
	if len(list) != 2 || list[0].Path != old || list[0].Repeats != 1 {
		t.Fatalf("recent order: %+v", list)
	}
	if list, _, _ := s.ListFindings(FindingFilter{Limit: 10}); list[0].Path != other {
		t.Fatalf("default order changed: %+v", list)
	}
}

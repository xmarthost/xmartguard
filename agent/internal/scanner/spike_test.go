package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// A signature that quarantines too many files at once is paused: the rest
// only wait, an alert goes out, and bulk actions finish the job either way.
func TestSpikePausesSignatureAndBulkActions(t *testing.T) {
	old := SpikeLimit
	SpikeLimit = 3
	t.Cleanup(func() { SpikeLimit = old })
	s := newScanner(t)
	if _, err := s.Settings.Patch([]byte(`{"scanner":{"virus_action":"quarantine"}}`)); err != nil {
		t.Fatal(err)
	}
	var paused []string
	s.OnSignaturePaused = func(sig string, n int) { paused = append(paused, sig) }
	dir := t.TempDir()
	for i := 0; i < 5; i++ {
		p := filepath.Join(dir, fmt.Sprintf("site%d", i), "exec.php")
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(malicious["exec.php"]+fmt.Sprintf("\n// %d", i)), 0o644)
		s.ScanFile(p)
	}
	list, _, _ := s.ListFindings(FindingFilter{Limit: 10})
	q, waiting := 0, 0
	sig := ""
	for _, f := range list {
		sig = f.Signature
		switch {
		case f.Status == "quarantined":
			q++
		case f.Status == "detected" && f.Note == NotePaused:
			waiting++
		}
	}
	if q != 3 || waiting != 2 || len(paused) != 1 {
		t.Fatalf("quarantined %d, waiting %d, alerts %v: %+v", q, waiting, paused, list)
	}
	if p := s.Paused(); len(p) != 1 || p[0].Files != 2 {
		t.Fatalf("paused: %+v", p)
	}
	// Bulk quarantine of what waits.
	f := BulkFilter{Signature: sig, Action: "quarantine"}
	if n, sample, err := s.BulkPreview(f, 10); err != nil || n != 2 || len(sample) != 2 {
		t.Fatalf("preview %d %d %v", n, len(sample), err)
	}
	if r, err := s.BulkApply(f, nil); err != nil || r.Done != 2 {
		t.Fatalf("bulk quarantine %+v %v", r, err)
	}
	s.Unpause(sig)
	if len(s.Paused()) != 0 {
		t.Fatal("still paused")
	}
	// Bulk restore by time window: nothing before, all five in it.
	if n, _, _ := s.BulkPreview(BulkFilter{Signature: sig, Action: "restore", To: 1}, 10); n != 0 {
		t.Fatalf("restore before the window: %d", n)
	}
	r, err := s.BulkApply(BulkFilter{Signature: sig, Action: "restore", From: 1}, nil)
	if err != nil || r.Done != 5 {
		t.Fatalf("bulk restore %+v %v", r, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "site4", "exec.php")); err != nil {
		t.Fatal("file not restored")
	}
	if _, err := s.BulkApply(BulkFilter{Action: "restore"}, nil); err == nil {
		t.Fatal("bulk without a signature")
	}
}

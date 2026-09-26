package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestApplyCuts(t *testing.T) {
	src := []byte("a\nBAD1\nb\nc BAD2 d\ne\n")
	out, n, err := ApplyCuts(src, []Cut{{From: 2, To: 2}, {From: 4, To: 4, Text: " BAD2"}})
	if err != nil || string(out) != "a\nb\nc d\ne\n" || n != 10 {
		t.Fatalf("%q %d %v", out, n, err)
	}
	for _, bad := range [][]Cut{{{From: 0, To: 1}}, {{From: 5, To: 9}}, {{From: 1, To: 3}, {From: 2, To: 2}}, {{From: 4, To: 4, Text: "nope"}}, nil} {
		if _, _, err := ApplyCuts(src, bad); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
}

func TestTrimKeepsSiteRunning(t *testing.T) {
	s := newScanner(t)
	dir := t.TempDir()
	legit := "<?php\nfunction hello() { return esc_html(get_option('x')); }\n" + strings.Repeat("// plugin code line\n", 60)
	infected := malicious["eval.php"] + "\n" + legit
	p := filepath.Join(dir, "plugin.php")
	os.WriteFile(p, []byte(infected), 0o640)
	info, _ := os.Lstat(p)
	d, _ := s.CheckFile(p, info, s.Settings.Get().Scanner)
	if d == nil {
		t.Fatal("infected file not detected")
	}
	f, err := s.Record(0, "manual", p, info, *d)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Quarantine(f.ID); err != nil {
		t.Fatal(err)
	}
	// Too much removed: refused, nothing changes.
	if err := s.Trim(f.ID, []Cut{{From: 3, To: 40}}, 20); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("large trim: %v", err)
	}
	// Removing the wrong line leaves malware: refused.
	if err := s.Trim(f.ID, []Cut{{From: 3, To: 3}}, 20); err == nil || !strings.Contains(err.Error(), "still detects") {
		t.Fatalf("wrong trim: %v", err)
	}
	if err := s.Trim(f.ID, []Cut{{From: 1, To: 1}}, 20); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(p)
	if string(got) != legit {
		t.Fatalf("trimmed content: %q", got[:40])
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o640 {
		t.Fatalf("mode %v", st.Mode())
	}
	g, _ := s.Get(f.ID)
	if g.Status != "trimmed" {
		t.Fatalf("status %s", g.Status)
	}
	orig, _, err := s.Content(f.ID, 1<<20)
	if err != nil || string(orig) != infected {
		t.Fatalf("original not kept: %v", err)
	}
	// Restore puts the original back.
	if err := s.Restore(f.ID); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(p); string(got) != infected {
		t.Fatal("original not restored")
	}
}

func TestTrimKeepsOwnPHPTag(t *testing.T) {
	s := newScanner(t)
	dir := t.TempDir()
	legit := "\n/** plugin */\nfunction hello() { return esc_html(get_option('x')); }\n" + strings.Repeat("// plugin code line\n", 60)
	infected := malicious["eval.php"] + "<?php" + legit
	p := filepath.Join(dir, "submit.php")
	os.WriteFile(p, []byte(infected), 0o644)
	info, _ := os.Lstat(p)
	d, _ := s.CheckFile(p, info, s.Settings.Get().Scanner)
	f, err := s.Record(0, "manual", p, info, *d)
	if err != nil {
		t.Fatal(err)
	}
	// The AI asked for the whole first line; only the injected block goes.
	if err := s.Trim(f.ID, []Cut{{From: 1, To: 1}}, 20); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(p); string(got) != "<?php"+legit {
		t.Fatalf("trimmed: %q", got[:30])
	}
	if _, err := refineCuts([]byte("<?php\nfoo();\n"), []Cut{{From: 1, To: 1}}); err == nil {
		t.Fatal("cut of the only open tag accepted")
	}
}

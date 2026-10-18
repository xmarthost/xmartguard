package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

// A dropper writes tempnam() files and renames them: the scanner catches the
// temporary name, which is gone a moment later. Such findings are closed,
// not left open as if they waited for an action.
func TestVanishedFilesAreClosed(t *testing.T) {
	s := newScanner(t)
	dir := t.TempDir()
	kept := filepath.Join(dir, "kept.php")
	os.WriteFile(kept, []byte("<?php"), 0o644)
	for i, p := range []string{kept, filepath.Join(dir, "scpChAqqx")} {
		if _, err := s.DB.Exec(`INSERT INTO findings (id, source, path, owner, category, signature, status, created_at, updated_at) VALUES (?, 'realtime', ?, 'u', 'virus', 'PHP.Test', 'detected', 1, 1)`, i+1, p); err != nil {
			t.Fatal(err)
		}
	}
	n, err := s.CloseVanished()
	if err != nil || n != 1 {
		t.Fatalf("closed %d, err %v", n, err)
	}
	var st1, st2, note string
	s.DB.QueryRow(`SELECT status FROM findings WHERE id = 1`).Scan(&st1)
	s.DB.QueryRow(`SELECT status, note FROM findings WHERE id = 2`).Scan(&st2, &note)
	if st1 != "detected" || st2 != "deleted" || note != NoteGone {
		t.Fatalf("kept %q, vanished %q (%q)", st1, st2, note)
	}
}

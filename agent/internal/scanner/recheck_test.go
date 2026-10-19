package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// Quarantined copies are judged again by the current engine: the empty
// cPanel prepend setting is released, a real loader and an AI verdict of
// malicious are kept, and paging walks to older findings.
func TestRecheckQuarantine(t *testing.T) {
	s := newScanner(t)
	dir := t.TempDir()
	files := []struct{ path, content string }{
		{"/home/u/public_html/.user.ini", "auto_prepend_file = \"\"\n"},
		{"/home/u/public_html/php.ini", "auto_prepend_file = '/home/u/.cache/.p'\n"},
		{"/home/u/public_html/kept-by-ai.ini", "auto_prepend_file = \"\"\nmemory_limit = 1G\n"},
	}
	for i, f := range files {
		q := filepath.Join(dir, filepath.Base(f.path)+".q")
		os.WriteFile(q, []byte(f.content), 0o600)
		if _, err := s.DB.Exec(`INSERT INTO findings (id, source, path, owner, category, signature, status, qpath, created_at, updated_at) VALUES (?, 'manual', ?, 'u', 'suspicious', 'PHP.Config.AutoPrepend', 'quarantined', ?, 1, 1)`, i+1, f.path, q); err != nil {
			t.Fatal(err)
		}
	}
	sum := sha256.Sum256([]byte(files[2].content))
	keep := func(sha string) bool { return sha == hex.EncodeToString(sum[:]) }
	rep, err := s.Recheck(RecheckFilter{}, keep)
	if err != nil || rep.Checked != 3 || rep.Still != 2 || len(rep.Clean) != 1 || rep.Clean[0].ID != 1 {
		t.Fatalf("%+v %v", rep, err)
	}
	page, _ := s.Recheck(RecheckFilter{Limit: 2}, keep)
	if page.Checked != 2 || page.NextBeforeID != 2 {
		t.Fatalf("first page %+v", page)
	}
	if rest, _ := s.Recheck(RecheckFilter{Limit: 2, BeforeID: page.NextBeforeID}, keep); rest.Checked != 1 || len(rest.Clean) != 1 || rest.NextBeforeID != 0 {
		t.Fatalf("second page %+v", rest)
	}
	if only, _ := s.Recheck(RecheckFilter{IDs: []int64{2}}, keep); only.Checked != 1 || len(only.Clean) != 0 {
		t.Fatalf("by id %+v", only)
	}
}

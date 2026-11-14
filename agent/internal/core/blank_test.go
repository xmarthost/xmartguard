package core

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/ai"
	"github.com/xmarthost/xmartguard/agent/internal/store"
)

// 2026-11-14 (business700): the fleet knowledge base held "malicious" for
// the hash of empty content, and every empty index.html of every server was
// flagged XG.AI.Malicious (291 on one server). A blank file runs no code: no
// verdict for it is kept or acted on, and the old detections are undone.
func TestBlankFileNeverAIMalicious(t *testing.T) {
	a := newTestAgent(t, `{"ai":{"enabled":false,"act":true},"scanner":{"virus_action":"quarantine"}}`)
	dir := filepath.Join(t.TempDir(), "public_html", "wp-content", "plugins", "x")
	os.MkdirAll(dir, 0o755)
	empty := filepath.Join(dir, "index.html")
	space := filepath.Join(dir, "index.php")
	code := filepath.Join(dir, "real.php")
	os.WriteFile(empty, nil, 0o644)
	os.WriteFile(space, []byte("\xef\xbb\xbf \n\t\n"), 0o644)
	os.WriteFile(code, []byte("<?php echo 'inert fixture';"), 0o644)

	// A wrong fleet verdict for empty content is not kept.
	ai.Save(a.DB, ai.Verdict{SHA256: ai.EmptySHA, Verdict: ai.Malicious, Confidence: 95, Source: "fleet", Model: "x", At: store.Now()})
	if _, ok := ai.Cached(a.DB, ai.EmptySHA); ok {
		t.Fatal("verdict for empty content kept")
	}
	// Nor acted on: no new finding for a blank file.
	for _, p := range []string{empty, space} {
		a.onAIVerdict(ai.Job{Path: p}, ai.Verdict{SHA256: ai.EmptySHA, Verdict: ai.Malicious, Confidence: 95})
	}
	var n int
	a.DB.QueryRow(`SELECT count(*) FROM findings`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d findings for blank files", n)
	}
	if !ai.BlankFile(empty) || !ai.BlankFile(space) || ai.BlankFile(code) {
		t.Fatal("BlankFile wrong")
	}

	// Detections from before the fix: the blank ones are undone, a real
	// file's stays.
	now := time.Now().Unix()
	for _, p := range []string{empty, code} {
		info, _ := os.Stat(p)
		a.DB.Exec(`INSERT INTO findings (source, path, owner, category, signature, status, sha256, size, created_at, updated_at) VALUES ('ai',?,'u','virus','XG.AI.Malicious','detected',?,?,?,?)`,
			p, map[bool]string{true: ai.EmptySHA, false: "ab"}[p == empty], info.Size(), now, now)
	}
	if got := a.clearBlankAI(); got != 1 {
		t.Fatalf("cleared %d, want 1", got)
	}
	var st string
	a.DB.QueryRow(`SELECT status FROM findings WHERE path = ?`, code).Scan(&st)
	if st != "detected" {
		t.Fatalf("real file's detection: %s", st)
	}
	a.DB.QueryRow(`SELECT status FROM findings WHERE path = ?`, empty).Scan(&st)
	if st == "detected" {
		t.Fatal("blank file still detected")
	}
}

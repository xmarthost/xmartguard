package core

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/ai"
	"github.com/xmarthost/xmartguard/agent/internal/scanner"
)

// Audit A1 F13: an administrator's "clear" stands even for a signature whose
// AI "clean" verdicts are not trusted (before, only "restore" did).
func TestAdminClearStandsForUntrustedSignature(t *testing.T) {
	a := newTestAgent(t, `{"ai":{"enabled":false}}`)
	file := filepath.Join(t.TempDir(), "x.php")
	os.WriteFile(file, []byte("<?php echo 'inert fixture';"), 0o644)
	sha := "ab" + strings.Repeat("0", 62)
	now := time.Now().Unix()
	a.DB.Exec(`INSERT INTO findings (source, path, owner, category, signature, status, sha256, created_at, updated_at) VALUES ('manual',?,'u','virus','PHP.Obfuscated.CompressedPayload','detected',?,?,?)`, file, sha, now, now)
	if ai.IsCleared(a.DB, sha) {
		t.Fatal("cleared before")
	}
	if _, err := a.Handlers()["finding.action"](context.Background(), []byte(`{"ids":[1],"action":"clear"}`)); err != nil {
		t.Fatal(err)
	}
	if !ai.IsCleared(a.DB, sha) || !ai.AdminCleared(a.DB, sha) {
		t.Fatal("administrator's clear not honoured")
	}
	if v, ok := ai.Cached(a.DB, sha); !ok || v.Source != ai.SourceAdmin {
		t.Fatalf("verdict %+v", v)
	}
}

// A file an administrator restores is not flagged again while unchanged;
// if its content changes it is scanned (and flagged) again.
func TestRestoredFileIsNotFlaggedAgain(t *testing.T) {
	a := newTestAgent(t, `{"scanner":{"virus_action":"quarantine"},"ai":{"enabled":false}}`)
	dir := filepath.Join(t.TempDir(), "public_html")
	os.MkdirAll(dir, 0o755)
	file := filepath.Join(dir, "x.php")
	body := "<?php @eval($_POST['a']); ?>"
	os.WriteFile(file, []byte(body), 0o644)

	scan := func() []scanner.Finding {
		id, err := a.Scanner.Start("path", dir, "test")
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 3000; i++ { // up to a minute on a busy machine
			scans, _ := a.Scanner.ListScans(1)
			if len(scans) > 0 && scans[0].ID == id && scans[0].Status == "completed" {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		fs, _, _ := a.Scanner.ListFindings(scanner.FindingFilter{ScanID: id, Limit: 10})
		return fs
	}
	fs := scan()
	if len(fs) != 1 || fs[0].Status != "quarantined" {
		t.Fatalf("first scan: %+v", fs)
	}
	h := a.Handlers()
	if _, err := h["finding.action"](context.Background(), []byte(fmt.Sprintf(`{"ids":[%d],"action":"restore"}`, fs[0].ID))); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(file); err != nil {
		t.Fatal("not restored")
	}
	if fs := scan(); len(fs) != 0 {
		t.Fatalf("restored file flagged again: %+v", fs)
	}
	// Changed content is scanned again.
	os.WriteFile(file, []byte(body+"\n<?php @eval($_GET['b']); ?>"), 0o644)
	if fs := scan(); len(fs) != 1 {
		t.Fatalf("changed file not flagged: %+v", fs)
	}
}

// A quarantined file the AI finds clean (≥90%) is put back at once, shows as
// restored by AI, and is not flagged again while unchanged.
func TestAICleanRestoresAtOnce(t *testing.T) {
	a := newTestAgent(t, `{"scanner":{"virus_action":"quarantine"},"ai":{"enabled":false,"restore_clean":true}}`)
	dir := filepath.Join(t.TempDir(), "public_html")
	os.MkdirAll(dir, 0o755)
	file := filepath.Join(dir, "theme-functions.php")
	os.WriteFile(file, []byte("<?php @eval($_POST['a']); ?>"), 0o644)
	id, _ := a.Scanner.Start("path", dir, "test")
	var fs []scanner.Finding
	for i := 0; i < 200 && len(fs) == 0; i++ {
		time.Sleep(20 * time.Millisecond)
		fs, _, _ = a.Scanner.ListFindings(scanner.FindingFilter{ScanID: id, Status: "quarantined", Limit: 10})
	}
	if len(fs) != 1 {
		t.Fatalf("not quarantined: %+v", fs)
	}
	f := fs[0]
	v := ai.Verdict{SHA256: f.SHA256, Verdict: ai.Clean, Confidence: 100, Reason: "plugin helpers", Model: "gemini", Source: "ai", At: 1}
	ai.Save(a.DB, v)
	a.onAIVerdict(ai.Job{FindingID: f.ID, SHA256: f.SHA256}, v)
	got, _ := a.Scanner.Get(f.ID)
	if got.Status != scanner.StatusAIRestored {
		t.Fatalf("status %q", got.Status)
	}
	if _, err := os.Stat(file); err != nil {
		t.Fatal("file not back at its location")
	}
	id2, _ := a.Scanner.Start("path", dir, "test")
	for i := 0; i < 3000; i++ { // up to a minute on a busy machine
		scans, _ := a.Scanner.ListScans(1)
		if len(scans) > 0 && scans[0].ID == id2 && scans[0].Status == "completed" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if again, _, _ := a.Scanner.ListFindings(scanner.FindingFilter{ScanID: id2, Limit: 10}); len(again) != 0 {
		t.Fatalf("flagged again: %+v", again)
	}
}

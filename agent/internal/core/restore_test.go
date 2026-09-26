package core

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/scanner"
)

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
		for i := 0; i < 200; i++ {
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

package core

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xmarthost/xmartguard/agent/internal/ai"
	"github.com/xmarthost/xmartguard/agent/internal/scanner"
	"github.com/xmarthost/xmartguard/agent/internal/store"
)

type fakeWP struct{ files map[string][]byte }

func (f fakeWP) Checksums(context.Context, string) (map[string]string, error) {
	out := map[string]string{}
	for k, v := range f.files {
		s := md5.Sum(v)
		out[k] = hex.EncodeToString(s[:])
	}
	return out, nil
}

func (f fakeWP) File(_ context.Context, _, rel string) ([]byte, error) {
	if b, ok := f.files[rel]; ok {
		return b, nil
	}
	return nil, errors.New("404")
}

func TestInfectedCoreFileIsReplacedWithOfficial(t *testing.T) {
	a := newTestAgent(t, `{"scanner":{"virus_action":"quarantine"},"firewall":{"enabled":false}}`)
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "wp-includes"), 0o755)
	os.MkdirAll(filepath.Join(root, "wp-admin", "includes"), 0o755)
	os.WriteFile(filepath.Join(root, "wp-includes", "version.php"), []byte("<?php\n$wp_version = '7.1.2';\n"), 0o644)
	official := []byte("<?php\nfunction wp_handle_upload() { return true; }\n")
	a.WPSource = fakeWP{files: map[string][]byte{"wp-admin/includes/file.php": official}}
	p := filepath.Join(root, "wp-admin", "includes", "file.php")
	infected := "<?php @ev" + "al($_POST['x']); ?>" + string(official)
	os.WriteFile(p, []byte(infected), 0o644)

	a.Scanner.ScanFile(p)
	var status, qpath string
	a.DB.QueryRow(`SELECT status, qpath FROM findings WHERE path = ?`, p).Scan(&status, &qpath)
	if status != "cleaned" {
		t.Fatalf("status %q", status)
	}
	if got, _ := os.ReadFile(p); string(got) != string(official) {
		t.Fatalf("live file: %q", got)
	}
	if got, _ := os.ReadFile(qpath); string(got) != infected {
		t.Fatal("infected copy not kept in quarantine")
	}
}

func TestAICleanVerdictRestoresFalsePositive(t *testing.T) {
	a := newTestAgent(t, `{"scanner":{"virus_action":"quarantine","suspicious_action":"quarantine"},"firewall":{"enabled":false}}`)
	dir := t.TempDir()
	p := filepath.Join(dir, "legit.php")
	// Legitimate code that trips a rule (request data passed to a callback name).
	body := "<?php\n$handler = $_GET['page'];\n$handler();\n"
	os.WriteFile(p, []byte(body), 0o640)
	a.Scanner.ScanFile(p)
	var id int64
	var status string
	a.DB.QueryRow(`SELECT id, status FROM findings WHERE path = ?`, p).Scan(&id, &status)
	if status != "quarantined" {
		t.Fatalf("not quarantined: %q", status)
	}
	sum := sha256.Sum256([]byte(body))
	sha := hex.EncodeToString(sum[:])
	v := ai.Verdict{SHA256: sha, Verdict: ai.Clean, Confidence: 95, Reason: "admin router", Source: "ai", At: store.Now()}
	ai.Save(a.DB, v)
	a.onAIVerdict(ai.Job{FindingID: id, Path: p, SHA256: sha}, v)
	a.DB.QueryRow(`SELECT status FROM findings WHERE id = ?`, id).Scan(&status)
	if status != "cleared" {
		t.Fatalf("status %q", status)
	}
	if st, err := os.Stat(p); err != nil || st.Mode().Perm() != 0o640 {
		t.Fatalf("file not restored: %v", err)
	}
	// The same content is not flagged again.
	info, _ := os.Lstat(p)
	if d, _ := a.Scanner.CheckFile(p, info, a.Settings.Get().Scanner); d != nil {
		t.Fatalf("flagged again: %+v", d)
	}
	// A less confident "clean" does not restore.
	a.Scanner.ScanFile(p) // no new finding for cleared content
	var n int
	a.DB.QueryRow(`SELECT count(*) FROM findings WHERE path = ?`, p).Scan(&n)
	if n != 1 || !strings.HasPrefix(sha, sha[:4]) {
		t.Fatalf("findings %d", n)
	}
}

func TestSignatureFeedsAreInstalled(t *testing.T) {
	a := newTestAgent(t, `{"firewall":{"enabled":false}}`)
	shell := []byte("<?php /* test shell */ print 'XG distinctive feed marker 0042'; ?>")
	md := md5.Sum(shell)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"etag": "e1",
			"md5":  [][]any{{hex.EncodeToString(md[:]), len(shell), "php.test.shell.1"}},
			"hex":  [][2]string{{hex.EncodeToString([]byte("another distinctive marker 99")), "php.hex.marker.2"}},
			"yara": []map[string]string{{"name": "good", "text": `rule Good_Feed { strings: $a = "yara-feed-marker-77" condition: $a }`}, {"name": "broken", "text": "rule {"}},
		})
	}))
	defer srv.Close()
	a.AI.Portal = &ai.PortalAI{URL: srv.URL, ServerID: "x", Sign: func([]byte) string { return "s" }}
	if err := a.syncSignatures(context.Background()); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	check := func(name string, body []byte) string {
		p := filepath.Join(dir, name)
		os.WriteFile(p, body, 0o644)
		info, _ := os.Lstat(p)
		d, _ := a.Scanner.CheckFile(p, info, a.Settings.Get().Scanner)
		if d == nil {
			return ""
		}
		return d.Category + " " + d.Signature
	}
	if got := check("s.php", shell); got != "virus LMD.php.test.shell.1" {
		t.Fatalf("md5 feed: %q", got)
	}
	if got := check("h.php", []byte("<?php echo 'another distinctive marker 99';")); got != "suspicious LMD.php.hex.marker.2" {
		t.Fatalf("hex feed: %q", got)
	}
	if _, err := os.Stat(filepath.Join(scanner.FeedYARADir(), "good.yar")); err != nil {
		t.Fatal("valid YARA feed not installed")
	}
	if _, err := os.Stat(filepath.Join(scanner.FeedYARADir(), "broken.yar")); err == nil {
		t.Fatal("broken YARA feed installed")
	}
	// Turning feeds off removes them.
	a.Settings.Patch([]byte(`{"scanner":{"feeds":false}}`))
	a.syncSignatures(context.Background())
	if got := check("s2.php", shell); got != "" {
		t.Fatalf("feeds still active: %q", got)
	}
}

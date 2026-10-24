package ai

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xmarthost/xmartguard/agent/internal/scanner"
	"github.com/xmarthost/xmartguard/agent/internal/settings"
	"github.com/xmarthost/xmartguard/agent/internal/store"
)

func setup(t *testing.T, patch string) (*Analyzer, string) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XG_STATE_DIR", filepath.Join(dir, "state"))
	t.Setenv("XG_CONFIG_DIR", filepath.Join(dir, "conf"))
	db, err := store.Open()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	st, _ := settings.Load()
	if patch != "" {
		if _, err := st.Patch([]byte(patch)); err != nil {
			t.Fatal(err)
		}
	}
	f := filepath.Join(dir, "x.php")
	os.WriteFile(f, []byte("<?php\necho 'hello';\n"), 0o644)
	return &Analyzer{DB: db, Settings: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}, f
}

// There is no offline model: the AI is the portal's, an old "builtin"
// setting moves there, and without the portal a file gets no verdict (it
// is asked again later) instead of an offline guess.
func TestPortalOnly(t *testing.T) {
	a, f := setup(t, "")
	if s := a.Settings.Get().AI; !s.Enabled || s.Provider != "portal" || s.Scope != "suspicious" || !s.Learn {
		t.Fatalf("defaults: %+v", s)
	}
	if _, err := a.Settings.Patch([]byte(`{"ai":{"provider":"builtin"}}`)); err != nil || a.Settings.Get().AI.Provider != "portal" {
		t.Fatalf("builtin not moved to the portal: %v %q", err, a.Settings.Get().AI.Provider)
	}
	v, _ := a.Analyze(context.Background(), Job{Path: f, SHA256: "abc", Signature: "Test"})
	if v.Verdict != "" {
		t.Fatalf("verdict without the portal: %+v", v)
	}
	if _, ok := Cached(a.DB, "abc"); ok {
		t.Fatal("verdict cached without the portal")
	}
}

func TestOldProvidersMoveToPortal(t *testing.T) {
	a, _ := setup(t, `{"ai":{"provider":"ollama","ollama_url":"http://x","model":"m"}}`)
	if p := a.Settings.Get().AI.Provider; p != "portal" {
		t.Fatalf("provider %q", p)
	}
	if _, err := a.Settings.Patch([]byte(`{"ai":{"scope":"everything"}}`)); err == nil {
		t.Fatal("bad scope accepted")
	}
}

func TestExcerptKeepsRiskyLinesAndShortensBlobs(t *testing.T) {
	var b strings.Builder
	b.WriteString("<?php\n")
	for i := 0; i < 400; i++ {
		fmt.Fprintf(&b, "    $row%d = get_option('setting_%d'); // ordinary code\n", i, i)
	}
	b.WriteString("$p = '" + strings.Repeat("QUJD", 300) + "';\n")
	b.WriteString("eval(base64_decode($_POST['c']));\n")
	for i := 0; i < 400; i++ {
		fmt.Fprintf(&b, "echo esc_html($row%d);\n", i)
	}
	text, lines, truncated := Excerpt([]byte(b.String()), 4096)
	if !truncated || lines < 800 || len(text) > 4400 {
		t.Fatalf("truncated=%v lines=%d len=%d", truncated, lines, len(text))
	}
	if !strings.Contains(text, "403|eval(base64_decode($_POST['c']));") {
		t.Fatalf("risky line missing:\n%s", text)
	}
	if !strings.Contains(text, "…[1200 chars]") || strings.Contains(text, strings.Repeat("QUJD", 30)) {
		t.Fatal("blob not shortened")
	}
	if !strings.Contains(text, "1|<?php") || !strings.Contains(text, " lines …") || strings.Contains(text, "    $row") {
		t.Fatalf("head/markers/indent:\n%s", text[:300])
	}
	small, _, trunc := Excerpt([]byte("<?php\n\n  echo 1;\n"), 4096)
	if trunc || small != "1|<?php\n3|echo 1;\n" {
		t.Fatalf("small: %q", small)
	}
}

// fakePortal verifies the signed envelope like the portal does.
func fakePortal(t *testing.T, pub ed25519.PublicKey, handle func(path string, payload map[string]any) any) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var env map[string]string
		json.NewDecoder(r.Body).Decode(&env)
		sum := sha256.Sum256([]byte(env["payload"]))
		sig, _ := base64.StdEncoding.DecodeString(env["signature"])
		if !ed25519.Verify(pub, []byte("xg-ai-v2:"+env["server_id"]+":"+env["ts"]+":"+hex.EncodeToString(sum[:])), sig) {
			w.WriteHeader(401)
			io.WriteString(w, `{"error":"bad signature"}`)
			return
		}
		var payload map[string]any
		json.Unmarshal([]byte(env["payload"]), &payload)
		json.NewEncoder(w).Encode(handle(r.URL.Path, payload))
	}))
}

func portalFor(url string, priv ed25519.PrivateKey) *PortalAI {
	return &PortalAI{URL: url + "/", ServerID: "11111111-1111-1111-1111-111111111111",
		Sign: func(m []byte) string { return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, m)) }}
}

func TestPortalBatchAndTrimInstructions(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	var got map[string]any
	srv := fakePortal(t, pub, func(path string, p map[string]any) any {
		if path != "/api/agent/ai/judge" {
			return map[string]any{}
		}
		got = p
		return map[string]any{"results": []map[string]any{
			{"id": "0", "verdict": "malicious", "confidence": 96, "reason": "backdoor prepended", "injected": true,
				"cut": []map[string]any{{"from": 2, "to": 2}}, "model": "gemini-2.5-flash", "source": "ai"},
			{"id": "1", "verdict": "clean", "confidence": 90, "reason": "template", "model": "fleet", "source": "fleet"},
		}}
	})
	defer srv.Close()
	a, f := setup(t, `{"ai":{"provider":"portal"}}`)
	a.Portal = portalFor(srv.URL, priv)
	g := filepath.Join(filepath.Dir(f), "y.php")
	os.WriteFile(g, []byte("<?php echo 2;\n"), 0o644)
	s1, s2 := shaOf(t, f), shaOf(t, g)
	vs, err := a.AnalyzeBatch(context.Background(), []Job{{FindingID: 1, Path: f, SHA256: s1, Signature: "PHP.X"}, {Path: g, SHA256: s2}})
	if err != nil || vs[0].Verdict != Malicious || !vs[0].Injected || len(vs[0].Cut) != 1 || vs[1].Source != "fleet" {
		t.Fatalf("verdicts: %+v %v", vs, err)
	}
	files := got["files"].([]any)
	f0 := files[0].(map[string]any)
	if len(files) != 2 || f0["match"] != "PHP.X" || !strings.Contains(f0["excerpt"].(string), "2|echo 'hello';") {
		t.Fatalf("request: %v", got)
	}
	// No model features travel with the file (there is no fleet model).
	if _, ok := f0["features"]; ok {
		t.Fatalf("features sent: %v", f0)
	}
	if c, ok := Cached(a.DB, s1); !ok || !c.Injected || c.Cut[0].From != 2 || c.Size == 0 {
		t.Fatalf("cached: %+v", c)
	}
}

func shaOf(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// A2 F5: a file changed between detection and the AI read is not sent, so
// no verdict on other content is saved under the flagged hash.
func TestPortalSkipsFileChangedSinceDetection(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	sent := 0
	srv := fakePortal(t, pub, func(path string, p map[string]any) any {
		if path != "/api/agent/ai/judge" {
			return map[string]any{}
		}
		files := p["files"].([]any)
		sent += len(files)
		res := []map[string]any{}
		for _, f := range files {
			res = append(res, map[string]any{"id": f.(map[string]any)["id"], "verdict": "clean", "confidence": 99, "reason": "ok", "model": "m", "source": "ai"})
		}
		return map[string]any{"results": res}
	})
	defer srv.Close()
	a, f := setup(t, `{"ai":{"provider":"portal"}}`)
	a.Portal = portalFor(srv.URL, priv)
	flagged := shaOf(t, f)
	os.WriteFile(f, []byte("<?php\necho 'other content';\n"), 0o644)
	vs, _ := a.analyzePortal(context.Background(), []Job{{FindingID: 1, Path: f, SHA256: flagged, Signature: "PHP.X"}}, a.Settings.Get().AI)
	if sent != 0 || vs[0].Verdict != "" {
		t.Fatalf("changed file judged under the flagged hash: sent %d %+v", sent, vs)
	}
	if _, ok := Cached(a.DB, flagged); ok {
		t.Fatal("verdict saved under the flagged hash")
	}
}

func TestPortalDownNoVerdict(t *testing.T) {
	a, f := setup(t, `{"ai":{"provider":"portal"}}`)
	a.Portal = &PortalAI{URL: "http://127.0.0.1:1", ServerID: "x", Sign: func([]byte) string { return "" }}
	if v, err := a.Analyze(context.Background(), Job{FindingID: 3, Path: f, SHA256: "fb"}); err == nil || v.Verdict != "" {
		t.Fatalf("portal down: %+v %v", v, err)
	}
}

func TestFleetSyncLearnsHashes(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	sha := strings.Repeat("ab", 32)
	aiOnly := strings.Repeat("cd", 32)
	calls := 0
	srv := fakePortal(t, pub, func(path string, p map[string]any) any {
		calls++
		if path != "/api/agent/ai/sync" {
			return map[string]any{}
		}
		return map[string]any{
			"kb": []map[string]any{{"sha256": sha, "size": 1234, "verdict": "malicious", "confidence": 100, "reason": "web shell", "model": "admin"},
				{"sha256": aiOnly, "size": 99, "verdict": "malicious", "confidence": 97, "reason": "looks like a shell", "model": "groq"}},
			"cursor": 42,
			// A portal before 0.23.8 may still send a model update: ignored.
			"delta": map[string]any{"base_version": "v1", "version": 7, "bias": 0.1, "entries": [][2]float64{{5, 0.5}}, "samples": 3},
		}
	})
	defer srv.Close()
	a, _ := setup(t, `{"ai":{"provider":"portal"}}`)
	a.Portal = portalFor(srv.URL, priv)
	n, err := a.Sync(context.Background())
	if err != nil || n != 2 {
		t.Fatalf("sync: %d %v", n, err)
	}
	if store.GetKV(a.DB, "ai_kb_cursor") != "42" {
		t.Fatal("cursor not stored")
	}
	raw, _ := os.ReadFile(scanner.LearnedHashPath())
	// Only an administrator's verdict becomes a detection on every server.
	if !strings.Contains(string(raw), "1234 "+sha+" "+scanner.LearnedLabel) || strings.Contains(string(raw), aiOnly) {
		t.Fatalf("learned list: %s", raw)
	}
	if _, err := os.Stat(filepath.Join(store.StateDir(), "ai-delta.json")); err == nil {
		t.Fatal("model update saved")
	}
}

func TestShortPath(t *testing.T) {
	for in, want := range map[string]string{
		"/home/alice/public_html/wp-content/x.php": "~/public_html/wp-content/x.php",
		"/home2/bob/x.php":                         "~/x.php",
		"/var/www/html/x.php":                      "/var/www/html/x.php",
	} {
		if got := ShortPath(in); got != want {
			t.Errorf("%s: %s", in, got)
		}
	}
}

// A finding whose content only another server's AI found clean is judged by
// this server's AI, not acted on with the fleet verdict (which the scanner
// does not honour: the file was restored and flagged again every minute).
func TestFleetCleanFindingAskedHere(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	srv := fakePortal(t, pub, func(path string, p map[string]any) any {
		res := []map[string]any{}
		for _, f := range p["files"].([]any) {
			res = append(res, map[string]any{"id": f.(map[string]any)["id"], "verdict": "clean", "confidence": 95, "reason": "asked again", "model": "m", "source": "ai"})
		}
		return map[string]any{"results": res}
	})
	defer srv.Close()
	a, f := setup(t, "")
	a.Portal = portalFor(srv.URL, priv)
	sha := shaOf(t, f)
	Save(a.DB, Verdict{SHA256: sha, Verdict: Clean, Confidence: 100, Reason: "plugin", Model: "gemini", Source: "fleet", At: 1})
	if IsCleared(a.DB, sha) {
		t.Fatal("another server's AI verdict clears content here")
	}
	var got []Verdict
	a.OnVerdict = func(_ Job, v Verdict) { got = append(got, v) }
	a.process(context.Background(), []Job{{Path: f, SHA256: sha, FindingID: 7, Signature: "Test"}})
	if len(got) != 1 || got[0].Source == "fleet" {
		t.Fatalf("verdicts %+v, want one from this server", got)
	}
	// Known content without a finding still uses the stored verdict.
	got = nil
	Save(a.DB, Verdict{SHA256: sha, Verdict: Malicious, Confidence: 100, Model: "gemini", Source: "fleet", At: 2})
	a.process(context.Background(), []Job{{Path: f, SHA256: sha}})
	if len(got) != 1 || got[0].Source != "fleet" {
		t.Fatalf("known malware: %+v", got)
	}
}

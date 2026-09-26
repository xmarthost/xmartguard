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

	"github.com/xmarthost/xmartguard/agent/internal/ml"
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

func TestBuiltinDefault(t *testing.T) {
	a, f := setup(t, "")
	if s := a.Settings.Get().AI; !s.Enabled || s.Provider != "builtin" || s.Scope != "suspicious" || !s.Learn {
		t.Fatalf("defaults: %+v", s)
	}
	v, err := a.Analyze(context.Background(), Job{Path: f, SHA256: "abc", Signature: "Test"})
	if err != nil || v.Verdict != Clean || !strings.HasPrefix(v.Model, "builtin") {
		t.Fatalf("builtin: %+v %v", v, err)
	}
	if c, ok := Cached(a.DB, "abc"); !ok || c.Verdict != Clean || c.Source != "builtin" {
		t.Fatalf("not cached: %+v", c)
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
	vs, err := a.AnalyzeBatch(context.Background(), []Job{{FindingID: 1, Path: f, SHA256: "s1", Signature: "PHP.X"}, {Path: g, SHA256: "s2"}})
	if err != nil || vs[0].Verdict != Malicious || !vs[0].Injected || len(vs[0].Cut) != 1 || vs[1].Source != "fleet" {
		t.Fatalf("verdicts: %+v %v", vs, err)
	}
	files := got["files"].([]any)
	f0 := files[0].(map[string]any)
	if len(files) != 2 || f0["match"] != "PHP.X" || !strings.Contains(f0["excerpt"].(string), "2|echo 'hello';") {
		t.Fatalf("request: %v", got)
	}
	// Fleet training data travels with the file when learning is on.
	if base, _ := ml.Base(); f0["base"] != base.Version || len(f0["features"].([]any)) == 0 {
		t.Fatalf("no features: %v", f0["base"])
	}
	if c, ok := Cached(a.DB, "s1"); !ok || !c.Injected || c.Cut[0].From != 2 || c.Size == 0 {
		t.Fatalf("cached: %+v", c)
	}
}

func TestPortalDownFallsBackToBuiltin(t *testing.T) {
	a, f := setup(t, `{"ai":{"provider":"portal"}}`)
	a.Portal = &PortalAI{URL: "http://127.0.0.1:1", ServerID: "x", Sign: func([]byte) string { return "" }}
	v, err := a.Analyze(context.Background(), Job{FindingID: 3, Path: f, SHA256: "fb"})
	if err != nil || v.Source != "fallback" {
		t.Fatalf("fallback: %+v %v", v, err)
	}
}

func TestFleetSyncLearnsHashesAndModel(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	base, _ := ml.Base()
	sha := strings.Repeat("ab", 32)
	calls := 0
	srv := fakePortal(t, pub, func(path string, p map[string]any) any {
		calls++
		if path != "/api/agent/ai/sync" || p["base"] != base.Version {
			return map[string]any{}
		}
		return map[string]any{
			"kb":     []map[string]any{{"sha256": sha, "size": 1234, "verdict": "malicious", "confidence": 97, "reason": "web shell", "model": "groq"}},
			"cursor": 42,
			"delta":  map[string]any{"base_version": base.Version, "version": 7, "bias": 0.1, "entries": [][2]float64{{5, 0.5}}, "samples": 3},
		}
	})
	defer srv.Close()
	a, _ := setup(t, `{"ai":{"provider":"builtin"}}`)
	a.Portal = portalFor(srv.URL, priv)
	n, err := a.Sync(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("sync: %d %v", n, err)
	}
	defer ml.ApplyDelta(nil)
	if store.GetKV(a.DB, "ai_kb_cursor") != "42" || store.GetKV(a.DB, "ai_model_version") != "7" {
		t.Fatal("cursor not stored")
	}
	raw, _ := os.ReadFile(scanner.LearnedHashPath())
	if !strings.Contains(string(raw), "1234 "+sha+" "+scanner.LearnedLabel) {
		t.Fatalf("learned list: %s", raw)
	}
	m, _ := ml.Default()
	if !strings.HasSuffix(m.Version, "+fleet.7") || m.Weights[5] != base.Weights[5]+0.5 {
		t.Fatalf("delta not applied: %s", m.Version)
	}
	if _, err := os.Stat(filepath.Join(store.StateDir(), "ai-delta.json")); err != nil {
		t.Fatal("delta not saved")
	}
}

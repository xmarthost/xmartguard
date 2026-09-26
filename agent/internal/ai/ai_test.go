package ai

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
	if s := a.Settings.Get().AI; !s.Enabled || s.Provider != "builtin" {
		t.Fatalf("defaults: %+v", s)
	}
	v, err := a.Analyze(context.Background(), Job{Path: f, SHA256: "abc", Signature: "Test"})
	if err != nil || v.Verdict != Clean || !strings.HasPrefix(v.Model, "builtin") {
		t.Fatalf("builtin: %+v %v", v, err)
	}
	if c, ok := Cached(a.DB, "abc"); !ok || c.Verdict != Clean {
		t.Fatalf("not cached: %+v", c)
	}
}

func TestOllama(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/chat" {
			http.NotFound(w, r)
			return
		}
		json.NewDecoder(r.Body).Decode(&got)
		io.WriteString(w, `{"message":{"role":"assistant","content":"{\"verdict\":\"malicious\",\"confidence\":91,\"reason\":\"runs request data\"}"},"done":true}`)
	}))
	defer srv.Close()
	a, f := setup(t, `{"ai":{"provider":"ollama","ollama_url":"`+srv.URL+`/","model":"qwen2.5-coder:7b"}}`)
	v, err := a.Analyze(context.Background(), Job{Path: f, SHA256: "def", Signature: "Test"})
	if err != nil || v.Verdict != Malicious || v.Confidence != 91 || v.Model != "ollama qwen2.5-coder:7b" {
		t.Fatalf("ollama: %+v %v", v, err)
	}
	if got["model"] != "qwen2.5-coder:7b" || got["format"] == nil || got["stream"] != false {
		t.Fatalf("request: %v", got)
	}
}

func TestClaude(t *testing.T) {
	var key, path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key, path = r.Header.Get("X-Api-Key"), r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"msg_1","type":"message","role":"assistant","model":"claude-opus-5","stop_reason":"end_turn",
			"content":[{"type":"text","text":"{\"verdict\":\"clean\",\"confidence\":88,\"reason\":\"ordinary template\"}"}],
			"usage":{"input_tokens":10,"output_tokens":10}}`)
	}))
	defer srv.Close()
	a, f := setup(t, `{"ai":{"provider":"anthropic","api_key":"sk-test","model":"claude-opus-5"}}`)
	a.BaseURL = srv.URL
	v, err := a.Analyze(context.Background(), Job{Path: f, SHA256: "ghi", Signature: "Test"})
	if err != nil || v.Verdict != Clean || v.Confidence != 88 {
		t.Fatalf("claude: %+v %v", v, err)
	}
	if key != "sk-test" || path != "/v1/messages" {
		t.Fatalf("request: key %q path %q", key, path)
	}
}

func TestProviderValidation(t *testing.T) {
	a, _ := setup(t, "")
	if _, err := a.Settings.Patch([]byte(`{"ai":{"provider":"anthropic","model":"claude-opus-5"}}`)); err == nil {
		t.Fatal("Claude without a key accepted")
	}
	if _, err := a.Settings.Patch([]byte(`{"ai":{"provider":"ollama","ollama_url":"ftp://x"}}`)); err == nil {
		t.Fatal("bad Ollama URL accepted")
	}
}

func TestSample(t *testing.T) {
	big := []byte(strings.Repeat("a", 100*1024))
	s, trunc := sample(big, 10)
	if !trunc || len(s) > 11*1024 || !strings.Contains(s, "omitted") {
		t.Fatalf("sample len %d trunc %v", len(s), trunc)
	}
}

func TestPortalProvider(t *testing.T) {
	var got map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/agent/ai" {
			http.NotFound(w, r)
			return
		}
		json.NewDecoder(r.Body).Decode(&got)
		io.WriteString(w, `{"verdict":"suspicious","confidence":70,"reason":"obfuscated loader","model":"qwen2.5-coder:14b"}`)
	}))
	defer srv.Close()
	a, f := setup(t, `{"ai":{"provider":"portal"}}`)
	a.Portal = &PortalAI{URL: srv.URL + "/", ServerID: "11111111-1111-1111-1111-111111111111", Sign: func(m []byte) string { return "sig:" + string(m[:9]) }}
	v, err := a.Analyze(context.Background(), Job{Path: f, SHA256: "jkl", Signature: "Test"})
	if err != nil || v.Verdict != Suspicious || v.Model != "portal qwen2.5-coder:14b" {
		t.Fatalf("portal: %+v %v", v, err)
	}
	if got["signature"] != "sig:xg-ai-v1:" || got["system"] == "" || !strings.Contains(got["prompt"], "<file>") {
		t.Fatalf("request: %v", got)
	}
}

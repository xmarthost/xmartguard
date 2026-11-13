package core

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/xmarthost/xmartguard/agent/internal/ai"
	"github.com/xmarthost/xmartguard/agent/internal/store"
)

// A resend of earlier weeks' advisories (owner, 2026-11-13: act on every
// Wordfence vulnerability since 1 November) is longer than one page of the
// portal's answer: the agent reads every page in one sync, then stops.
func TestSyncVulnsReadsEveryPage(t *testing.T) {
	a := newTestAgent(t, `{"firewall":{"enabled":false},"cms":{"enabled":true,"rapid":true}}`)
	var asked []int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var env struct {
			Payload string `json:"payload"`
		}
		json.NewDecoder(r.Body).Decode(&env)
		var b struct {
			Since int64 `json:"since"`
		}
		json.Unmarshal([]byte(env.Payload), &b)
		asked = append(asked, b.Since)
		items := []map[string]any{}
		cursor := int64(4500)
		switch b.Since {
		case 100:
			items, cursor = []map[string]any{{"id": "a", "kind": "plugin", "slug": "x", "cvss": 9.8}}, 2100
		case 2100:
			items, cursor = []map[string]any{{"id": "b", "kind": "plugin", "slug": "y", "cvss": 9.8}}, 4100
		case 4100:
			items, cursor = []map[string]any{{"id": "c", "kind": "plugin", "slug": "z", "cvss": 9.8}}, 4500
		}
		json.NewEncoder(w).Encode(map[string]any{"items": items, "cursor": cursor})
	}))
	defer srv.Close()
	a.AI.Portal = &ai.PortalAI{URL: srv.URL, ServerID: "x", Sign: func([]byte) string { return "s" }}
	store.SetKV(a.DB, kvVulnCursor, "100")
	if err := a.syncVulns(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(asked) != 4 || asked[3] != 4500 {
		t.Fatalf("pages asked: %v", asked)
	}
	if got := store.GetKV(a.DB, kvVulnCursor); got != "4500" {
		t.Fatalf("cursor %s", got)
	}
}

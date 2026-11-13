package core

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
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
	var receipts []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var env struct {
			Payload string `json:"payload"`
		}
		json.NewDecoder(r.Body).Decode(&env)
		if r.URL.Path == "/api/agent/cms/vulns/results" {
			var b struct {
				Receipt struct {
					Seqs []int64 `json:"seqs"`
				} `json:"receipt"`
			}
			json.Unmarshal([]byte(env.Payload), &b)
			for _, q := range b.Receipt.Seqs {
				receipts = append(receipts, strconv.FormatInt(q, 10))
			}
			w.Write([]byte(`{"ok":true}`))
			return
		}
		var b struct {
			Since int64 `json:"since"`
		}
		json.Unmarshal([]byte(env.Payload), &b)
		asked = append(asked, b.Since)
		items := []map[string]any{}
		cursor := int64(4500)
		switch b.Since {
		case 100:
			items, cursor = []map[string]any{{"id": "a", "kind": "plugin", "slug": "x", "cvss": 9.8, "seq": 2100}}, 2100
		case 2100:
			items, cursor = []map[string]any{{"id": "b", "kind": "plugin", "slug": "y", "cvss": 9.8, "seq": 4100}}, 4100
		case 4100:
			items, cursor = []map[string]any{{"id": "c", "kind": "plugin", "slug": "z", "cvss": 9.8, "seq": 4500}}, 4500
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
	// Every page's advisories are confirmed to the portal (its report shows
	// which servers received a send).
	if strings.Join(receipts, ",") != "2100,4100,4500" {
		t.Fatalf("receipts: %v", receipts)
	}
}

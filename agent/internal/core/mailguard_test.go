package core

import (
	"context"
	"encoding/json"
	"testing"
)

// The portal's Spamhaus DQS key reaches every server; a server's own key
// wins; an invalid key is refused.
func TestMailGlobalDQSKey(t *testing.T) {
	a := newTestAgent(t, `{}`)
	h := a.Handlers()["mail.global"]
	if _, err := h(context.Background(), json.RawMessage(`{"dqs_key":"not a key"}`)); err == nil {
		t.Fatal("invalid key accepted")
	}
	if _, err := h(context.Background(), json.RawMessage(`{"dqs_key":"ABCDEFGHIJKLMNOPQRSTUVWXYZ"}`)); err != nil {
		t.Fatal(err)
	}
	if k, src := a.dqsKey(); k != "abcdefghijklmnopqrstuvwxyz" || src != "portal" {
		t.Fatalf("%q %q", k, src)
	}
	a.Settings.Patch(json.RawMessage(`{"reputation":{"spamhaus_dqs_key":"serverkeyserverkeyserverkey"}}`))
	if k, src := a.dqsKey(); k != "serverkeyserverkeyserverkey" || src != "server" {
		t.Fatalf("%q %q", k, src)
	}
	// Removed in the portal: no key left from it.
	a.Settings.Patch(json.RawMessage(`{"reputation":{"spamhaus_dqs_key":""}}`))
	h(context.Background(), json.RawMessage(`{"dqs_key":""}`))
	if k, _ := a.dqsKey(); k != "" {
		t.Fatalf("key left: %q", k)
	}
}

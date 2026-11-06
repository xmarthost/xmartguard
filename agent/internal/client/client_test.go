package client

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"github.com/xmarthost/xmartguard/agent/internal/config"
	"github.com/xmarthost/xmartguard/agent/internal/identity"
	"github.com/xmarthost/xmartguard/agent/internal/protocol"
	"github.com/xmarthost/xmartguard/agent/internal/sysinfo"
)

// Audit A1 F18: a portal that stops answering (a connection dropped without
// a FIN) is noticed by the keepalive ping, not after TCP gives up.
func TestKeepaliveNoticesDeadPortal(t *testing.T) {
	defer func(e, to time.Duration) { pingEvery, pingTimeout = e, to }(pingEvery, pingTimeout)
	pingEvery, pingTimeout = 100*time.Millisecond, 200*time.Millisecond
	hold := make(chan struct{})
	defer close(hold)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer c.CloseNow()
		ctx := r.Context()
		wsjson.Write(ctx, c, protocol.Envelope{Type: protocol.TypeChallenge, Nonce: "n"})
		var e protocol.Envelope
		wsjson.Read(ctx, c, &e)
		wsjson.Write(ctx, c, protocol.Envelope{Type: protocol.TypeWelcome})
		<-hold // never reads again: pings get no answer
	}))
	defer srv.Close()
	id, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	s := &Session{Cfg: &config.Config{ServerURL: srv.URL, ServerID: "x"}, ID: id, Collector: sysinfo.NewCollector(),
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	done := make(chan error, 1)
	go func() { done <- s.runOnce(context.Background()) }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "ping") {
			t.Fatalf("ended with %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("dead portal not noticed")
	}
}

func result(t *testing.T, s *Session, action string) protocol.Envelope {
	t.Helper()
	var got protocol.Envelope
	s.handle(context.Background(), protocol.Envelope{ID: "1", Action: action}, func(e protocol.Envelope) error { got = e; return nil })
	return got
}

// Audit A1 F5 / F6 and A10 F4 / F5: a panicking handler is an error, heavy
// actions run one at a time, long actions get the portal's deadline, and a
// result too large for the portal's frame limit is an error.
func TestHandleLimits(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	var deadline time.Duration
	s := &Session{Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Handlers: map[string]Handler{
		"boom": func(context.Context, json.RawMessage) (any, error) { var m map[string]int; m["x"]++; return nil, nil },
		"db.clean": func(context.Context, json.RawMessage) (any, error) {
			select {
			case started <- struct{}{}:
			default:
			}
			<-release
			return "done", nil
		},
		"monitor.rootkit": func(ctx context.Context, _ json.RawMessage) (any, error) {
			d, _ := ctx.Deadline()
			deadline = time.Until(d)
			return nil, nil
		},
		"big": func(context.Context, json.RawMessage) (any, error) { return strings.Repeat("x", MaxResult+1), nil },
		"ok":  func(context.Context, json.RawMessage) (any, error) { return map[string]int{"n": 1}, nil },
	}}
	if r := result(t, s, "boom"); *r.OK || !strings.Contains(r.Error, "internal error") {
		t.Fatalf("panic: %+v", r)
	}
	done := make(chan protocol.Envelope)
	go func() { done <- result(t, s, "db.clean") }()
	<-started
	if r := result(t, s, "db.clean"); *r.OK || !strings.Contains(r.Error, "busy") {
		t.Fatalf("second heavy run: %+v", r)
	}
	if r := result(t, s, "ok"); !*r.OK {
		t.Fatalf("light action refused: %+v", r)
	}
	close(release)
	if r := <-done; !*r.OK {
		t.Fatalf("heavy run: %+v", r)
	}
	if r := result(t, s, "db.clean"); !*r.OK {
		t.Fatal("slot not released")
	}
	result(t, s, "monitor.rootkit")
	if deadline < 50*time.Minute {
		t.Fatalf("rootkit deadline %v", deadline)
	}
	if r := result(t, s, "big"); *r.OK || !strings.Contains(r.Error, "too large") {
		t.Fatalf("big: ok=%v %q", *r.OK, r.Error)
	}
}

// The move to another account: the request the portal checks (its
// /api/agent/transfer signs over the token's hash, see routes/agent.ts).
func TestTransferSignsForTheToken(t *testing.T) {
	id, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/agent/transfer" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.Write([]byte(`{"ok":true,"moved":true}`))
	}))
	defer srv.Close()
	cfg := &config.Config{ServerURL: srv.URL, ServerID: "15d69a72-653a-47b6-90f6-fde737bce061"}
	moved, err := Transfer(context.Background(), cfg, id, " XG-AAAA-BBBB-CCCC \n")
	if err != nil || !moved {
		t.Fatalf("%v %v", moved, err)
	}
	sum := sha256.Sum256([]byte("XG-AAAA-BBBB-CCCC"))
	msg := "xg-transfer-v1:" + cfg.ServerID + ":" + hex.EncodeToString(sum[:]) + ":" + got["ts"]
	pub, _ := base64.StdEncoding.DecodeString(id.PublicKeyB64())
	sig, _ := base64.StdEncoding.DecodeString(got["signature"])
	if got["token"] != "XG-AAAA-BBBB-CCCC" || got["server_id"] != cfg.ServerID || !ed25519.Verify(ed25519.PublicKey(pub), []byte(msg), sig) {
		t.Fatalf("request %v", got)
	}
}

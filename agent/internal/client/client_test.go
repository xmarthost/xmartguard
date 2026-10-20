package client

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/protocol"
)

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

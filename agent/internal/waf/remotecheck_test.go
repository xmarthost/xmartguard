package waf

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCheckRemote(t *testing.T) {
	outgoingIP = func(context.Context) string { return "203.0.113.7" }
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("ModSec-key") {
		case "GOOD.1":
			_, _ = w.Write([]byte("# feed\nSecRule ARGS \"@rx x\" \"id:1,deny\"\n  SecAction \"id:2,pass\"\n"))
		case "EMPTY.1":
			_, _ = w.Write([]byte("<html>not licensed</html>"))
		default:
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	defer srv.Close()
	if n, err := checkRemote(context.Background(), "GOOD.1", srv.URL); err != nil || n != 2 {
		t.Fatalf("good: %d %v", n, err)
	}
	if _, err := checkRemote(context.Background(), "BAD.1", srv.URL); err == nil || !strings.Contains(err.Error(), "HTTP 403") || !strings.Contains(err.Error(), "IP") {
		t.Fatalf("bad: %v", err)
	}
	if _, err := checkRemote(context.Background(), "EMPTY.1", srv.URL); err == nil || !strings.Contains(err.Error(), "no rules") ||
		!strings.Contains(err.Error(), "not licensed") || !strings.Contains(err.Error(), "203.0.113.7") {
		t.Fatalf("empty: %v", err)
	}

	m := &Manager{}
	m.ruleSets.Remote = []RemoteRules{{ID: "me", Key: "BAD.1", URL: srv.URL}, {ID: "ok", Key: "GOOD.1", URL: srv.URL}}
	states := []RuleSetState{
		{ID: "remote:me", State: "active"},
		{ID: "remote:ok", State: "active", Detail: "loaded by ModSecurity from x; POST blocklist rbl.example.net"},
		{ID: "custom", State: "active"},
	}
	m.checkRemoteStates(states)
	if states[0].State != "error" || states[1].State != "active" || !strings.HasPrefix(states[1].Detail, "2 rules downloaded") ||
		!strings.HasSuffix(states[1].Detail, "POST blocklist rbl.example.net") || states[2].Detail != "" {
		t.Fatalf("%+v", states)
	}
}

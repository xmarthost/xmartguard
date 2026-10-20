package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/version"
)

// fakeAgent is an inert stand-in for the agent binary: it only prints a
// version.
func fakeAgent(v string) []byte { return []byte("#!/bin/sh\necho " + v + "\n") }

func portal(t *testing.T, bin []byte) *httptest.Server {
	sum := sha256.Sum256(bin)
	name := "/downloads/xpguard-agent-linux-" + runtime.GOARCH
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case name:
			w.Write(bin)
		case name + ".sha256":
			w.Write([]byte(hex.EncodeToString(sum[:]) + "  xpguard-agent\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func selfBinary(t *testing.T) string {
	self := filepath.Join(t.TempDir(), "xpguard-agent")
	if err := os.WriteFile(self, fakeAgent("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	return self
}

// Audit A1 F3: no downgrade, no http, no unverified TLS, no redirects.
func TestUpdateRefusesDowngradeAndCleartext(t *testing.T) {
	ctx := context.Background()
	self := selfBinary(t)
	old := portal(t, fakeAgent("0.0.1"))
	if _, err := update(ctx, old.Client(), old.URL, "", self); err == nil || !strings.Contains(err.Error(), "older") {
		t.Fatalf("downgrade: %v", err)
	}
	if b, _ := os.ReadFile(self); string(b) != string(fakeAgent("old")) {
		t.Fatal("binary replaced by an older build")
	}
	for _, u := range []string{"http://portal.example", "ftp://portal.example", "http://localhost.example", "http://127.0.0.1.example"} {
		if _, err := update(ctx, http.DefaultClient, u, "", self); err == nil || !strings.Contains(err.Error(), "https") {
			t.Fatalf("%s: %v", u, err)
		}
	}
	insecure := http.DefaultTransport.(*http.Transport).Clone()
	insecure.TLSClientConfig = old.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	insecure.TLSClientConfig.InsecureSkipVerify = true
	if _, err := update(ctx, &http.Client{Transport: insecure}, old.URL, "", self); err == nil {
		t.Fatal("update over unverified TLS")
	}
	moved := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, old.URL+r.URL.Path, http.StatusMovedPermanently)
	}))
	defer moved.Close()
	if _, err := update(ctx, moved.Client(), moved.URL, "", self); err == nil {
		t.Fatal("followed a redirect")
	}
}

// Audit A1 F4: the previous binary is kept, and comes back when the new
// one keeps failing to start.
func TestUpdateKeepsPreviousAndRollsBack(t *testing.T) {
	self := selfBinary(t)
	next := "99.0.0"
	srv := portal(t, fakeAgent(next))
	v, err := update(context.Background(), srv.Client(), srv.URL, "", self)
	if err != nil || v != next {
		t.Fatalf("update: %q %v", v, err)
	}
	if b, _ := os.ReadFile(self + ".prev"); string(b) != string(fakeAgent("old")) {
		t.Fatal("previous binary not kept")
	}
	// Starts of the new build are counted; the fourth puts the old one back.
	for i := 1; i <= MaxStarts; i++ {
		if note, err := started(self, next); note != "" || err != nil {
			t.Fatalf("start %d: %q %v", i, note, err)
		}
	}
	note, err := started(self, next)
	if err != nil || note == "" {
		t.Fatalf("no rollback: %q %v", note, err)
	}
	if b, _ := os.ReadFile(self); string(b) != string(fakeAgent("old")) {
		t.Fatal("previous binary not put back")
	}
	if _, err := os.Stat(markerPath(self)); err == nil {
		t.Fatal("marker left after rollback")
	}
	// A confirmed build is kept however often it restarts.
	if _, err := update(context.Background(), srv.Client(), srv.URL, "", self); err != nil {
		t.Fatal(err)
	}
	started(self, next)
	os.Remove(markerPath(self)) // Confirm, for this path
	for i := 0; i < MaxStarts+2; i++ {
		if note, _ := started(self, next); note != "" {
			t.Fatal("rolled back a confirmed build")
		}
	}
	if b, _ := os.ReadFile(self); string(b) != string(fakeAgent(next)) {
		t.Fatal("confirmed build replaced")
	}
}

// Audit A1 F7: a slow download is not cut by the client's total timeout;
// a stalled one ends after the idle timeout, and is tried again.
func TestUpdateSlowDownload(t *testing.T) {
	defer func(d time.Duration) { idleTimeout = d }(idleTimeout)
	defer func(f func() time.Duration) { retryDelay = f }(retryDelay)
	idleTimeout = 300 * time.Millisecond
	retryDelay = func() time.Duration { return 0 }
	bin := fakeAgent("99.0.0")
	sum := sha256.Sum256(bin)
	var stalls atomic.Int32
	stalls.Store(1)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".sha256") {
			w.Write([]byte(hex.EncodeToString(sum[:])))
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(bin)))
		if stalls.Add(-1) >= 0 {
			w.Write(bin[:1])
			w.(http.Flusher).Flush()
			time.Sleep(time.Second) // stalled: the client gives up
			return
		}
		for i := range bin { // slower than the client's total timeout
			w.Write(bin[i : i+1])
			w.(http.Flusher).Flush()
			time.Sleep(600 * time.Millisecond / time.Duration(len(bin)))
		}
	}))
	defer srv.Close()
	hc := srv.Client()
	hc.Timeout = 200 * time.Millisecond
	if v, err := update(context.Background(), hc, srv.URL, "", selfBinary(t)); err != nil || v != "99.0.0" {
		t.Fatalf("%q %v", v, err)
	}
}

func TestOlder(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"0.22.25", "0.22.26", true},
		{"0.22.26", "0.22.26-dev", false},
		{"0.22.26-dev", "0.22.26", false},
		{"0.9.0", "0.22.0", true},
		{"1.0.0", "0.22.26", false},
		{"garbage", version.Version, true},
	} {
		if got := Older(c.a, c.b); got != c.want {
			t.Errorf("Older(%q, %q) = %v", c.a, c.b, got)
		}
	}
}

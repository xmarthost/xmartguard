package updater

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync/atomic"
	"testing"
)

// 2026-11-13: the portal's web server reset half the agents' downloads.
// With the version from the portal, the binary comes from the GitHub
// release, accepted only with the portal's checksum and the release
// signature; anything wrong there falls back to the portal.
func TestUpdateFromRelease(t *testing.T) {
	ctx := context.Background()
	key, priv := testKey(t)
	defer func(k, r string) { ReleaseKey, Releases = k, r }(ReleaseKey, Releases)
	ReleaseKey = key
	bin := fakeAgent("999.0.0")
	sum := sha256.Sum256(bin)
	want := hex.EncodeToString(sum[:])
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, bin))
	name := "xpguard-agent-linux-" + runtime.GOARCH

	var relBin []byte
	relSig := sig
	var portalHits, relHits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/rel/v999.0.0/" + name:
			relHits.Add(1)
			if relBin == nil {
				http.NotFound(w, r)
				return
			}
			w.Write(relBin)
		case "/rel/v999.0.0/" + name + ".sig":
			w.Write([]byte(relSig))
		case "/downloads/" + name:
			portalHits.Add(1)
			w.Write(bin)
		case "/downloads/" + name + ".sha256":
			w.Write([]byte(want + "  x\n"))
		case "/downloads/" + name + ".sig":
			w.Write([]byte(sig))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	Releases = srv.URL + "/rel"
	run := func() (string, error) {
		return updateWith(ctx, srv.Client(), srv.URL, want, "999.0.0", selfBinary(t))
	}

	// From the release; the portal's binary is not downloaded.
	relBin = bin
	if v, err := run(); err != nil || v != "999.0.0" || portalHits.Load() != 0 || relHits.Load() != 1 {
		t.Fatalf("release: %q %v portal=%d", v, err, portalHits.Load())
	}
	// A release binary that does not match the portal's checksum, a bad
	// signature, or none there: the portal's copy.
	for what, set := range map[string]func(){
		"tampered":      func() { relBin, relSig = fakeAgent("evil"), sig },
		"bad signature": func() { relBin, relSig = bin, "AAAA" },
		"not published": func() { relBin, relSig = nil, sig },
	} {
		set()
		portalHits.Store(0)
		if v, err := run(); err != nil || v != "999.0.0" || portalHits.Load() != 1 {
			t.Errorf("%s: %q %v portal=%d", what, v, err, portalHits.Load())
		}
	}
	// No version from the portal (older portal): the portal only.
	relHits.Store(0)
	if _, err := updateWith(ctx, srv.Client(), srv.URL, want, "", selfBinary(t)); err != nil || relHits.Load() != 0 {
		t.Errorf("no version: %v rel=%d", err, relHits.Load())
	}
}

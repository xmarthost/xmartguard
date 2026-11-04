package updater

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"testing"
)

func testKey(t *testing.T) (string, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(pub)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), priv
}

func signedPortal(t *testing.T, bin []byte, sig string) *httptest.Server {
	sum := sha256.Sum256(bin)
	name := "/downloads/xpguard-agent-linux-" + runtime.GOARCH
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case name:
			w.Write(bin)
		case name + ".sha256":
			w.Write([]byte(hex.EncodeToString(sum[:]) + "  xpguard-agent\n"))
		case name + ".sig":
			if sig == "" {
				http.NotFound(w, r)
				return
			}
			w.Write([]byte(sig + "\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// With the release key built in, only a binary the key signed is taken:
// a portal taken over (right checksum, no or a wrong signature) cannot
// replace the agent. Without a key, updates work as before.
func TestUpdateNeedsReleaseSignature(t *testing.T) {
	ctx := context.Background()
	key, priv := testKey(t)
	_, other := testKey(t)
	bin := fakeAgent("999.0.0")
	good := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, bin))
	forged := base64.StdEncoding.EncodeToString(ed25519.Sign(other, bin))
	defer func(k string) { ReleaseKey = k }(ReleaseKey)

	ReleaseKey = key
	for name, sig := range map[string]string{"no signature": "", "another key": forged, "not base64": "%%%", "short": "AAAA"} {
		self := selfBinary(t)
		p := signedPortal(t, bin, sig)
		if _, err := update(ctx, p.Client(), p.URL, "", self); err == nil || !strings.Contains(err.Error(), "signature") {
			t.Errorf("%s: %v", name, err)
		}
		if b, _ := os.ReadFile(self); string(b) != string(fakeAgent("old")) {
			t.Errorf("%s: binary replaced", name)
		}
	}
	self := selfBinary(t)
	p := signedPortal(t, bin, good)
	if v, err := update(ctx, p.Client(), p.URL, "", self); err != nil || v != "999.0.0" {
		t.Fatalf("signed update: %q %v", v, err)
	}
	// The key written on one line (\n as text) works too.
	ReleaseKey = strings.ReplaceAll(key, "\n", `\n`)
	if err := verifyRelease(ReleaseKey, bin, func() ([]byte, error) { return []byte(good), nil }); err != nil {
		t.Fatalf("one-line key: %v", err)
	}

	ReleaseKey = ""
	self = selfBinary(t)
	p = signedPortal(t, bin, "")
	if _, err := update(ctx, p.Client(), p.URL, "", self); err != nil {
		t.Fatalf("no key: %v", err)
	}
}

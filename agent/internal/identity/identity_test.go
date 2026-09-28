package identity

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSaveLoadSign(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "identity.key")
	id, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := id.Save(path); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("key mode %v, want 0600", st.Mode().Perm())
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.PublicKeyB64() != id.PublicKeyB64() {
		t.Fatal("public key changed after reload")
	}
	msg := []byte("hello")
	sig, _ := base64.StdEncoding.DecodeString(loaded.SignB64(msg))
	pub, _ := base64.StdEncoding.DecodeString(id.PublicKeyB64())
	if !ed25519.Verify(pub, msg, sig) {
		t.Fatal("signature does not verify")
	}
}

func TestLoadRejectsGarbage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "k")
	os.WriteFile(path, []byte("not a key"), 0o600)
	if _, err := Load(path); err == nil {
		t.Fatal("expected error")
	}
}

func TestLegacyKeyRelabelled(t *testing.T) {
	p := filepath.Join(t.TempDir(), "identity.key")
	id, _ := Generate()
	os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: legacyPEMType, Bytes: id.priv.Seed()}), 0o600)
	got, err := Load(p)
	if err != nil || !got.priv.Equal(id.priv) {
		t.Fatal("legacy key not loaded", err)
	}
	if b, _ := os.ReadFile(p); !strings.Contains(string(b), pemType) || strings.Contains(string(b), "XMART") {
		t.Fatalf("not relabelled: %s", b)
	}
}

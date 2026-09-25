package identity

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
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

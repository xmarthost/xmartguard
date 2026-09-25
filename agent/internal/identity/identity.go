// Package identity manages the agent's Ed25519 identity key. The private key
// never leaves the server; only the public key is sent at enrollment.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const pemType = "XMARTGUARD ED25519 PRIVATE KEY"

// Identity wraps an Ed25519 key pair.
type Identity struct {
	priv ed25519.PrivateKey
}

// Generate creates a new random identity.
func Generate() (*Identity, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Identity{priv: priv}, nil
}

// Load reads a key written by Save.
func Load(path string) (*Identity, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != pemType {
		return nil, errors.New("identity: invalid key file")
	}
	if len(block.Bytes) != ed25519.SeedSize {
		return nil, errors.New("identity: invalid seed length")
	}
	return &Identity{priv: ed25519.NewKeyFromSeed(block.Bytes)}, nil
}

// Save writes the key seed with mode 0600, atomically.
func (i *Identity) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data := pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: i.priv.Seed()})
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("identity: %w", err)
	}
	return nil
}

// PublicKeyB64 returns the raw 32-byte public key, base64 (std) encoded.
func (i *Identity) PublicKeyB64() string {
	return base64.StdEncoding.EncodeToString(i.priv.Public().(ed25519.PublicKey))
}

// SignB64 signs msg and returns a base64 signature.
func (i *Identity) SignB64(msg []byte) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(i.priv, msg))
}

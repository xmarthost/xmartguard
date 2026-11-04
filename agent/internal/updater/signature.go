package updater

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"strings"
)

// ReleaseKey is the public half of the owner's release signing key (an
// Ed25519 key in PEM, "-----BEGIN PUBLIC KEY-----"). The private half
// never reaches the portal: it lives in the repository's GitHub Actions
// secret XPGUARD_SIGNING_KEY, and the release workflow signs every agent
// binary with it. When set, an update is taken only with a valid
// signature, whatever the portal says: a portal taken over cannot run its
// own agent on the servers (the way cPGuard's fleet was attacked,
// 2026-11-02). Empty: updates are checked by their checksum only.
// It is written here, in the source, so every build carries it.
var ReleaseKey = ""

// errUnsigned: the portal has no valid signature for the binary.
var errUnsigned = errors.New("the update has no valid release signature; update refused")

// releaseKey parses ReleaseKey (nil, nil when no key is set).
func releaseKey(pemText string) (ed25519.PublicKey, error) {
	pemText = strings.TrimSpace(pemText)
	if pemText == "" {
		return nil, nil
	}
	// The key may be set on one line (ldflags): "\n" written as text.
	pemText = strings.ReplaceAll(pemText, `\n`, "\n")
	b, _ := pem.Decode([]byte(pemText))
	if b == nil {
		return nil, errors.New("the release key is not PEM")
	}
	k, err := x509.ParsePKIXPublicKey(b.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := k.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("the release key is not an Ed25519 key")
	}
	return pub, nil
}

// verifyRelease checks the signature (base64 of the 64-byte Ed25519
// signature of the binary, as openssl pkeyutl -sign -rawin writes it) with
// the built-in key. fetchSig is only called when a key is set.
func verifyRelease(key string, bin []byte, fetchSig func() ([]byte, error)) error {
	pub, err := releaseKey(key)
	if err != nil {
		return err
	}
	if pub == nil {
		return nil
	}
	raw, err := fetchSig()
	if err != nil {
		return errUnsigned
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(pub, bin, sig) {
		return errUnsigned
	}
	return nil
}

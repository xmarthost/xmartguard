package updater

import (
	"os"
	"testing"
)

// builtInKey is the release key of the source, kept before TestMain clears
// it for the tests of the rest of the update (their test portal signs
// nothing; TestUpdateNeedsReleaseSignature sets its own key).
var builtInKey = ReleaseKey

func TestMain(m *testing.M) {
	ReleaseKey = ""
	os.Exit(m.Run())
}

// The built-in release key is the owner's (2026-11-04): a valid Ed25519
// public key, so every agent from this release on needs signed updates.
func TestBuiltInReleaseKey(t *testing.T) {
	pub, err := releaseKey(builtInKey)
	if err != nil || len(pub) != 32 {
		t.Fatalf("release key: %v (%d bytes)", err, len(pub))
	}
}

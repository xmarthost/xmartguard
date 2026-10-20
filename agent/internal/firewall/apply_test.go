package firewall

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// fakeBin writes a shell script standing in for nft or iptables-restore
// (nothing reaches the kernel).
func fakeBin(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "fake")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}

// Applies never overlap: a slow apply's older snapshot cannot be loaded
// after a newer one (an unblocked address came back until the next apply).
func TestApplySerialised(t *testing.T) {
	m := unitManager(t)
	log := filepath.Join(t.TempDir(), "calls")
	m.NFT = NFT{Bin: fakeBin(t, "cat >/dev/null\necho start >> "+log+"\nsleep 0.1\necho end >> "+log+"\n")}
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = m.Apply() }()
	}
	wg.Wait()
	b, _ := os.ReadFile(log)
	got := strings.Fields(string(b))
	if len(got) != 12 {
		t.Fatalf("%d calls: %v", len(got), got)
	}
	for i, s := range got {
		if want := []string{"start", "end"}[i%2]; s != want {
			t.Fatalf("applies overlapped: %v", got)
		}
	}
}

// iptables-restore waits for the xtables lock (-w); a version without -w
// (CentOS 7) still loads the rules. A lock failure is reported, not
// hidden by the retry without LOG.
func TestRestoreWaitsForLock(t *testing.T) {
	old := fakeBin(t, "for a in \"$@\"; do [ \"$a\" = -w ] && { echo \"iptables-restore: invalid option -- 'w'\"; exit 2; }; done\ncat >/dev/null\n")
	if err := restoreRules(context.Background(), old, "*filter\nCOMMIT\n"); err != nil {
		t.Fatalf("old iptables-restore: %v", err)
	}
	args := filepath.Join(t.TempDir(), "args")
	cur := fakeBin(t, "echo \"$@\" > "+args+"\ncat >/dev/null\n")
	if err := restoreRules(context.Background(), cur, "*filter\nCOMMIT\n"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(args); strings.TrimSpace(string(b)) != "--noflush -w" {
		t.Fatalf("args %q", b)
	}
	if !xtablesLocked(errors.New("Another app is currently holding the xtables lock. Perhaps you want to use the -w option?")) || xtablesLocked(errors.New("iptables-restore: line 12 failed")) {
		t.Fatal("lock error detection")
	}
}

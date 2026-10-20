package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Audit A1 F12: agent.log (appended to by systemd) is capped: the old
// lines move to agent.log.1 and new lines start the file again.
func TestRotateLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.log")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o640)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	f.WriteString(strings.Repeat("old line\n", 100))
	if rotated, err := rotateLog(f, path, 10_000); rotated || err != nil {
		t.Fatalf("rotated under the limit: %v", err)
	}
	if rotated, err := rotateLog(f, path, 500); !rotated || err != nil {
		t.Fatalf("not rotated: %v", err)
	}
	f.WriteString("new line\n")
	if b, _ := os.ReadFile(path); string(b) != "new line\n" {
		t.Fatalf("log after rotation: %q", b)
	}
	if b, _ := os.ReadFile(path + ".1"); len(b) != 900 {
		t.Fatalf("old log %d bytes", len(b))
	}
}

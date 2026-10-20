package logtail

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Audit A1 F20: a line longer than MaxLine (no newline for a long time) is
// dropped, not kept growing in memory; the lines after it come through.
func TestOverlongLineDropped(t *testing.T) {
	defer func(d time.Duration) { pollEvery = d }(pollEvery)
	pollEvery = 20 * time.Millisecond
	path := filepath.Join(t.TempDir(), "log")
	os.WriteFile(path, nil, 0o644)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	lines := make(chan string, 10)
	go Follow(ctx, path, lines)
	time.Sleep(100 * time.Millisecond)
	f, _ := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	defer f.Close()
	f.WriteString("first\n")
	blob := strings.Repeat("x", 600<<10)
	for i := 0; i < 4; i++ { // over several polls, no newline
		f.WriteString(blob)
		time.Sleep(60 * time.Millisecond)
	}
	f.WriteString("\nafter\n")
	var got []string
	deadline := time.After(3 * time.Second)
	for len(got) < 2 {
		select {
		case l := <-lines:
			got = append(got, l)
		case <-deadline:
			t.Fatalf("lines %d: %q", len(got), got)
		}
	}
	if got[0] != "first\n" || got[1] != "after\n" {
		t.Fatalf("got %d-byte and %d-byte lines", len(got[0]), len(got[1]))
	}
}

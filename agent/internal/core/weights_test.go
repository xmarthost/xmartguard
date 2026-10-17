package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestServiceWeights(t *testing.T) {
	root := t.TempDir()
	oldRoot, oldRun := unitMoveRoot, runSystemctl
	t.Cleanup(func() { unitMoveRoot, runSystemctl = oldRoot, oldRun })
	unitMoveRoot = root
	var calls []string
	runSystemctl = func(args ...string) error { calls = append(calls, strings.Join(args, " ")); return nil }
	ensureServiceWeights() // no unit: nothing
	if len(calls) != 0 {
		t.Fatal("touched systemd without the service installed")
	}
	os.MkdirAll(root+unitDir, 0o755)
	os.WriteFile(root+unitDir+"/"+NewUnitName, []byte("[Service]\n"), 0o644)
	ensureServiceWeights()
	b, err := os.ReadFile(filepath.Join(root+unitDir, NewUnitName+".d", weightsDropIn))
	if err != nil || !strings.Contains(string(b), "CPUWeight=20") {
		t.Fatalf("drop-in %q %v", b, err)
	}
	if strings.Join(calls, "|") != "daemon-reload|set-property --runtime xpguard-agent.service CPUWeight=20 IOWeight=20" {
		t.Fatalf("calls %q", calls)
	}
	ensureServiceWeights() // already in place: nothing again
	if len(calls) != 2 {
		t.Fatalf("applied again: %q", calls)
	}
}

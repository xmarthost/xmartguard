package core

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestMoveUnitScriptSyntax(t *testing.T) {
	a := newTestAgent(t, "")
	root := t.TempDir()
	unitMoveRoot = root
	defer func() { unitMoveRoot = "" }()
	var script string
	runSwitch = func(s string) error { script = s; return nil }
	old := root + OldBinPath
	_ = os.MkdirAll(filepath.Dir(old), 0o755)
	_ = os.WriteFile(old, []byte("x"), 0o755)
	_ = os.MkdirAll(root+unitDir, 0o755)
	_ = os.WriteFile(root+unitDir+"/"+OldUnitName, []byte("ExecStart="+OldBinPath+" run\n"), 0o644)
	a.maybeMoveUnit(old)
	if out, err := exec.Command("sh", "-n", "-c", script).CombinedOutput(); err != nil {
		t.Fatalf("script syntax: %v %s\n%s", err, out, script)
	}
}

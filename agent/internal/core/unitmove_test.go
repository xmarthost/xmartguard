package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMoveUnit(t *testing.T) {
	a := newTestAgent(t, "")
	root := t.TempDir()
	unitMoveRoot = root
	defer func() { unitMoveRoot = "" }()
	var script string
	runSwitch = func(s string) error { script = s; return nil }

	old := root + OldBinPath
	_ = os.MkdirAll(filepath.Dir(old), 0o755)
	_ = os.WriteFile(old, []byte("agent-binary"), 0o755)
	_ = os.MkdirAll(root+unitDir, 0o755)
	_ = os.WriteFile(root+unitDir+"/"+OldUnitName, []byte("[Service]\nExecStart="+OldBinPath+" run\n"), 0o644)
	_ = os.MkdirAll(root+"/etc/csf", 0o755)
	_ = os.WriteFile(root+"/etc/csf/csf.pignore", []byte("exe:"+OldBinPath+"\n"), 0o600)

	// Another program path (already moved, development build): nothing happens.
	a.maybeMoveUnit("/usr/local/bin/other")
	if script != "" {
		t.Fatal("moved a non-standard install")
	}

	a.maybeMoveUnit(old)
	if b, err := os.ReadFile(root + NewBinPath); err != nil || string(b) != "agent-binary" {
		t.Fatalf("program not copied: %v", err)
	}
	nu, _ := os.ReadFile(root + unitDir + "/" + NewUnitName)
	if !strings.Contains(string(nu), "ExecStart="+NewBinPath+" run") || strings.Contains(string(nu), "xmartguard") {
		t.Fatalf("new unit: %s", nu)
	}
	pig, _ := os.ReadFile(root + "/etc/csf/csf.pignore")
	if !strings.Contains(string(pig), "exe:"+NewBinPath) {
		t.Fatalf("pignore: %s", pig)
	}
	for _, want := range []string{"systemctl stop " + OldUnitName, "systemctl enable --now " + NewUnitName, "systemctl is-active -q " + NewUnitName,
		"ln -s " + NewBinPath + " " + OldBinPath, "systemctl enable --now " + OldUnitName, "lfd restart"} {
		if !strings.Contains(script, want) {
			t.Fatalf("switch script lacks %q:\n%s", want, script)
		}
	}
	// Tried once: not again within the cool-down.
	script = ""
	a.maybeMoveUnit(old)
	if script != "" {
		t.Fatal("retried at once")
	}
}

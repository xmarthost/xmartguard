package waf

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLiteSpeedRunning(t *testing.T) {
	dir := t.TempDir()
	old := procRoot
	procRoot = dir
	defer func() { procRoot = old }()
	write := func(pid, comm string) {
		os.MkdirAll(filepath.Join(dir, pid), 0o755)
		os.WriteFile(filepath.Join(dir, pid, "comm"), []byte(comm+"\n"), 0o644)
	}
	write("10", "httpd")
	write("self", "litespeed") // not a process number
	if LiteSpeedRunning() {
		t.Fatal("Apache only: not LiteSpeed")
	}
	write("20", "lshttpd")
	if !LiteSpeedRunning() {
		t.Fatal("lshttpd running")
	}
}

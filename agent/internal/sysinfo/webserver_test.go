package sysinfo

import (
	"os"
	"path/filepath"
	"testing"
)

// A cPanel server switched back to Apache (expired LiteSpeed licence) keeps
// LiteSpeed's files: the running server decides.
func TestWebServerFollowsTheRunningServer(t *testing.T) {
	root := t.TempDir()
	old := Root
	Root = root
	defer func() { Root = old }()
	mk := func(rel, body string) {
		path := filepath.Join(root, rel)
		os.MkdirAll(filepath.Dir(path), 0o755)
		os.WriteFile(path, []byte(body), 0o755)
	}
	mk("usr/local/lsws/bin/lshttpd", "")
	if got := WebServer(); got != "litespeed" {
		t.Fatalf("LiteSpeed only: %q", got)
	}
	mk("usr/sbin/httpd", "")
	mk("proc/101/comm", "httpd\n")
	if got := WebServer(); got != "apache" {
		t.Fatalf("LiteSpeed installed, Apache running: %q", got)
	}
	mk("proc/202/comm", "litespeed\n")
	if got := WebServer(); got != "litespeed" {
		t.Fatalf("LiteSpeed running: %q", got)
	}
}

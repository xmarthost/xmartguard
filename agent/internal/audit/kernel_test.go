package audit

import (
	"os"
	"path/filepath"
	"testing"
)

// A kernel fix installed but not running, link protections off and /proc
// open to every account (without CageFS) are reported; a patched, rebooted
// server with the protections on is not, nor el9 kernels of one release
// compared by every number.
func TestKernelAndIsolation(t *testing.T) {
	root := t.TempDir()
	put := func(p, body string) {
		os.MkdirAll(filepath.Dir(filepath.Join(root, p)), 0o755)
		os.WriteFile(filepath.Join(root, p), []byte(body), 0o644)
	}
	put("proc/sys/kernel/osrelease", "5.14.0-570.12.1.el9_6.x86_64\n")
	os.MkdirAll(filepath.Join(root, "lib/modules/5.14.0-570.12.1.el9_6.x86_64"), 0o755)
	os.MkdirAll(filepath.Join(root, "lib/modules/5.14.0-570.52.1.el9_6.x86_64"), 0o755)
	put("proc/sys/fs/protected_symlinks", "0\n")
	put("proc/sys/fs/protected_hardlinks", "1\n")
	put("proc/mounts", "proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n")
	a := &Auditor{StackRoot: root}
	got := map[string]bool{}
	for _, it := range a.kernel() {
		got[it.Title] = true
	}
	for _, want := range []string{"Kernel update installed, reboot pending", "fs.protected_symlinks is off", "/proc shows every account's processes"} {
		if !got[want] {
			t.Errorf("missing %q (got %v)", want, got)
		}
	}
	if len(got) != 3 {
		t.Errorf("items: %v", got)
	}
	put("usr/bin/kcarectl", "#!/bin/sh\n")
	for _, it := range a.kernel() {
		if it.Check == "kernel" && it.Severity != "low" {
			t.Errorf("live-patched kernel: %s", it.Severity)
		}
	}
	os.Remove(filepath.Join(root, "usr/bin/kcarectl"))

	put("proc/sys/kernel/osrelease", "5.14.0-570.52.1.el9_6.x86_64\n")
	put("proc/sys/fs/protected_symlinks", "1\n")
	put("proc/mounts", "proc /proc proc rw,nosuid,nodev,noexec,relatime,hidepid=2 0 0\n")
	if items := a.kernel(); len(items) != 0 {
		t.Fatalf("patched server: %+v", items)
	}
	put("proc/mounts", "proc /proc proc rw 0 0\n")
	put("usr/sbin/cagefsctl", "#!/bin/sh\n")
	if items := a.kernel(); len(items) != 0 {
		t.Fatalf("CageFS server: %+v", items)
	}
	if cmpKernel("5.14.0-570.9.1.el9_6.x86_64", "5.14.0-570.12.1.el9_6.x86_64") >= 0 {
		t.Error("kernel numbers compared as text")
	}
}

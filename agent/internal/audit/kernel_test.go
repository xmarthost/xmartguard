package audit

import (
	"os"
	"path/filepath"
	"strings"
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

// php.ini letting scripts run commands, or blocking them but leaving
// putenv (the LD_PRELOAD bypass); the last disable_functions line counts.
// A kernel without SYN cookies.
func TestDisableFunctionsAndSyncookies(t *testing.T) {
	for ini, want := range map[string]string{
		"disable_functions =\n": "PHP may run commands",
		"memory_limit = 256M\n": "PHP may run commands",
		"disable_functions = exec,shell_exec,system,passthru,proc_open,popen\n":                   "putenv is allowed",
		"disable_functions = exec,system,putenv\n":                                                "",
		"disable_functions = \"exec, shell_exec, system, passthru, popen, proc_open, putenv\"\n":  "",
		"disable_functions = exec,system,putenv\ndisable_functions =\n":                           "PHP may run commands",
		"; disable_functions = exec\ndisable_functions = exec,shell_exec,system,putenv ; tools\n": "",
	} {
		items := disableFunctions("php.ini", ini)
		got := ""
		if len(items) > 0 {
			got = items[0].Title
		}
		if want == "" && got != "" || want != "" && !strings.HasPrefix(got, want) {
			t.Errorf("%q: %q", ini, got)
		}
	}
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "proc/sys/net/ipv4"), 0o755)
	os.WriteFile(filepath.Join(root, "proc/sys/net/ipv4/tcp_syncookies"), []byte("0\n"), 0o644)
	if items := (&Auditor{StackRoot: root}).syncookies(); len(items) != 1 {
		t.Fatalf("syncookies off: %+v", items)
	}
	os.WriteFile(filepath.Join(root, "proc/sys/net/ipv4/tcp_syncookies"), []byte("1\n"), 0o644)
	if items := (&Auditor{StackRoot: root}).syncookies(); len(items) != 0 {
		t.Fatalf("syncookies on: %+v", items)
	}
}

func TestRealtimeCoverage(t *testing.T) {
	a := &Auditor{Realtime: func() (int, int64) { return 1200, 3 }}
	if items := a.realtimeCoverage(); len(items) != 2 || items[0].Severity != "medium" {
		t.Fatalf("%+v", items)
	}
	a.Realtime = func() (int, int64) { return 0, 0 }
	if items := a.realtimeCoverage(); len(items) != 0 {
		t.Fatalf("%+v", items)
	}
}

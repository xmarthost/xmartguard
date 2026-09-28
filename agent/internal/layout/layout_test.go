package layout

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, p, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// A server on 0.10.1: program and service already renamed, configuration
// and data still under the old directories.
func oldServer(t *testing.T) string {
	root := t.TempDir()
	Root = root
	t.Cleanup(func() { Root = "" })
	write(t, root+"/etc/xmartguard/agent.json", `{"server_url":"https://p"}`)
	write(t, root+"/etc/xmartguard/waf/rules.conf", "rules")
	write(t, root+"/opt/xmartguard/data/agent.db", "db")
	write(t, root+"/opt/xmartguard/data/quarantine/1", "q")
	write(t, root+"/opt/xmartguard/logs/agent.log", "log")
	write(t, root+"/opt/xmartguard/manifest", "dir /opt/xmartguard\ndir /etc/xmartguard\nfile /etc/sysctl.d/xmartguard.conf\n")
	write(t, root+"/opt/xpguard/bin/xpguard-agent", "bin")
	write(t, root+"/opt/xpguard/logs/install.log", "new\n")
	write(t, root+"/opt/xmartguard/logs/install.log", "old\n")
	os.Symlink("/opt/xpguard/bin/xpguard-agent", root+"/opt/xmartguard/bin/xmartguard-agent")
	os.MkdirAll(root+"/opt/xmartguard/bin", 0o755)
	os.Symlink("/opt/xpguard/bin/xpguard-agent", root+"/opt/xmartguard/bin/xmartguard-agent")
	write(t, root+"/etc/systemd/system/xpguard-agent.service", "ExecStart=/opt/xpguard/bin/xpguard-agent run\nStandardOutput=append:/opt/xmartguard/logs/agent.log\n")
	write(t, root+"/etc/sysctl.d/xmartguard.conf", "fs.inotify.max_user_watches = 1\n")
	write(t, root+"/etc/csf/csf.pignore", "exe:/usr/sbin/sshd\nexe:/opt/xmartguard/bin/xmartguard-agent\nexe:/opt/xpguard/bin/xpguard-agent\n")
	os.MkdirAll(root+"/usr/local/bin", 0o755)
	os.Symlink("/opt/xmartguard/bin/xmartguard-agent", root+"/usr/local/bin/xmartguard-agent")
	os.Symlink("/opt/xpguard/bin/xpguard-agent", root+"/usr/local/bin/xgcli")
	write(t, root+"/etc/apache2/conf.d/modsec/modsec2.user.conf", "SecRule x\nInclude \"/etc/xmartguard/waf/xmartguard_modsec.conf\"\n")
	return root
}

func read(p string) string { b, _ := os.ReadFile(p); return string(b) }

func TestMigrate(t *testing.T) {
	root := oldServer(t)
	if Pick(ConfDir, OldConfDir, "agent.json") != OldConfDir || Pick(HomeDir+"/data", OldHomeDir+"/data", "agent.db") != OldHomeDir+"/data" {
		t.Fatal("unmoved server must keep its old directories")
	}
	// The old service still exists: nothing moves.
	write(t, root+"/etc/systemd/system/xmartguard-agent.service", "old")
	if notes, err := Migrate(false); err != nil || len(notes) != 0 || !Pending() {
		t.Fatalf("moved under the old service: %v %v", notes, err)
	}
	os.Remove(root + "/etc/systemd/system/xmartguard-agent.service")

	notes, err := Migrate(false)
	if err != nil {
		t.Fatal(err, notes)
	}
	if Pending() {
		t.Fatal("still pending")
	}
	for _, p := range []string{"/etc/xpguard/agent.json", "/etc/xpguard/waf/rules.conf", "/opt/xpguard/data/agent.db", "/opt/xpguard/data/quarantine/1", "/opt/xpguard/logs/agent.log", "/opt/xpguard/bin/xpguard-agent"} {
		if _, err := os.Stat(root + p); err != nil {
			t.Fatalf("%s missing", p)
		}
	}
	if l := read(root + "/opt/xpguard/logs/install.log"); l != "old\nnew\n" {
		t.Fatalf("install.log %q", l)
	}
	// Old paths still resolve until nothing names them.
	if read(root+"/etc/xmartguard/agent.json") == "" || read(root+"/opt/xmartguard/data/agent.db") != "db" {
		t.Fatal("old paths do not resolve")
	}
	if Pick(ConfDir, OldConfDir, "agent.json") != ConfDir {
		t.Fatal("pick")
	}
	if u := read(root + "/etc/systemd/system/xpguard-agent.service"); strings.Contains(u, "xmartguard") {
		t.Fatalf("unit: %s", u)
	}
	if m := read(root + "/opt/xpguard/manifest"); strings.Contains(m, "xmartguard") {
		t.Fatalf("manifest: %s", m)
	}
	if _, err := os.Stat(root + "/etc/sysctl.d/xpguard.conf"); err != nil {
		t.Fatal("sysctl not renamed")
	}
	if p := read(root + "/etc/csf/csf.pignore"); strings.Contains(p, "xmartguard") || !strings.Contains(p, "exe:/usr/sbin/sshd") {
		t.Fatalf("pignore: %s", p)
	}
	if l, _ := os.Readlink(root + "/usr/local/bin/xmartguard-agent"); l != "/opt/xpguard/bin/xpguard-agent" {
		t.Fatalf("link %s", l)
	}
	// Second run: nothing to do.
	if notes, err := Migrate(false); err != nil || len(notes) != 0 {
		t.Fatalf("second run: %v %v", notes, err)
	}

	// The web server still includes the old path: links stay.
	if DropLinks() {
		t.Fatal("links dropped while referenced")
	}
	if refs := References(); len(refs) != 1 || !strings.Contains(refs[0], "modsec2.user.conf") {
		t.Fatalf("refs %v", refs)
	}
	write(t, root+"/etc/apache2/conf.d/modsec/modsec2.user.conf", "SecRule x\nInclude \"/etc/xpguard/waf/xpguard_modsec.conf\"\n")
	if !DropLinks() {
		t.Fatalf("links kept: %v", References())
	}
	for _, p := range []string{"/etc/xmartguard", "/opt/xmartguard", "/usr/local/bin/xmartguard-agent", "/opt/xpguard/bin/xmartguard-agent"} {
		if _, err := os.Lstat(root + p); err == nil {
			t.Fatalf("%s left", p)
		}
	}
	if _, err := os.Lstat(root + "/usr/local/bin/xgcli"); err != nil {
		t.Fatal("xgcli removed")
	}
}

func TestMigrateConflictKeepsBoth(t *testing.T) {
	root := oldServer(t)
	write(t, root+"/opt/xpguard/data/agent.db", "other")
	if _, err := Migrate(true); err == nil || !strings.Contains(err.Error(), "agent.db") {
		t.Fatalf("conflict not reported: %v", err)
	}
	if read(root+"/opt/xmartguard/data/agent.db") != "db" || read(root+"/opt/xpguard/data/agent.db") != "other" {
		t.Fatal("data lost")
	}
	// /etc moved regardless.
	if _, err := os.Stat(root + "/etc/xpguard/agent.json"); err != nil {
		t.Fatal("etc not moved")
	}
}

func TestFreshServer(t *testing.T) {
	Root = t.TempDir()
	defer func() { Root = "" }()
	if Pending() {
		t.Fatal("pending on a fresh server")
	}
	if notes, err := Migrate(true); err != nil || len(notes) != 0 {
		t.Fatal(notes, err)
	}
	if !DropLinks() || Pick(ConfDir, OldConfDir, "agent.json") != ConfDir {
		t.Fatal("fresh")
	}
}

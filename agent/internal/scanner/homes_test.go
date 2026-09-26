package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

// Accounts may live on several partitions (/home, /home2, /home3, …) and
// addon domains may have document roots outside public_html.
func TestUsersOnSeveralHomePartitions(t *testing.T) {
	dir := t.TempDir()
	h1, h2, h3 := filepath.Join(dir, "home", "alice"), filepath.Join(dir, "home2", "bob"), filepath.Join(dir, "home3", "carol")
	for _, h := range []string{h1, h2, h3} {
		os.MkdirAll(filepath.Join(h, "public_html"), 0o755)
	}
	addon := filepath.Join(h2, "addon.example")
	os.MkdirAll(addon, 0o755)
	passwd := filepath.Join(dir, "passwd")
	os.WriteFile(passwd, []byte("root:x:0:0::/root:/bin/bash\n"+
		"alice:x:1001:1001::"+h1+":/bin/bash\n"+
		"bob:x:1002:1002::"+h2+":/bin/bash\n"+
		"carol:x:1003:1003::"+h3+":/bin/bash\n"+
		"svc:x:1004:1004::/usr/lib/svc:/sbin/nologin\n"), 0o644)
	users := filepath.Join(dir, "cpusers")
	os.MkdirAll(users, 0o755)
	for _, u := range []string{"alice", "bob", "carol"} {
		os.WriteFile(filepath.Join(users, u), []byte("PLAN=default\n"), 0o644)
	}
	userdata := filepath.Join(dir, "userdata")
	os.MkdirAll(filepath.Join(userdata, "bob"), 0o755)
	os.WriteFile(filepath.Join(userdata, "bob", "addon.example"), []byte("---\ndocumentroot: "+addon+"\nservername: addon.example\n"), 0o644)
	os.WriteFile(filepath.Join(userdata, "bob", "main"), []byte("main_domain: bob.example\n"), 0o644)

	oldP, oldU, oldD := passwdFile, cpanelUsersDir, cpanelUserdata
	passwdFile, cpanelUsersDir, cpanelUserdata = passwd, users, userdata
	defer func() { passwdFile, cpanelUsersDir, cpanelUserdata = oldP, oldU, oldD }()

	got := map[string]string{}
	for _, u := range Users() {
		got[u.Name] = u.Home
	}
	if got["alice"] != h1 || got["bob"] != h2 || got["carol"] != h3 || len(got) != 3 {
		t.Fatalf("users %v", got)
	}
	roots := map[string]bool{}
	for _, r := range WebRoots() {
		roots[r] = true
	}
	for _, want := range []string{filepath.Join(h1, "public_html"), filepath.Join(h2, "public_html"), filepath.Join(h3, "public_html"), addon} {
		if !roots[want] {
			t.Errorf("web roots miss %s: %v", want, roots)
		}
	}

	// Without cPanel: any non-system home of a regular user counts.
	cpanelUsersDir = filepath.Join(dir, "none")
	got = map[string]string{}
	for _, u := range Users() {
		got[u.Name] = u.Home
	}
	if len(got) != 3 || got["svc"] != "" {
		t.Fatalf("plain users %v", got)
	}
}

func TestDevShmIsScanned(t *testing.T) {
	if systemPath("/dev/shm/x/y.php") || !systemPath("/dev/null") || !systemPath("/etc/passwd") {
		t.Fatal("systemPath")
	}
	if _, err := ValidateTarget("/dev/shm"); err != nil {
		t.Fatalf("/dev/shm rejected: %v", err)
	}
}

package panel

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fakeCPanel(t *testing.T) (root, log string) {
	root = t.TempDir()
	log = filepath.Join(root, "calls.log")
	t.Setenv("XG_CPANEL_ROOT", root)
	for _, d := range []string{"usr/local/cpanel/bin", "usr/local/cpanel/scripts", "usr/local/cpanel/base/frontend/jupiter", "var/cpanel/apps"} {
		os.MkdirAll(filepath.Join(root, d), 0o755)
	}
	os.WriteFile(filepath.Join(root, "usr/local/cpanel/version"), []byte("11.120\n"), 0o644)
	for _, tool := range []string{"bin/register_appconfig", "bin/unregister_appconfig", "scripts/install_plugin", "scripts/uninstall_plugin"} {
		script := "#!/bin/sh\necho \"$(basename $0) $*\" >> " + log + "\n"
		os.WriteFile(filepath.Join(root, "usr/local/cpanel", tool), []byte(script), 0o755)
	}
	return root, log
}

func TestInstallUninstall(t *testing.T) {
	root, log := fakeCPanel(t)
	if !Detected() || Installed() {
		t.Fatal("detection wrong before install")
	}
	done, err := Install()
	if err != nil || len(done) != 2 {
		t.Fatalf("install: %v %v", done, err)
	}
	if !Installed() {
		t.Fatal("not installed")
	}
	cgi, _ := os.Stat(filepath.Join(root, "usr/local/cpanel/whostmgr/docroot/cgi/xmartguard/index.cgi"))
	if cgi.Mode().Perm() != 0o700 {
		t.Fatalf("cgi mode %v", cgi.Mode())
	}
	php, _ := os.ReadFile(filepath.Join(root, "usr/local/cpanel/base/frontend/jupiter/xmartguard/index.live.php"))
	if !strings.Contains(string(php), "panel-api") {
		t.Fatal("php relay missing")
	}
	calls, _ := os.ReadFile(log)
	if !strings.Contains(string(calls), "register_appconfig") || !strings.Contains(string(calls), "install_plugin") {
		t.Fatalf("tools not run: %s", calls)
	}
	// Second install with no changes does not re-register.
	os.Remove(log)
	if _, err := Install(); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(log); len(b) != 0 {
		t.Fatalf("re-registered unchanged plugin: %s", b)
	}
	if err := Uninstall(); err != nil {
		t.Fatal(err)
	}
	calls, _ = os.ReadFile(log)
	if !strings.Contains(string(calls), "unregister_appconfig xmartguard") || !strings.Contains(string(calls), "uninstall_plugin") {
		t.Fatalf("uninstall tools not run: %s", calls)
	}
	for _, rel := range []string{"usr/local/cpanel/whostmgr/docroot/cgi/xmartguard", "usr/local/cpanel/base/frontend/jupiter/xmartguard", "var/cpanel/apps/xmartguard.conf"} {
		if _, err := os.Stat(filepath.Join(root, rel)); err == nil {
			t.Fatalf("%s left behind", rel)
		}
	}
}

func TestServeCGI(t *testing.T) {
	env := map[string]string{"REQUEST_METHOD": "GET", "REMOTE_USER": "root"}
	get := func(k string) string { return env[k] }
	var out bytes.Buffer
	ServeCGI("whm", false, false, get, strings.NewReader(""), &out)
	if !strings.HasPrefix(out.String(), "Content-Type: text/html") || !strings.Contains(out.String(), `var MODE = "whm"`) {
		t.Fatalf("page: %.200s", out.String())
	}
	env["REMOTE_USER"] = "reseller1"
	out.Reset()
	ServeCGI("whm", false, false, get, strings.NewReader(""), &out)
	if !strings.Contains(out.String(), "Status: 403") {
		t.Fatalf("reseller allowed: %s", out.String())
	}
	env["REMOTE_USER"] = "root"
	env["REQUEST_METHOD"] = "POST"
	env["CONTENT_TYPE"] = "application/x-www-form-urlencoded"
	out.Reset()
	ServeCGI("whm", false, false, get, strings.NewReader("a=b"), &out)
	if !strings.Contains(out.String(), "Status: 415") {
		t.Fatalf("form post accepted: %s", out.String())
	}
	t.Setenv("XG_SOCKET", filepath.Join(t.TempDir(), "none.sock"))
	env["CONTENT_TYPE"] = "application/json"
	env["CONTENT_LENGTH"] = "20"
	out.Reset()
	ServeCGI("whm", false, false, get, strings.NewReader(`{"action":"x"}      `), &out)
	if !strings.Contains(out.String(), "not running") {
		t.Fatalf("relay error: %s", out.String())
	}
	out.Reset()
	ServeCGI("cpanel", true, true, get, nil, &out)
	if strings.HasPrefix(out.String(), "Content-Type") || strings.Contains(out.String(), "<html") || !strings.Contains(out.String(), `var MODE = "cpanel"`) {
		t.Fatalf("fragment: %.200s", out.String())
	}
}

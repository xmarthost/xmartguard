package waf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A server set up before the xPGuard name: the old include is replaced by
// the new one in one step, and put back when the web server rejects it.
func TestInstallReplacesOldInclude(t *testing.T) {
	dir := t.TempDir()
	oldInc := filepath.Join(dir, "xmartguard_modsec.conf")
	hook := filepath.Join(dir, "modsec2.user.conf")
	os.WriteFile(oldInc, []byte("old"), 0o644)
	os.WriteFile(hook, []byte("SecRule other\nInclude \"/etc/xmartguard/waf/xmartguard_modsec.conf\"\n"), 0o644)
	tg := Target{Name: "cpanel", ModSec: true, IncludeFile: filepath.Join(dir, "xpguard_modsec.conf"), HookFile: hook,
		OldIncludes: []string{oldInc}, Engine: "On"}

	m := &Manager{RulesDir: filepath.Join(dir, "waf")}
	tg.configTest = []string{"false"}
	if err := m.install(tg, "SecRule new", nil); err == nil {
		t.Fatal("rejected config accepted")
	}
	if b, _ := os.ReadFile(oldInc); string(b) != "old" {
		t.Fatal("old include not restored")
	}
	if b, _ := os.ReadFile(hook); !strings.Contains(string(b), "xmartguard_modsec.conf") || exists(tg.IncludeFile) {
		t.Fatalf("hook not rolled back: %s", b)
	}

	tg.configTest, tg.reload = []string{"true"}, []string{"true"}
	if err := m.install(tg, "SecRule new", nil); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(hook)
	if exists(oldInc) || strings.Contains(string(b), "xmartguard") || strings.Count(string(b), tg.IncludeFile) != 1 || !strings.Contains(string(b), "SecRule other") {
		t.Fatalf("old include kept: %s", b)
	}
	inc, _ := os.ReadFile(tg.IncludeFile)
	if !strings.Contains(string(inc), filepath.Join(dir, "waf", "rules.conf")) {
		t.Fatalf("include: %s", inc)
	}
	RemoveInclude(tg)
	if b, _ := os.ReadFile(hook); strings.Contains(string(b), "Include") || exists(tg.IncludeFile) {
		t.Fatalf("not unhooked: %s", b)
	}
}

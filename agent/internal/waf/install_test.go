package waf

import (
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/settings"
	"github.com/xmarthost/xmartguard/agent/internal/store"
)

// Installs the rules into the real local Apache (Debian layout), checks
// that a bad bot is refused, then removes everything. Destructive: only on
// a disposable machine with XG_DESTRUCTIVE_TESTS=1.
func TestInstallIntoRealApache(t *testing.T) {
	if os.Getenv("XG_DESTRUCTIVE_TESTS") != "1" || os.Geteuid() != 0 {
		t.Skip("set XG_DESTRUCTIVE_TESTS=1 (as root) to run")
	}
	tg := Detect()
	if tg.Name != "debian" || !tg.ModSec {
		t.Skipf("needs Debian Apache with mod_security2, detected %+v", tg)
	}
	if exists(tg.IncludeFile) {
		t.Skip("an include already exists")
	}
	dir := t.TempDir()
	os.Chmod(dir, 0o755)
	os.Chmod(filepath.Dir(dir), 0o755)
	t.Setenv("XG_STATE_DIR", filepath.Join(dir, "state"))
	t.Setenv("XG_CONFIG_DIR", filepath.Join(dir, "conf"))
	db, _ := store.Open()
	defer db.Close()
	st, _ := settings.Load()
	if _, err := st.Patch([]byte(`{"waf":{"upload_scan":false,"block_php_upload":true,"webshell":true,"login_urls":["/wp-login.php","/my-login"],"whitelist_domains":["*.example.org"]}}`)); err != nil {
		t.Fatal(err)
	}
	m := &Manager{DB: db, Settings: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), RulesDir: filepath.Join(dir, "waf")}
	os.MkdirAll("/var/www/html", 0o755)
	os.WriteFile("/var/www/html/xg-ok.html", []byte("ok"), 0o644)
	defer os.Remove("/var/www/html/xg-ok.html")
	exec.Command("apache2ctl", "start").Run()
	defer exec.Command("apache2ctl", "stop").Run()
	defer func() {
		st.Patch([]byte(`{"waf":{"enabled":false}}`))
		m.Apply()
		exec.Command("a2disconf", "xmartguard-waf").Run()
		if exists(tg.IncludeFile) {
			t.Error("include left behind after disabling the WAF")
		}
	}()
	if err := m.Apply(); err != nil {
		t.Fatal(err)
	}
	if s := m.Status(); !s.Available || s.Error != "" || s.Panel != "debian" {
		t.Fatalf("status %+v", s)
	}
	time.Sleep(time.Second)
	getPath := func(path, ua string) int {
		req, _ := http.NewRequest("GET", "http://127.0.0.1"+path, nil)
		req.Header.Set("User-Agent", ua)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode
	}
	get := func(ua string) int { return getPath("/xg-ok.html", ua) }
	if c := get("Mozilla/5.0"); c != 200 {
		t.Fatalf("normal request %d", c)
	}
	if c := get("sqlmap/1.7"); c != 403 {
		t.Fatalf("bad bot not blocked: %d", c)
	}
	if c := getPath("/wp-content/wso.php", "Mozilla/5.0"); c != 403 {
		t.Fatalf("web shell request not blocked: %d", c)
	}
	// A rule that makes the config invalid must be rolled back.
	st.Patch([]byte(`{"waf":{"custom_bots":["okbot"]}}`))
	orig := m.RulesDir
	m.RulesDir = "/nonexistent\"dir"
	if err := m.Apply(); err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("broken config not rolled back: %v", err)
	}
	m.RulesDir = orig
	if c := get("Mozilla/5.0"); c != 200 {
		t.Fatalf("site down after rollback: %d", c)
	}
	// Deleting the rules (e.g. /etc/xmartguard removed by hand) must not
	// break Apache: the include is optional.
	os.RemoveAll(m.RulesDir)
	if out, err := exec.Command("apache2ctl", "-t").CombinedOutput(); err != nil {
		t.Fatalf("apache config broken without the rules dir: %s", out)
	}
	// The uninstaller's cleanup unhooks the include.
	RemoveInclude(Detect())
	if exists(tg.IncludeFile) || exists("/etc/apache2/conf-enabled/xmartguard-waf.conf") {
		t.Fatal("RemoveInclude left files behind")
	}
}

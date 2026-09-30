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

func TestCentralRuleRender(t *testing.T) {
	c := settings.Defaults().WAF
	c.LoginURLs = []string{"/wp-login.php"}
	ct := &Central{URL: "https://captcha.xpguard.org/v", ServerID: "15d69a72-653a-47b6-90f6-fde737bce061"}
	out := Render(c, Options{Dir: "/etc/xpguard/waf", Central: ct})
	for _, want := range []string{
		"id:7700904", "redirect:https://captcha.xpguard.org/v?s=15d69a72-653a-47b6-90f6-fde737bce061&ip=%{REMOTE_ADDR}&h=%{REQUEST_HEADERS.Host}&u=%{REQUEST_URI}",
		`"@ipMatchFromFile /etc/xpguard/waf/captcha-suspects.txt"`, `"!@ipMatchFromFile /etc/xpguard/waf/captcha-pass.txt"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
	// Everyone (the login-page CAPTCHA for everyone): no suspect list.
	all := Render(c, Options{Dir: "/x", Central: &Central{URL: ct.URL, ServerID: ct.ServerID, All: true}})
	if !strings.Contains(all, "id:7700904") || strings.Contains(all, FileCaptchaSuspects) || !strings.Contains(all, FileCaptchaPass) {
		t.Fatalf("all visitors:\n%s", all)
	}
	// The server's own login-page CAPTCHA, when it is used, wins.
	if out := Render(c, Options{Dir: "/x", Central: ct, Gate: &Gate{Tokens: []string{"0123456789abcdef"}, HTTPSPort: 7743}}); strings.Contains(out, "7700904") {
		t.Error("central rule rendered together with the gate")
	}
	// A bad URL or server id never reaches the rules.
	for _, bad := range []*Central{{URL: "http://x.org/v", ServerID: ct.ServerID}, {URL: ct.URL + "\",deny", ServerID: ct.ServerID}, {URL: ct.URL, ServerID: "x y"}} {
		if out := Render(c, Options{Dir: "/x", Central: bad}); strings.Contains(out, "7700904") {
			t.Errorf("rendered with %+v", bad)
		}
	}
	f := CentralFiles(&Central{Suspects: []string{"203.0.113.9", "2001:db8::/32"}})
	if f[FileCaptchaSuspects] != "203.0.113.9\n2001:db8::/32\n" || f[FileCaptchaPass] != placeholderIP+"\n" {
		t.Fatalf("files %q", f)
	}
}

// On a real Apache with ModSecurity: a suspect is redirected to the CAPTCHA
// page from the login page only, and passes once on the pass list.
func TestCentralRuleOnApache(t *testing.T) {
	if os.Getenv("XG_DESTRUCTIVE_TESTS") != "1" || os.Geteuid() != 0 {
		t.Skip("set XG_DESTRUCTIVE_TESTS=1 (as root) to run")
	}
	tg := Detect()
	if tg.Name != "debian" || !tg.ModSec || exists(tg.IncludeFile) {
		t.Skipf("needs Debian Apache with mod_security2 and no include, detected %+v", tg)
	}
	dir := t.TempDir()
	os.Chmod(dir, 0o755)
	os.Chmod(filepath.Dir(dir), 0o755)
	t.Setenv("XG_STATE_DIR", filepath.Join(dir, "state"))
	t.Setenv("XG_CONFIG_DIR", filepath.Join(dir, "conf"))
	db, _ := store.Open()
	defer db.Close()
	st, _ := settings.Load()
	st.Patch([]byte(`{"waf":{"upload_scan":false,"login_urls":["/wp-login.php"]}}`))
	central := &Central{URL: "https://captcha.xpguard.org/v", ServerID: "15d69a72-653a-47b6-90f6-fde737bce061", Suspects: []string{"127.0.0.1"}}
	m := &Manager{DB: db, Settings: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), RulesDir: filepath.Join(dir, "waf"),
		NoSelfTest: true, Central: func() *Central { return central }}
	os.MkdirAll("/var/www/html", 0o755)
	os.WriteFile("/var/www/html/wp-login.php", []byte("login"), 0o644)
	os.WriteFile("/var/www/html/xg-ok.html", []byte("ok"), 0o644)
	defer os.Remove("/var/www/html/wp-login.php")
	defer os.Remove("/var/www/html/xg-ok.html")
	exec.Command("apache2ctl", "start").Run()
	defer exec.Command("apache2ctl", "stop").Run()
	defer func() {
		st.Patch([]byte(`{"waf":{"enabled":false}}`))
		m.Apply()
		exec.Command("a2disconf", "xpguard-waf").Run()
	}()
	if err := m.Apply(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	get := func(path string) (int, string) {
		req, _ := http.NewRequest("GET", "http://127.0.0.1"+path, nil)
		req.Host = "shop.example.com"
		req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) Firefox/130.0")
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode, res.Header.Get("Location")
	}
	code, loc := get("/wp-login.php?redirect_to=/wp-admin/&reauth=1")
	want := "https://captcha.xpguard.org/v?s=15d69a72-653a-47b6-90f6-fde737bce061&ip=127.0.0.1&h=shop.example.com&u=/wp-login.php?redirect_to=/wp-admin/&reauth=1"
	if code != 302 || loc != want {
		t.Fatalf("suspect on the login page: %d %q", code, loc)
	}
	if code, _ := get("/xg-ok.html"); code != 200 {
		t.Fatalf("suspect on another page: %d", code)
	}
	// Solved: on the pass list.
	central.Pass = []string{"127.0.0.1"}
	if !m.CentralChanged() {
		t.Fatal("pass list change not noticed")
	}
	if err := m.Apply(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second)
	if code, _ := get("/wp-login.php"); code != 200 {
		t.Fatalf("passed visitor still sent to the CAPTCHA: %d", code)
	}
	// Not a suspect any more.
	central.Pass, central.Suspects = nil, nil
	m.Apply()
	time.Sleep(time.Second)
	if code, _ := get("/wp-login.php"); code != 200 {
		t.Fatalf("normal visitor sent to the CAPTCHA: %d", code)
	}
}

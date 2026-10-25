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

// Hostname mode: suspects go to the check on this server's own hostname
// (port 443), and that page is not inspected.
func TestHostPageRedirect(t *testing.T) {
	c := &Central{URL: "https://captcha.xpguard.org/v", ServerID: "15d69a72-653a-47b6-90f6-fde737bce061", Suspects: []string{"203.0.113.9"},
		HostPage: "https://server1.example.net/xpguard-check/"}
	conf := Render(settings.WAF{LoginURLs: []string{"/wp-login.php"}}, Options{Dir: "/etc/xg", Central: c})
	for _, want := range []string{
		"redirect:https://server1.example.net/xpguard-check/?s=15d69a72-653a-47b6-90f6-fde737bce061&ip=%{REMOTE_ADDR}&h=%{REQUEST_HEADERS.Host}&u=%{REQUEST_URI}",
		`"id:7700068,phase:1,t:none,t:lowercase,pass,nolog,ctl:ruleEngine=Off,chain"`, `SecRule SERVER_NAME "@streq server1.example.net"`,
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(conf, "redirect:https://captcha.xpguard.org/v") {
		t.Error("still sent to the portal address")
	}
	// A bad address never reaches the rules: the portal address instead.
	for _, bad := range []string{"https://server1.example.net/other/", "http://server1.example.net/xpguard-check/", "https://a b/xpguard-check/", `https://x"y.com/xpguard-check/`} {
		c.HostPage = bad
		conf := Render(settings.WAF{LoginURLs: []string{"/wp-login.php"}}, Options{Dir: "/etc/xg", Central: c})
		if !strings.Contains(conf, "redirect:https://captcha.xpguard.org/v?") || strings.Contains(conf, "id:7700068") {
			t.Errorf("%q used", bad)
		}
	}
}

func TestHostPageOnApache(t *testing.T) {
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
	central := &Central{URL: "https://captcha.xpguard.org/v", ServerID: "15d69a72-653a-47b6-90f6-fde737bce061", Suspects: []string{"127.0.0.1"},
		HostPage: "https://server1.example.net/xpguard-check/"}
	m := &Manager{DB: db, Settings: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), RulesDir: filepath.Join(dir, "waf"),
		NoSelfTest: true, Central: func() *Central { return central }}
	os.MkdirAll("/var/www/html/xpguard-check", 0o755)
	os.WriteFile("/var/www/html/wp-login.php", []byte("login"), 0o644)
	os.WriteFile("/var/www/html/xpguard-check/index.html", []byte("hostname page"), 0o644)
	defer os.Remove("/var/www/html/wp-login.php")
	defer os.RemoveAll("/var/www/html/xpguard-check")
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
	get := func(host, path string) (int, string) {
		req, _ := http.NewRequest("GET", "http://127.0.0.1"+path, nil)
		req.Host = host
		req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) Firefox/130.0")
		req.Header.Set("Accept", "text/html,*/*;q=0.8")
		var res *http.Response
		var err error
		for i := 0; i < 20; i++ {
			if res, err = client.Do(req); err == nil {
				break
			}
			time.Sleep(250 * time.Millisecond)
		}
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode, res.Header.Get("Location")
	}
	code, loc := get("shop.example.com", "/wp-login.php?redirect_to=/wp-admin/")
	if want := "https://server1.example.net/xpguard-check/?s=15d69a72-653a-47b6-90f6-fde737bce061&ip=127.0.0.1&h=shop.example.com&u=/wp-login.php?redirect_to=/wp-admin/"; code != 302 || loc != want {
		t.Fatalf("suspect: %d %q", code, loc)
	}
	// The page on the hostname opens (the link holds a page that looks like
	// an attack to rule sets; it is not inspected there).
	if code, _ := get("server1.example.net", "/xpguard-check/?s=x&ip=127.0.0.1&h=shop.example.com&u=/wp-login.php?redirect_to=/wp-admin/"); code != 200 {
		t.Fatalf("hostname page: %d", code)
	}
}

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

// Site mode without port 7743 (2026-11-06): suspects go to the check's
// page on the website they opened, port 443; that page is not inspected,
// and a path that only starts like it (../ or encoded) still is.
func TestSitePageRedirect(t *testing.T) {
	ct := &Central{URL: "https://captcha.xpguard.org/v", ServerID: "15d69a72-653a-47b6-90f6-fde737bce061", Suspects: []string{"203.0.113.9"}, SitePage: true}
	conf := Render(settings.WAF{LoginURLs: []string{"/wp-login.php"}}, Options{Dir: "/etc/xg", Central: ct})
	for _, want := range []string{
		"redirect:https://%{REQUEST_HEADERS.Host}/xpguard-verify/?s=15d69a72-653a-47b6-90f6-fde737bce061&ip=%{REMOTE_ADDR}&h=%{REQUEST_HEADERS.Host}&u=%{REQUEST_URI}",
		`SecRule REQUEST_FILENAME "@beginsWith /xpguard-verify/" "id:7700073,phase:1,t:none,t:urlDecodeUni,t:normalizePath,t:lowercase,pass,nolog,ctl:ruleEngine=Off"`,
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(conf, "redirect:https://captcha.xpguard.org/v") || strings.Contains(conf, "&g=") {
		t.Error("still sent to the portal or the CAPTCHA port")
	}
	// No pass values: the pass list only.
	if strings.Contains(conf, "xg_gate=") {
		t.Error("cookie rules without pass values")
	}
	// With the pass values: a pass cookie the page set lets the visitor in
	// at once (no web server reload), and its use is reported.
	tok := "0123456789abcdef0123456789abcdef"
	ct.Slots = [][]string{{tok}, {"fedcba9876543210fedcba9876543210"}}
	conf = Render(settings.WAF{LoginURLs: []string{"/wp-login.php"}}, Options{Dir: "/etc/xg", Central: ct})
	for _, want := range []string{
		`SecRule &REQUEST_HEADERS:Cookie "@eq 0" "t:none,chain"`,
		`SecRule REQUEST_HEADERS:Cookie "!@rx (?:^|;)\s*xg_gate=(?:` + tok + `|fedcba9876543210fedcba9876543210)\s*(?:;|$)" "t:none,chain"`,
		`SecRule REMOTE_ADDR "!@ipMatchFromFile /etc/xg/captcha-pass.txt" "t:none`,
		"msg:'xPGuard - CAPTCHA pass cookie used'",
		"redirect:https://%{REQUEST_HEADERS.Host}/xpguard-verify/?",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(conf, "&g=") {
		t.Error("sent to the CAPTCHA port")
	}
	// The page not working: the port mode, as before (the agent sets Site).
	ct.SitePage, ct.Site, ct.HTTPSPort = false, true, 7743
	conf = Render(settings.WAF{LoginURLs: []string{"/wp-login.php"}}, Options{Dir: "/etc/xg", Central: ct})
	if !strings.Contains(conf, "&g=7743&u=") || strings.Contains(conf, "id:7700073") {
		t.Error("port mode changed")
	}
	if SitePagePath != "/xpguard-verify/" {
		t.Error("path differs from captcha.SitePagePath")
	}
}

// The alias file is written only when wanted, switched off (not removed)
// after, and per platform where xPGuard writes Apache configuration.
func TestSiteAliasPath(t *testing.T) {
	for name, want := range map[string]string{"cpanel": "/etc/apache2/conf.d/xpguard-verify.conf", "rhel": "/etc/httpd/conf.d/xpguard-verify.conf",
		"debian": "/etc/apache2/conf-enabled/xpguard-verify.conf", "": ""} {
		if got := SiteAliasPath(Target{Name: name}); got != want {
			t.Errorf("%q: %q", name, got)
		}
	}
}

// On Apache: the alias serves the page on every website (any Host), the
// suspect is sent there, and the page's link (holding a page that looks
// like an attack) is not blocked.
func TestSitePageOnApache(t *testing.T) {
	if os.Getenv("XG_DESTRUCTIVE_TESTS") != "1" || os.Geteuid() != 0 {
		t.Skip("set XG_DESTRUCTIVE_TESTS=1 (as root) to run")
	}
	tg := Detect()
	if tg.Name != "debian" || !tg.ModSec || exists(tg.IncludeFile) {
		t.Skipf("needs Debian Apache with mod_security2 and no include, detected %+v", tg)
	}
	alias := SiteAliasPath(tg)
	dir := t.TempDir()
	os.Chmod(dir, 0o755)
	os.Chmod(filepath.Dir(dir), 0o755)
	pageDir := filepath.Join(dir, "verify")
	os.MkdirAll(pageDir, 0o755)
	os.WriteFile(filepath.Join(pageDir, "index.html"), []byte("site page"), 0o644)
	os.WriteFile(filepath.Join(pageDir, "x.php"), []byte("<?php echo 1;"), 0o644)
	conf := "Alias /xpguard-verify/ " + pageDir + "/\n<Directory \"" + pageDir + "\">\n    Options None\n    AllowOverride None\n    DirectoryIndex index.html\n    Require all granted\n" +
		"    <FilesMatch \"\\.(?i:php\\d?|phtml|phar|cgi|pl|py|sh)$\">\n        Require all denied\n    </FilesMatch>\n</Directory>\n"
	t.Setenv("XG_STATE_DIR", filepath.Join(dir, "state"))
	t.Setenv("XG_CONFIG_DIR", filepath.Join(dir, "conf"))
	db, _ := store.Open()
	defer db.Close()
	st, _ := settings.Load()
	st.Patch([]byte(`{"waf":{"upload_scan":false,"login_urls":["/wp-login.php"]}}`))
	tok := "0123456789abcdef0123456789abcdef"
	central := &Central{URL: "https://captcha.xpguard.org/v", ServerID: "15d69a72-653a-47b6-90f6-fde737bce061", Suspects: []string{"127.0.0.1"}, SitePage: true,
		Slots: [][]string{{tok}, {"fedcba9876543210fedcba9876543210"}}}
	on := true
	m := &Manager{DB: db, Settings: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), RulesDir: filepath.Join(dir, "waf"),
		NoSelfTest: true, Central: func() *Central { return central },
		SiteAlias: func() (string, bool) {
			if on {
				return conf, true
			}
			return "# off\n", false
		}}
	os.MkdirAll("/var/www/html", 0o755)
	os.WriteFile("/var/www/html/wp-login.php", []byte("login"), 0o644)
	defer os.Remove("/var/www/html/wp-login.php")
	defer os.Remove(alias)
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
	if b, _ := os.ReadFile(alias); string(b) != conf {
		t.Fatal("alias not written")
	}
	time.Sleep(time.Second)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	cookie := ""
	get := func(host, path string) (int, string, string) {
		req, _ := http.NewRequest("GET", "http://127.0.0.1"+path, nil)
		req.Host = host
		if cookie != "" {
			req.Header.Set("Cookie", cookie)
		}
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
		b, _ := io.ReadAll(res.Body)
		res.Body.Close()
		return res.StatusCode, res.Header.Get("Location"), string(b)
	}
	code, loc, _ := get("shop.example.com", "/wp-login.php?redirect_to=/wp-admin/")
	if want := "https://shop.example.com/xpguard-verify/?s=15d69a72-653a-47b6-90f6-fde737bce061&ip=127.0.0.1&h=shop.example.com&u=/wp-login.php?redirect_to=/wp-admin/"; code != 302 || loc != want {
		t.Fatalf("suspect: %d %q", code, loc)
	}
	for _, host := range []string{"shop.example.com", "other.example.org"} {
		if code, _, body := get(host, "/xpguard-verify/?s=x&ip=127.0.0.1&h="+host+"&u=/wp-login.php?redirect_to=/wp-admin/&a=<script>"); code != 200 || body != "site page" {
			t.Fatalf("%s: page %d %q", host, code, body)
		}
	}
	if code, _, body := get("shop.example.com", "/xpguard-verify/x.php"); code != 403 || strings.Contains(body, "echo") {
		t.Fatalf("script in the page folder: %d", code)
	}
	// The pass cookie the page sets: in at once, no reload; a wrong one not.
	cookie = "wordpress_test_cookie=1; xg_gate=" + tok
	if code, loc, body := get("shop.example.com", "/wp-login.php?redirect_to=/wp-admin/"); code != 200 || body != "login" {
		t.Fatalf("with the pass cookie: %d %q", code, loc)
	}
	cookie = "xg_gate=ffffffffffffffffffffffffffffffff"
	if code, _, _ := get("shop.example.com", "/wp-login.php"); code != 302 {
		t.Fatalf("with a wrong pass cookie: %d", code)
	}
	cookie = ""
	// A path that only starts with the page's is still inspected.
	if code, loc, _ := get("shop.example.com", "/xpguard-verify/../wp-login.php"); code != 302 || !strings.Contains(loc, "/xpguard-verify/?s=") {
		t.Fatalf("../ past the page: %d %q", code, loc)
	}

	// Switched off: the file stays with the off text.
	on = false
	central.SitePage = false
	if err := m.Apply(); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(alias); string(b) != "# off\n" {
		t.Fatalf("alias not switched off: %q", b)
	}
}

package waf

import (
	"fmt"
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

// A password-guessing attack spread over many addresses (one per few
// attempts, as botnets and VPNs rotate) never reached the per-address ban
// threshold: 22 attempts from 6 addresses on websoulhost.com in 3 minutes,
// none banned. The login page of such a website now asks every visitor for
// the CAPTCHA.
func TestSiteAttackRule(t *testing.T) {
	if got := AttackSites([]string{"WWW.Shop.Example.com", "websoulhost.com.", "shop.example.com", "bad host!", "a|b.com", "localhost"}); strings.Join(got, ",") != "shop.example.com,websoulhost.com" {
		t.Fatalf("sites: %v", got)
	}
	c := &Central{URL: "https://captcha.xpguard.org/v", ServerID: "15d69a72-653a-47b6-90f6-fde737bce061", Suspects: []string{"203.0.113.9"},
		Sites: []string{"websoulhost.com", "shop.example.com"}, SiteLoginURLs: []string{"/wp-login.php", "/client-area/login"}}
	if f := CentralFiles(c, nil)[FileCaptchaSites]; f != "shop.example.com\nwebsoulhost.com\n" {
		t.Fatalf("sites file %q", f)
	}
	conf := Render(settings.WAF{LoginURLs: []string{"/wp-login.php", "/xmlrpc.php", "/client-area/login"}}, Options{Dir: "/etc/xg", Central: c})
	mark := strings.Index(conf, "id:7700067")
	gate := strings.Index(conf, "suspicious visitor sent to the CAPTCHA")
	if mark < 0 || gate < 0 || mark > gate {
		t.Fatalf("site mark %d, gate %d:\n%s", mark, gate, conf)
	}
	for _, want := range []string{`SecRule SERVER_NAME "@rx ^(?:www\.)?(?:shop\.example\.com|websoulhost\.com)\.?$"`, `(?:/wp-login\.php|/client-area/login)(?:/|$)`} {
		if !strings.Contains(conf, want) {
			t.Errorf("missing %q", want)
		}
	}
	// The login page for everyone already: no site rule.
	c.All = true
	if strings.Contains(Render(settings.WAF{LoginURLs: []string{"/wp-login.php"}}, Options{Dir: "/etc/xg", Central: c}), "id:7700067") {
		t.Error("site rule with the CAPTCHA for everyone")
	}
	c.All = false
	c.Sites = nil
	if strings.Contains(Render(settings.WAF{LoginURLs: []string{"/wp-login.php"}}, Options{Dir: "/etc/xg", Central: c}), "id:7700067") {
		t.Error("site rule without sites")
	}

	// A new site on the list makes the agent reload at once; one leaving
	// waits for the 10-minute refresh.
	dir := t.TempDir()
	t.Setenv("XG_CONFIG_DIR", filepath.Join(dir, "conf"))
	st, _ := settings.Load()
	m := &Manager{Settings: st, RulesDir: dir}
	os.WriteFile(filepath.Join(dir, FileCaptchaSites), []byte("websoulhost.com\n"), 0o644)
	if m.CentralSitesAdded([]string{"websoulhost.com"}) || m.CentralSitesAdded(nil) {
		t.Error("no new site, reload asked")
	}
	if !m.CentralSitesAdded([]string{"www.websoulhost.com", "shop.example.com"}) {
		t.Error("new site not noticed")
	}
}

// business200 lists /wp-admin as a protected login URL. Every POST of a
// logged-in admin's screens there (admin-ajax.php: heartbeat, autosave)
// answers 200 and was counted as a failed login: site owners on iCloud
// Private Relay were banned after 10 and could not pass the CAPTCHA again,
// and their own site went into login attack mode. The admin folder is no
// login page (wp-login.php is): it is neither counted nor gated.
func TestWPAdminIsNoLoginPage(t *testing.T) {
	if got := LoginPages([]string{"/wp-admin", "/WP-Admin/", "/wp-admin/admin-ajax.php", "/members/login.php", "/wp-login.php"}); strings.Join(got, ",") != "/members/login.php,/wp-login.php" {
		t.Fatalf("login pages: %v", got)
	}
	c := settings.Defaults().WAF
	c.Enabled, c.BruteForce, c.WordPress = true, true, true
	c.LoginURLs = []string{"/wp-login.php", "/wp-admin", "/members/login.php"}
	central := &Central{URL: "https://captcha.xpguard.org/v", ServerID: "15d69a72-653a-47b6-90f6-fde737bce061", Suspects: []string{"203.0.113.9"}}
	out := Render(c, Options{Dir: "/r", Central: central})
	for _, id := range []int{IDLoginCustom, IDCentralGate, IDCentralNoBrowser} {
		ch := chainOf(out, id)
		if len(ch) < 2 {
			t.Fatalf("rule %d missing:\n%s", id, out)
		}
		path := ch[0]
		if id == IDLoginCustom {
			path = ch[1]
		}
		re := rxOf(t, path)
		if re.MatchString("/wp-admin/admin-ajax.php") || re.MatchString("/wp-admin/post.php") || re.MatchString("/wp-admin/") {
			t.Errorf("rule %d counts or gates the admin folder: %s", id, path)
		}
		if !re.MatchString("/members/login.php") {
			t.Errorf("rule %d lost the protected login URL: %s", id, path)
		}
	}
	// Only the admin folder listed: no protected-URL counter at all.
	c.LoginURLs = []string{"/wp-admin/"}
	if strings.Contains(Render(c, Options{Dir: "/r"}), fmt.Sprintf("id:%d,", IDLoginCustom)) {
		t.Error("counter for the admin folder")
	}
}

func TestSiteAttackOnApache(t *testing.T) {
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
	st.Patch([]byte(`{"waf":{"upload_scan":false,"login_urls":["/wp-login.php","/xmlrpc.php"]}}`))
	// 127.0.0.1 is no suspect: only the site is under attack.
	central := &Central{URL: "https://captcha.xpguard.org/v", ServerID: "15d69a72-653a-47b6-90f6-fde737bce061", Suspects: []string{"203.0.113.9"},
		Sites: []string{"websoulhost.com"}, SiteLoginURLs: []string{"/wp-login.php"}}
	m := &Manager{DB: db, Settings: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), RulesDir: filepath.Join(dir, "waf"),
		NoSelfTest: true, Central: func() *Central { return central }}
	os.MkdirAll("/var/www/html", 0o755)
	for _, f := range []string{"wp-login.php", "xmlrpc.php", "xg-ok.html"} {
		os.WriteFile("/var/www/html/"+f, []byte("ok"), 0o644)
		defer os.Remove("/var/www/html/" + f)
	}
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
	get := func(host, path, accept string) (int, string) {
		req, _ := http.NewRequest("GET", "http://127.0.0.1"+path, nil)
		req.Host = host
		req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) Firefox/130.0")
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
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
	html := "text/html,*/*;q=0.8"
	if code, loc := get("www.websoulhost.com", "/wp-login.php", html); code != 302 || !strings.HasPrefix(loc, "https://captcha.xpguard.org/v?") || !strings.Contains(loc, "&h=www.websoulhost.com&") {
		t.Fatalf("visitor of the attacked site's login page: %d %q", code, loc)
	}
	if code, _ := get("websoulhost.com", "/wp-login.php", "*/*"); code != 403 {
		t.Fatalf("script on the attacked site's login page: %d", code)
	}
	// The WAF self-test's probe of a login or admin save is not gated
	// (business600, 2026-10-31: the Joomla lift probe got the gate's 403).
	if code, _ := get("websoulhost.com", crsTestPath+"/wp-login.php", "*/*"); code != 404 {
		t.Fatalf("self-test probe on the attacked site's login path: %d", code)
	}
	// Its other pages, xmlrpc.php (apps), and other sites stay as they are.
	for _, c := range [][2]string{{"websoulhost.com", "/xg-ok.html"}, {"shop.example.com", "/wp-login.php"}, {"evilwebsoulhost.com", "/wp-login.php"}} {
		if code, _ := get(c[0], c[1], html); code != 200 {
			t.Fatalf("%s%s: %d", c[0], c[1], code)
		}
	}
	// (A GET of xmlrpc.php is refused by its own rule, 7700307: not sent
	// to the CAPTCHA.)
	if code, loc := get("websoulhost.com", "/xmlrpc.php", html); code == 302 || loc != "" {
		t.Fatalf("xmlrpc.php sent to the CAPTCHA: %d %q", code, loc)
	}
	// Solved: on the pass list.
	central.Pass = []string{"127.0.0.1"}
	if err := m.Apply(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second)
	if code, _ := get("websoulhost.com", "/wp-login.php", html); code != 200 {
		t.Fatalf("passed visitor: %d", code)
	}
	// The attack is over.
	central.Pass, central.Sites = nil, nil
	if err := m.Apply(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second)
	if code, _ := get("websoulhost.com", "/wp-login.php", html); code != 200 {
		t.Fatalf("after the attack: %d", code)
	}
}

package waf

import (
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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
	f := CentralFiles(&Central{Suspects: []string{"203.0.113.9", "2001:db8::/32"}}, nil)
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
	accept := "text/html,application/xhtml+xml,*/*;q=0.8"
	get := func(path string) (int, string) {
		req, _ := http.NewRequest("GET", "http://127.0.0.1"+path, nil)
		req.Host = "shop.example.com"
		req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) Firefox/130.0")
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
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
	// Not a browser (xmlrpc-style clients, scripts, no Accept at all): a 403, no redirect.
	for _, a := range []string{"*/*", "application/json", ""} {
		accept = a
		if code, loc := get("/wp-login.php"); code != 403 || loc != "" {
			t.Fatalf("non-browser suspect (Accept %q): %d %q", a, code, loc)
		}
	}
	accept = "text/html,*/*"
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

// On the website's own address: suspects go to this server's CAPTCHA port
// and pass with the cookie, without a reload (checked on a real Apache).
func TestCentralSiteMode(t *testing.T) {
	c := settings.Defaults().WAF
	c.LoginURLs = []string{"/wp-login.php"}
	tok := "0123456789abcdef0123456789abcdef"
	ct := &Central{URL: "https://captcha.xpguard.org/v", ServerID: "15d69a72-653a-47b6-90f6-fde737bce061", Site: true, Slots: [][]string{{tok}, {"fedcba9876543210fedcba9876543210"}}, HTTPSPort: 7743}
	out := Render(c, Options{Dir: "/etc/xpguard/waf", Central: ct})
	for _, want := range []string{
		"id:7700904", "id:7700907", "id:7700906", "id:7700908",
		// Through the portal's page, which sends a browser that reaches the
		// CAPTCHA port on to it (roxannebradley.online: refused on :7743).
		"redirect:https://captcha.xpguard.org/v?s=15d69a72-653a-47b6-90f6-fde737bce061&ip=%{REMOTE_ADDR}&h=%{REQUEST_HEADERS.Host}&g=7743&u=%{REQUEST_URI}",
		`  SecRule REMOTE_ADDR "!@ipMatchFromFile /etc/xpguard/waf/captcha-pass.txt" "t:none,chain"`,
		`SecRule &REQUEST_HEADERS:Cookie "@eq 0" "t:none,chain"`, `SecRule REQUEST_HEADERS:Cookie "!@rx (?:^|;)\s*xg_gate=(?:` + tok + `|fedcba9876543210fedcba9876543210)\s*(?:;|$)" "t:none,chain"`,
		// Which value a suspect sends, one rule per slot (shared passes).
		"id:7700910,phase:1,t:none,t:urlDecodeUni,t:normalizePath,t:lowercase,pass,log,msg:'xPGuard - CAPTCHA pass cookie used'", "id:7700911,",
		`SecRule REQUEST_HEADERS:Cookie "@rx (?:^|;)\s*xg_gate=(?:fedcba9876543210fedcba9876543210)\s*(?:;|$)" "t:none"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(out, "/.xpguard/gate?back=") {
		t.Error("site mode still sends to the CAPTCHA port directly")
	}
	// No valid token or port: portal mode.
	if out := Render(c, Options{Dir: "/x", Central: &Central{URL: ct.URL, ServerID: ct.ServerID, Site: true, Slots: [][]string{{"bad token"}}, HTTPSPort: 7743}}); !strings.Contains(out, "captcha.xpguard.org/v?s=") || strings.Contains(out, "&g=") {
		t.Error("site mode without a token")
	}

	if os.Getenv("XG_DESTRUCTIVE_TESTS") != "1" || os.Geteuid() != 0 {
		t.Skip("set XG_DESTRUCTIVE_TESTS=1 (as root) for the Apache part")
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
	ct.Suspects = []string{"127.0.0.1"}
	m := &Manager{DB: db, Settings: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), RulesDir: filepath.Join(dir, "waf"),
		NoSelfTest: true, Central: func() *Central { return ct }}
	os.MkdirAll("/var/www/html", 0o755)
	os.WriteFile("/var/www/html/wp-login.php", []byte("login"), 0o644)
	defer os.Remove("/var/www/html/wp-login.php")
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
	getPath := func(path, cookie string) (int, string) {
		req, _ := http.NewRequest("GET", "http://127.0.0.1"+path, nil)
		req.Host = "shop.example.com"
		req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) Firefox/130.0")
		req.Header.Set("Accept", "text/html,*/*")
		if cookie != "" {
			req.Header.Set("Cookie", cookie)
		}
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode, res.Header.Get("Location")
	}
	get := func(cookie string) (int, string) {
		return getPath("/wp-login.php?redirect_to=/wp-admin/&reauth=1", cookie)
	}
	want := "https://captcha.xpguard.org/v?s=15d69a72-653a-47b6-90f6-fde737bce061&ip=127.0.0.1&h=shop.example.com&g=7743&u=/wp-login.php?redirect_to=/wp-admin/&reauth=1"
	// The login page reached through PATH_INFO or an encoded name is the
	// same login page (PHP runs wp-login.php for /wp-login.php/x).
	for _, p := range []string{"/wp-login.php/x", "/wp-login.php/", "/wp%2dlogin.php", "//WP-LOGIN.php"} {
		if code, loc := getPath(p, ""); code != 302 || !strings.HasPrefix(loc, "https://captcha.xpguard.org/v?s=") || !strings.Contains(loc, "&g=7743&u=") {
			t.Fatalf("suspect on %s: %d %q", p, code, loc)
		}
	}
	// A cookie value that is not one of the accepted ones, or one glued to
	// more text, does not pass.
	for _, cookie := range []string{"xg_gate=" + tok + "0", "xg_gate=0" + tok, "axg_gate=" + tok, "xg_gate=" + strings.ToUpper(tok)} {
		if code, _ := get(cookie); code != 302 {
			t.Fatalf("forged cookie %q: %d", cookie, code)
		}
	}
	for _, cookie := range []string{"", "wordpress_test_cookie=WP+Cookie+check", "xg_gate=ffffffffffffffffffffffffffffffff"} {
		if code, loc := get(cookie); code != 302 || loc != want {
			t.Fatalf("suspect with cookie %q: %d %q", cookie, code, loc)
		}
	}
	// The pass cookie lets the visitor in at once: no reload in between.
	for _, cookie := range []string{"xg_gate=" + tok, "wordpress_test_cookie=WP+Cookie+check; xg_gate=" + tok} {
		if code, _ := get(cookie); code != 200 {
			t.Fatalf("passed visitor (%q) still sent to the CAPTCHA: %d", cookie, code)
		}
	}
	// The web server's log says which value the suspect sent, as an event
	// the agent reads (it withdraws values sent from other addresses).
	time.Sleep(300 * time.Millisecond)
	logb, _ := os.ReadFile("/var/log/apache2/error.log")
	seen := false
	for _, l := range strings.Split(string(logb), "\n") {
		if ev, ok := ParseLine(l); ok && CentralPassSlot(ev.RuleID) == 0 && ev.IP == "127.0.0.1" {
			seen = true
		}
	}
	if !seen {
		t.Fatal("no pass-cookie event in the web server's log")
	}
	// Solved on the portal (the CAPTCHA port was out of reach): the address
	// is let in without a cookie, as in portal mode.
	ct.Pass = []string{"127.0.0.1"}
	if err := m.Apply(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second)
	if code, _ := get(""); code != 200 {
		t.Fatalf("address passed on the portal still sent to the CAPTCHA: %d", code)
	}
}

// PHP runs /wp-login.php for /wp-login.php/anything (PATH_INFO), so the
// login, XML-RPC and comment rules match the script name with any path
// after it, and decoded (/wp%2dlogin.php).
func TestLoginRulesPathInfo(t *testing.T) {
	c := settings.Defaults().WAF
	out := Render(c, Options{Dir: "/etc/xpguard/waf"})
	for _, want := range []string{`"@rx /wp-login\.php(?:/|$)" "t:none,t:urlDecodeUni,t:normalizePath,t:lowercase`, `"@rx /xmlrpc\.php(?:/|$)" "t:none,t:urlDecodeUni,t:normalizePath,t:lowercase`} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(out, `"@endsWith /wp-login.php"`) || strings.Contains(out, `"@endsWith /xmlrpc.php"`) {
		t.Error("a login rule still matches only the end of the path")
	}
	re := regexp.MustCompile(`/wp-login\.php(?:/|$)`)
	for p, want := range map[string]bool{"/wp-login.php": true, "/wp-login.php/x": true, "/blog/wp-login.php/": true, "/wp-login.phpx": false, "/wp-login.php.bak": false} {
		if re.MatchString(p) != want {
			t.Errorf("%s: %v", p, !want)
		}
	}
}

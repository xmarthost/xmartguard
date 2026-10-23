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

// Every rule that reads a list file keeps its own copy of it in every web
// server process (about 35 MB for the IPDB list). The IPDB list is read
// once per address source (the visitor's own address, behind Cloudflare,
// behind a local proxy) and the IPDB POST block and CAPTCHA suspects test
// the marks; before, up to 18 copies (cloud2: LiteSpeed at 235 MB a process).
func TestIPDBListReadOnce(t *testing.T) {
	c := settings.Defaults().WAF
	c.Enabled, c.IPDBPost = true, true
	c.LoginURLs = []string{"/wp-login.php"}
	ct := &Central{URL: "https://captcha.xpguard.org/v", ServerID: "15d69a72-653a-47b6-90f6-fde737bce061", Suspects: []string{"203.0.113.9"},
		Site: true, HTTPSPort: 7743, Slots: [][]string{{"0123456789abcdef0123456789abcdef"}, {"fedcba9876543210fedcba9876543210"}}}
	count := func(out, file string) int { return strings.Count(out, "/"+file+`"`) }
	out := Render(c, Options{Dir: "/r", Central: ct, IPDBMarks: true})
	if n := count(out, FileIPDBIPs); n != 3 {
		t.Fatalf("IPDB list read %d times, want 3 (one per address source)", n)
	}
	if n := count(out, FileCaptchaSuspects); n != 1 {
		t.Fatalf("suspects list read %d times, want 1", n)
	}
	// Without the marks (IPDB off) the suspects list (then holding every
	// suspect) is still read once.
	if out := Render(c, Options{Dir: "/r", Central: ct}); count(out, FileCaptchaSuspects) != 1 || strings.Contains(out, "xg_ipdb") {
		t.Fatalf("without the marks: suspects read %d times", count(out, FileCaptchaSuspects))
	}
	// The marks come before the rules that read them.
	if strings.Index(out, "setvar:tx.xg_ipdb=1") > strings.Index(out, "TX:xg_ipdb \"@eq 1\"") {
		t.Fatal("IPDB mark after its first use")
	}

	// The files: suspects not on the IPDB list, and IPDB entries that are
	// no suspects (allowed, protected).
	f := CentralFiles(&Central{Suspects: []string{"198.51.100.0/24", "203.0.113.9"}}, []string{"198.51.100.0/24", "192.0.2.7"})
	if f[FileCaptchaSuspects] != "203.0.113.9\n" || f[FileCaptchaNotSuspects] != "192.0.2.7\n" {
		t.Fatalf("files %q", f)
	}
}

// On Apache: an IPDB-listed visitor of the login page is sent to the
// CAPTCHA and its POSTs are refused (the marks); the same address when the
// agent left it out of the suspects (a solved check, an allowed address)
// opens the page; a suspect that is not on the IPDB (recent bans) is still
// sent to the CAPTCHA.
func TestIPDBMarksOnApache(t *testing.T) {
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
	st.Patch([]byte(`{"waf":{"enabled":true,"upload_scan":false,"ipdb_post":true,"login_urls":["/wp-login.php"]},"captcha":{"central":true}}`))
	ipdb := []string{"127.0.0.1", "192.0.2.0/24"}
	central := &Central{URL: "https://captcha.xpguard.org/v", ServerID: "15d69a72-653a-47b6-90f6-fde737bce061", Suspects: []string{"127.0.0.1", "192.0.2.0/24"}}
	m := &Manager{DB: db, Settings: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), RulesDir: filepath.Join(dir, "waf"),
		NoSelfTest: true, Central: func() *Central { return central }, IPDBIPs: func() []string { return ipdb }}
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
	apply := func() {
		t.Helper()
		if err := m.Apply(); err != nil {
			t.Fatal(err)
		}
		time.Sleep(1500 * time.Millisecond)
	}
	apply()
	b, _ := os.ReadFile(filepath.Join(m.RulesDir, "rules.conf"))
	if n := strings.Count(string(b), "/"+FileIPDBIPs+`"`); n != 3 {
		t.Fatalf("IPDB list read %d times in rules.conf", n)
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	send := func(method, path string) int {
		req, _ := http.NewRequest(method, "http://127.0.0.1"+path, strings.NewReader("a=1"))
		req.Host = "shop.example.com"
		req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) Firefox/130.0")
		req.Header.Set("Accept", "text/html,*/*")
		if method == "POST" {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode
	}
	if code := send("GET", "/wp-login.php"); code != 302 {
		t.Fatalf("IPDB-listed suspect on the login page: %d, want the CAPTCHA", code)
	}
	if code := send("POST", "/xg-ok.html"); code != 403 {
		t.Fatalf("POST from an IPDB-listed address: %d", code)
	}
	if code := send("GET", "/xg-ok.html"); code != 200 {
		t.Fatalf("IPDB-listed visitor on another page: %d", code)
	}
	// Left out of the suspects by the agent: no CAPTCHA.
	central.Suspects = []string{"192.0.2.0/24"}
	apply()
	if code := send("GET", "/wp-login.php"); code != 200 {
		t.Fatalf("IPDB entry that is no suspect sent to the CAPTCHA: %d", code)
	}
	// Not on the IPDB, a suspect for another reason (a recent ban).
	ipdb, central.Suspects = []string{"192.0.2.0/24"}, []string{"127.0.0.1"}
	apply()
	if code := send("GET", "/wp-login.php"); code != 302 {
		t.Fatalf("suspect off the IPDB on the login page: %d", code)
	}
	if code := send("POST", "/xg-ok.html"); code == 403 {
		t.Fatal("POST refused for an address not on the IPDB")
	}
}

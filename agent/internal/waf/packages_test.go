package waf

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/settings"
	"github.com/xmarthost/xmartguard/agent/internal/store"
)

const browserUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36"

func TestPackagesRender(t *testing.T) {
	c := settings.Defaults().WAF
	out := Render(c, Options{Dir: "/r", Trusted: true, VerifiedBots: []string{"googlebot"}})
	for _, id := range []int{IDWPCoreDirect, IDWPAdminFake, IDWPLookalike, IDWPUploadsList, IDWPCachePHP, IDStaticPHP, IDRepeatDirPHP,
		IDHiddenDirPHP, IDDoubleEncode, IDRootProbe, IDRootProbe + 1000, IDBareMozilla, IDFakeSearchBot, IDMalwareExt,
		IDVPGravitySMTP, IDVPFileManager, IDVPRevSlider, IDVPDuplicator, IDVPLiteSpeed} {
		if !strings.Contains(out, fmt.Sprintf("id:%d,", id)) {
			t.Errorf("rule %d not rendered", id)
		}
	}
	// Trusted services skip the new bot rules too.
	if !strings.Contains(out, fmt.Sprintf("ctl:ruleRemoveById=%d-%d,ctl:ruleRemoveById=%d,", IDBadBots, IDFakeSearchBot, IDRootProbe+1000)) {
		t.Error("trusted services do not skip the probe rules")
	}
	// No verified list, no fake-crawler rule: a real crawler must never be blocked.
	if strings.Contains(Render(c, Options{Dir: "/r", Trusted: true}), fmt.Sprintf("id:%d,", IDFakeSearchBot)) {
		t.Error("fake crawler rule without an official address list")
	}
	c.Generic, c.VirtualPatches = false, false
	out = Render(c, Options{Dir: "/r"})
	for _, id := range []int{IDStaticPHP, IDDoubleEncode, IDVPGravitySMTP} {
		if strings.Contains(out, fmt.Sprintf("id:%d,", id)) {
			t.Errorf("rule %d rendered with its package off", id)
		}
	}
	for _, p := range Packages {
		for _, cat := range p.Categories {
			found := false
			for _, r := range Catalog {
				found = found || r.Category == cat
			}
			if !found {
				t.Errorf("package %s: no rule in category %s", p.ID, cat)
			}
		}
	}
}

// On a real Apache with ModSecurity: attacks seen on hosting servers are
// blocked, everyday requests of WordPress, WooCommerce, Elementor, Joomla
// and OpenCart sites are not.
func TestPackagesOnApache(t *testing.T) {
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
	st.Patch([]byte(`{"waf":{"upload_scan":false,"ai_bots":true}}`))
	m := &Manager{DB: db, Settings: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), RulesDir: filepath.Join(dir, "waf"), NoSelfTest: true,
		TrustedIPs: func() []string { return []string{"66.249.64.0/19"} }, VerifiedBots: func() []string { return []string{"googlebot"} }}
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

	// send makes a raw request (paths are sent exactly as written).
	send := func(method, uri string, hdr map[string]string, body string) int {
		c, err := net.DialTimeout("tcp", "127.0.0.1:80", 3*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		req := method + " " + uri + " HTTP/1.1\r\nHost: shop.example.com\r\n"
		for k, v := range hdr {
			req += k + ": " + v + "\r\n"
		}
		if body != "" {
			req += fmt.Sprintf("Content-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n", len(body))
		}
		req += "Connection: close\r\n\r\n" + body
		io.WriteString(c, req)
		line, _ := bufio.NewReader(c).ReadString('\n')
		var code int
		fmt.Sscanf(line, "HTTP/1.1 %d", &code)
		return code
	}
	browser := map[string]string{"User-Agent": browserUA, "Referer": "https://shop.example.com/"}
	bare := map[string]string{}
	loggedIn := map[string]string{"User-Agent": browserUA, "Cookie": "wordpress_logged_in_abc=admin%7C1"}

	attacks := []struct {
		uri string
		hdr map[string]string
	}{
		{"/w.php", bare}, {"/alfa.php", bare}, {"/wp_blog_footer.php", map[string]string{"User-Agent": ""}},
		{"/wp-includes/css/admin.php", browser}, {"/wp-includes//wp-includes/cache.php", browser}, {"/wp-includes/fonts/about.php", browser},
		{"/wp-includes/js/codemirror/about.php", browser}, {"/wp-admin/includes/buy.php", browser}, {"/wp-admin/css/colors/blue/index.php", browser},
		{"/wp-admin/js/widgets/goods.php", browser}, {"/wp-admin/images/cloud.php", browser}, {"/wp-admin/network/cloud.php", browser},
		{"/wp-admin/user/cloud.php", browser}, {"/wp-l0gin.php", browser}, {"/wp-conflg.php", browser}, {"/blog/wp-2019.php", browser},
		{"/xmrlpc.php", browser}, {"/wp-content/uploads/", browser}, {"/wp-content/uploads/2026/09/", browser}, {"/wp-content/cache/index.php", browser},
		{"/wp-content/blogs.dir/about.php", browser}, {"/images/images/cache.php", browser}, {"//cache/cache/cache.php", browser},
		{"/cgi-bin/cgi-bin/cgi-bin/cache.php", browser}, {"/assets/images/ups.php", browser}, {"/css/cloud.php", browser},
		{"/.tmb/worksec.php", browser}, {"/.trash7206/index.php", browser},
		{"/?page_id=3&pagename=template%252f%252e%252e%252f%252e%252e%252fwp-admin%252finstall", browser},
		{"/sendgrid.env", browser}, {"/aws/ses/smtp.env", browser}, {"/env.txt", browser}, {"/.aws/credentials.bak", browser},
		{"/wp-config.php", browser}, {"/wp-config-sample.php", browser}, {"/wp-includes/SimplePie/gzdecodes.php.suspected", browser},
		{"/shell.php", browser}, {"/alfa-rex.php7", browser}, {"/wp-content/themes/seotheme/mar.php", browser},
		{"/wp-content/plugins/hellopress/wp_filemanager.php", browser}, {"/wp-content/plugins/WordPressCore/", browser},
		{"/", map[string]string{"User-Agent": "Mozilla/5.0"}},
		{"/robots.txt", map[string]string{"User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"}},
		{"/wp-json/gravitysmtp/v1/tests/mock-data?page=gravitysmtp-settings", browser},
		{"/?rest_route=/gravitysmtp/v1/tests/mock-data", browser},
		{"/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php", browser},
		{"/wp-admin/admin-ajax.php?action=revslider_show_image&img=../wp-config.php", browser},
		{"/wp-admin/admin-ajax.php?action=duplicator_download&file=..%2Fwp-config.php", browser},
		{"/wp-content/litespeed/debug/debug.log", browser},
	}
	for _, a := range attacks {
		if code := send("GET", a.uri, a.hdr, ""); code != 403 {
			t.Errorf("attack not blocked: %s (%d)", a.uri, code)
		}
	}

	normal := []struct {
		method, uri string
		hdr         map[string]string
		body        string
	}{
		{"GET", "/", browser, ""}, {"GET", "/index.php", bare, ""}, {"GET", "/wp-cron.php?doing_wp_cron=1", map[string]string{"User-Agent": "WordPress/6.6; https://shop.example.com"}, ""},
		{"GET", "/?s=shoes&post_type=product", browser, ""}, {"GET", "/shop/?orderby=price", browser, ""}, {"GET", "/?wc-ajax=get_refreshed_fragments", browser, ""},
		{"POST", "/?wc-ajax=checkout", browser, "billing_first_name=Ali&payment_method=cod"}, {"GET", "/wp-login.php", browser, ""},
		{"POST", "/wp-login.php", browser, "log=admin&pwd=secret&redirect_to=https%3A%2F%2Fshop.example.com%2Fwp-admin%2F"},
		{"GET", "/wp-admin/", loggedIn, ""}, {"GET", "/wp-admin/post.php?post=12&action=elementor", loggedIn, ""},
		{"POST", "/wp-admin/admin-ajax.php", loggedIn, "action=elementor_ajax&actions=%7B%7D"}, {"GET", "/wp-admin/load-scripts.php?c=1&load%5Bchunk_0%5D=jquery-core", loggedIn, ""},
		{"GET", "/wp-admin/load-styles.php?c=1&load%5Bchunk_0%5D=dashicons", loggedIn, ""}, {"GET", "/wp-admin/network/sites.php", loggedIn, ""},
		{"GET", "/wp-admin/user/profile.php", loggedIn, ""}, {"GET", "/wp-admin/about.php", loggedIn, ""}, {"GET", "/wp-includes/js/tinymce/wp-tinymce.php?c=1", loggedIn, ""},
		{"GET", "/wp-includes/js/jquery/jquery.min.js?ver=3.7.1", browser, ""}, {"GET", "/wp-includes/css/dist/block-library/style.min.css", browser, ""},
		{"GET", "/wp-json/wp/v2/posts?per_page=5", browser, ""}, {"GET", "/wp-json/wc/store/v1/cart", browser, ""},
		{"POST", "/wp-json/contact-form-7/v1/contact-forms/3175/feedback", browser, "your-name=Ali&your-email=a%40example.com"},
		{"GET", "/wp-content/uploads/2024/05/banner.jpg", browser, ""}, {"GET", "/wp-content/uploads/elementor/css/post-12.css", browser, ""},
		{"GET", "/wp-content/cache/autoptimize/css/autoptimize_1.php", browser, ""}, {"GET", "/wp-content/cache/min/1/style.css", browser, ""},
		{"GET", "/wp-content/themes/astra/assets/css/minified/main.min.css", browser, ""}, {"GET", "/wp-content/plugins/woocommerce/assets/js/frontend/cart.min.js", browser, ""},
		{"GET", "/.well-known/acme-challenge/abc123", bare, ""}, {"GET", "/.well-known/pki-validation/check.php", bare, ""},
		{"GET", "/feed/", browser, ""}, {"GET", "/wp-sitemap.xml", browser, ""}, {"GET", "/sitemap_index.xml", browser, ""},
		{"GET", "/robots.txt", map[string]string{"User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", "X-Forwarded-For": "66.249.66.1"}, ""},
		{"GET", "/?redirect_to=https%253A%252F%252Fshop.example.com%252Fcart", browser, ""},
		{"GET", "/administrator/index.php", browser, ""}, {"GET", "/index.php?option=com_content&view=article&id=5", browser, ""},
		{"GET", "/images/banners/summer.jpg", browser, ""}, {"GET", "/index.php?route=product/product&product_id=42", browser, ""},
		{"GET", "/image/catalog/logo.png", browser, ""}, {"GET", "/api/orders?page=2", map[string]string{"User-Agent": "okhttp/4.12"}, ""},
		{"POST", "/ipn.php", map[string]string{"User-Agent": "PayPal IPN ( https://www.paypal.com/ipn )"}, "txn_id=1"},
		{"GET", "/wp-admin/admin-ajax.php?action=revslider_show_image&img=slide1.jpg", browser, ""},
	}
	for _, n := range normal {
		if code := send(n.method, n.uri, n.hdr, n.body); code == 403 || code == 0 {
			t.Errorf("normal request blocked: %s %s (%d)", n.method, n.uri, code)
		}
	}
}

func TestPackageStates(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XG_STATE_DIR", filepath.Join(dir, "state"))
	t.Setenv("XG_CONFIG_DIR", filepath.Join(dir, "conf"))
	db, _ := store.Open()
	defer db.Close()
	st, _ := settings.Load()
	st.Patch([]byte(`{"waf":{"virtual_patches":false}}`))
	m := &Manager{DB: db, Settings: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	now := store.Now()
	for _, e := range []struct {
		id int
		at int64
	}{{IDRootProbe, now - 60}, {IDRootProbe + 1000, now - 60}, {IDStaticPHP, now - 3*86400}, {IDVPGravitySMTP + 1000, now - 60}} {
		db.Exec(`INSERT INTO waf_events (at, ip, rule_id, action, category) VALUES (?, '203.0.113.5', ?, 'Access denied with code 403', 'waf')`, e.at, e.id)
	}
	ps := map[string]PackageState{}
	for _, p := range m.PackageStates() {
		ps[p.ID] = p
	}
	if s := ps["scanner"]; !s.Enabled || s.Hits24h != 2 || s.Hits7d != 2 {
		t.Errorf("scanner %+v", s)
	}
	if g := ps["generic"]; !g.Enabled || g.Hits24h != 0 || g.Hits7d != 1 || g.Active != g.Rules {
		t.Errorf("generic %+v", g)
	}
	// Virtual patches off; 7702001 is no rule of ours and counts nowhere.
	if v := ps["virtual_patches"]; v.Enabled || v.Active != 0 || v.Hits24h != 0 {
		t.Errorf("virtual patches %+v", v)
	}
}

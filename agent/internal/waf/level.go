package waf

import (
	"fmt"
	"regexp"
	"strings"
)

// WAF levels (Settings » WAF): how much the OWASP CRS may block.
//
//	low     only clear attacks: anomaly threshold at least 20 (four critical
//	        rules), no blocks by reputation alone (IPDB, Tor)
//	normal  threshold at least 10 (two critical rules: one weak signal in a
//	        form or an editor never blocks)
//	strict  the threshold of WAF Rule Sets (5 by default: one critical rule)
//
// In low and normal, logged-in WordPress users saving their own site
// (wp-admin, admin-ajax, the REST API, also with an application password)
// are not blocked by the CRS at all; visitors on the IPDB, Tor or ban lists
// still are. This works by the anomaly threshold, which every ModSecurity
// engine (Apache, LiteSpeed) supports, not by rule removal.

const (
	IDEditorCookie = 7700040
	IDEditorAuth   = 7700041
	// IDWPUser marks a request of a logged-in WordPress user once, early
	// (tx.xg_wp_user any login cookie, tx.xg_wp_editor a real one or the
	// block editor's nonce); the other rules test these variables.
	IDWPUser = 7700046
	// IDContentType replaces CRS 920420 (content type not allowed): it reads
	// the header itself against a fixed list instead of CRS's variable
	// macros. On a LiteSpeed server CRS refused WooCommerce checkouts,
	// Contact Form 7, Joomla sign-ups and admin-ajax with plain form posts.
	IDContentType = 7700052
	// IDAdminArea: a save from the admin area of any web application
	// (Joomla's /administrator/, OpenCart, Laravel and custom panels' /admin/)
	// sent by that admin area's own page with a session; +1000 on an address
	// with a bad reputation.
	IDAdminArea = 7700058
	// IDJoomlaAdmin: a Joomla administrator save with its form token (no
	// header needed); +1000 on an address with a bad reputation.
	IDJoomlaAdmin = 7700070
	// joomlaAdminThreshold: such a save is refused from this score on.
	joomlaAdminThreshold = 30
	// IDWCRestKeys: a WooCommerce REST API write sent with the shop's API
	// keys (+1000 OAuth, +2000 Basic authentication).
	IDWCRestKeys = 7700072
	// IDAppSave: a web application admin's save marked before the CRS
	// setup (tx.xg_app_save, the WHMCS admin area); +1000 on an address
	// with a bad reputation.
	IDAppSave = 7700059
	// IDEditorAdmin: a logged-in editor on an address with a bad reputation
	// saving from their own site's wp-admin.
	IDEditorAdmin = 7702040
	// Mail clients (Outlook) asking cPanel for their settings.
	IDAutodiscover = 7700042
	// IDSessionHost/IDSessionSite: a request a website's own page sends
	// (Origin or Referer of the same host) with a session cookie.
	IDSessionHost = 7700043
	IDSessionSite = 7700044
	// IDSessionXSS: a same-site request with a session that carries script
	// injection (XSS score sessionXSSCap or more) is still refused: comment,
	// review and contact forms of visitors keep their stored-XSS protection.
	IDSessionXSS  = 7700045
	sessionXSSCap = 15
	// sessionThreshold: same-site requests of a visitor with a session
	// (admin panels, Livewire, forms) are blocked from this score on: an
	// editor saving HTML or code scores 10-25, an attack tool far more.
	sessionThreshold = 30
	// editorThreshold: no request reaches it.
	editorThreshold = 100000
)

func (m *Manager) level() string {
	if m.Settings == nil {
		return "normal"
	}
	switch l := m.Settings.Get().WAF.Level; l {
	case "low", "strict":
		return l
	}
	return "normal"
}

// crsThreshold is the inbound anomaly threshold for the level.
func (m *Manager) crsThreshold(crs CRSConfig) int {
	in := clampInt(crs.InboundThreshold, 3, 1000, 5)
	switch m.level() {
	case "low":
		return max(in, 20)
	case "normal":
		return max(in, 10)
	}
	return in
}

// editorSetup lifts the threshold for logged-in WordPress users on their
// site's admin and REST API. It comes after the CRS setup and soft blocking
// (it also clears their soft-block flag).
func editorSetup() string {
	set := fmt.Sprintf(`SecRule &TX:xg_strict "@eq 0" "t:none,setvar:tx.xg_soft=0,setvar:tx.xg_editor=1,setvar:tx.inbound_anomaly_score_threshold=%d"`, editorThreshold)
	return "# Logged-in WordPress users editing their site (xPGuard WAF level).\n" +
		fmt.Sprintf(`SecRule TX:xg_wp_area "@eq 1" "id:%d,phase:1,pass,t:none,nolog,chain"`, IDEditorCookie) + "\n" +
		`  SecRule TX:xg_wp_editor "@eq 1" "t:none,chain"` + "\n  " + set + "\n" +
		fmt.Sprintf(`SecRule TX:xg_wp_rest "@eq 1" "id:%d,phase:1,pass,t:none,nolog,chain"`, IDEditorAuth) + "\n" +
		`  SecRule REQUEST_HEADERS:Authorization "@rx ^(?:basic|bearer)\s+\S{8,}" "t:none,t:lowercase,chain"` + "\n  " + set + "\n" +
		// On an address with a bad reputation (a shared mobile or office
		// address another user abused) the logged-in editor still saves
		// posts and menus: one weak signal is let through, a real attack
		// (several rules) is not.
		fmt.Sprintf(`SecRule TX:xg_wp_area "@eq 1" "id:%d,phase:1,pass,t:none,nolog,chain"`, IDEditorCookie+1000) + "\n" +
		`  SecRule TX:xg_wp_editor "@eq 1" "t:none,chain"` + "\n" +
		fmt.Sprintf(`  SecRule &TX:xg_strict "@ge 1" "t:none,setvar:tx.xg_soft=0,setvar:tx.inbound_anomaly_score_threshold=%d"`, sessionThreshold) + "\n" +
		// The same editor saving from their own wp-admin page (Elementor's
		// HTML widget, page builders, code snippets score 35-80): the browser
		// says the request came from the same site (Sec-Fetch-Site) and the
		// Referer is this site's wp-admin. Attack tools on that address send
		// neither, so they keep the stricter threshold above.
		fmt.Sprintf(`SecRule TX:xg_wp_area "@eq 1" "id:%d,phase:1,pass,t:none,nolog,chain"`, IDEditorAdmin) + "\n" +
		`  SecRule TX:xg_wp_editor "@eq 1" "t:none,chain"` + "\n" +
		`  SecRule &TX:xg_strict "@ge 1" "t:none,chain"` + "\n" +
		`  SecRule REQUEST_HEADERS:Sec-Fetch-Site "@streq same-origin" "t:none,t:lowercase,chain"` + "\n" +
		`  SecRule REQUEST_HEADERS:Referer "@rx ^https?://([^/?#]+)/(?:[^?#]*/)?wp-admin/" "t:none,t:lowercase,capture,chain"` + "\n" +
		fmt.Sprintf(`  SecRule TX:1 "@streq %%{REQUEST_HEADERS.Host}" "t:none,t:lowercase,setvar:tx.xg_soft=0,setvar:tx.xg_editor=1,setvar:tx.inbound_anomaly_score_threshold=%d"`, editorThreshold) + "\n" +
		adminAreaSetup()
}

// adminAreaSetup lifts the threshold for saves from the admin area of any
// web application, the way editorSetup does for WordPress: Joomla's
// administrator saving email templates or editing files (File Explorer),
// OpenCart, Laravel and custom panels saving HTML. The browser says the
// request came from the same site (Sec-Fetch-Site, which a page of another
// site cannot fake), the Referer is the same host's admin area and a
// session cookie is sent; the application checks the login. On an address
// with a bad reputation only the session threshold applies.
func adminAreaSetup() string {
	head := func(id int) string {
		return fmt.Sprintf(`SecRule REQUEST_FILENAME "@rx (?:^|/)%s/" "id:%d,phase:1,pass,t:none,t:urlDecodeUni,t:lowercase,nolog,chain"`, adminAreaSegments, id) + "\n" +
			`  SecRule REQUEST_HEADERS:Sec-Fetch-Site "@streq same-origin" "t:none,t:lowercase,chain"` + "\n" +
			// A session cookie, read from the header: LiteSpeed's engine does
			// not fill the cookie collections reliably (joomlashare.ir: every
			// Joomla administrator save scoring 10-25 was refused there, and
			// the site owner was banned for it).
			`  SecRule REQUEST_HEADERS:Cookie "@rx [^\s;=]+=[^\s;]" "t:none,chain"` + "\n" +
			// The page it came from is in the admin area. Same site: the
			// browser's own Sec-Fetch-Site above, not a comparison with the
			// Host header through a macro, which LiteSpeed's engine did not
			// honour (joomlashares.com: Joomla Global Configuration saves
			// scoring 10 still refused after 0.23.28).
			fmt.Sprintf(`  SecRule REQUEST_HEADERS:Referer "@rx ^https?://[^/?#]+/(?:[^?#]*/)?%s/" "t:none,t:lowercase,chain"`, adminAreaSegments) + "\n"
	}
	return "# Saves from a web application's own admin area (xPGuard WAF level).\n" +
		head(IDAdminArea) +
		fmt.Sprintf(`  SecRule &TX:xg_strict "@eq 0" "t:none,setvar:tx.xg_soft=0,setvar:tx.xg_session=0,setvar:tx.xg_editor=1,setvar:tx.inbound_anomaly_score_threshold=%d"`, editorThreshold) + "\n" +
		head(IDAdminArea+1000) +
		fmt.Sprintf(`  SecRule &TX:xg_strict "@ge 1" "t:none,setvar:tx.xg_soft=0,setvar:tx.inbound_anomaly_score_threshold=%d"`, sessionThreshold) + "\n" +
		joomlaAdminSetup()
}

// joomlaAdminFamilies: the CRS families Joomla administrator saves set off
// (joomlashares.com, business600: .htaccess Maker 932160/932260, Global
// Configuration 941100/941160, File Explorer 930120/932140/932160 scoring
// 40, jDownloads 932230/932235/932250): taken out of a save with the form
// token; SQL injection is still checked.
var joomlaAdminFamilies = []string{"930", "932", "933", "941"}

// wcRestFamilies: product HTML in WooCommerce REST writes (CJdropshipping:
// 941100, 941160).
var wcRestFamilies = []string{"941"}

// joomlaAdminSetup lifts the threshold for Joomla administrator saves told
// by Joomla's own form token: every save posts a field named with 32 hex
// characters. It needs no request header: on LiteSpeed (joomlashares.com,
// business600, 2026-10-27/28) Global Configuration, Admin Tools' .htaccess
// Maker, File Explorer and jDownloads saves scoring 10-30 were still
// refused with the Sec-Fetch-Site lifts above in place. Joomla checks the
// token and the login itself; a request without them changes nothing.
// Since 0.24.17 such a save also skips joomlaAdminFamilies (LiteSpeed
// scores a request again after the first check, so no threshold is safe
// there) and the threshold is 30 for what still checks it (SQL injection,
// protocol). On an address with a bad reputation only the session
// threshold applies, without skipping families.
func joomlaAdminSetup() string {
	head := func(id int) string {
		// The path from REQUEST_URI, up to the query: on LiteSpeed a path
		// test ending in "$" never matched (self-test, business600).
		return fmt.Sprintf(`SecRule REQUEST_URI "@rx ^[^?]*/administrator/(?:index\.php)?(?:\?|$)" "id:%d,phase:2,pass,t:none,t:urlDecodeUni,t:lowercase,nolog,chain"`, id) + "\n" +
			`  SecRule REQUEST_METHOD "@streq POST" "t:none,chain"` + "\n" +
			// ARGS_NAMES: the collection CRS itself reads on every engine.
			`  SecRule ARGS_NAMES "@rx ^[0-9a-f]{32}$" "t:none,chain"` + "\n"
	}
	return "# Joomla administrator saves with the form token (xPGuard WAF level).\n" +
		head(IDJoomlaAdmin) +
		fmt.Sprintf(`  SecRule &TX:xg_strict "@eq 0" "t:none,setvar:tx.xg_soft=0,setvar:tx.inbound_anomaly_score_threshold=%d,%s"`, joomlaAdminThreshold, familyFlags(joomlaAdminFamilies...)) + "\n" +
		head(IDJoomlaAdmin+1000) +
		fmt.Sprintf(`  SecRule &TX:xg_strict "@ge 1" "t:none,setvar:tx.xg_soft=0,setvar:tx.inbound_anomaly_score_threshold=%d"`, sessionThreshold) + "\n"
}

// adminAreaSegments name an application's admin area: not "dashboard" or
// "panel", which are customer areas too (their users are not the site's
// administrators).
const adminAreaSegments = `(?:admin|administrator|adminpanel|admin-panel|backend)`

// sessionSetup lifts the threshold for requests a website's own pages send
// with a session cookie: admin panels of any application (Laravel,
// CodeIgniter, school and lab systems), Livewire components and the
// site's own forms. Their users save HTML, code samples and text that
// reads like SQL; the OWASP CRS still blocks a request with many strong
// signals, and visitors on the IPDB, Tor or ban lists keep the normal
// threshold. It comes before the editor setup (which lifts it further for
// logged-in WordPress users).
func sessionSetup() string {
	return "# Requests from a website's own pages with a session cookie (xPGuard WAF level).\n" +
		fmt.Sprintf(`SecRule REQUEST_HEADERS:Host "@rx ^([^:]+)" "id:%d,phase:1,pass,t:none,t:lowercase,nolog,capture,setvar:tx.xg_host=%%{TX.1}"`, IDSessionHost) + "\n" +
		fmt.Sprintf(`SecRule REQUEST_HEADERS:Origin|REQUEST_HEADERS:Referer "@rx ^https?://([^/:?#]+)" "id:%d,phase:1,pass,t:none,t:lowercase,nolog,capture,chain"`, IDSessionSite) + "\n" +
		`  SecRule TX:1 "@streq %{tx.xg_host}" "t:none,chain"` + "\n" +
		// Joomla and many PHP applications name the session cookie with a
		// 32-character hash (md5 of the site's secret).
		`  SecRule REQUEST_COOKIES_NAMES "@rx (?i)(?:sess|sid$|xsrf|csrf|token|logged_in|auth|remember|^[0-9a-f]{32}$)" "t:none,chain"` + "\n" +
		// WordPress has its own rule for logged-in users; its shop and
		// comment visitors have session cookies too and are not relaxed.
		// (no "|" in a collection's name regex: ModSecurity splits on it)
		`  SecRule &REQUEST_COOKIES_NAMES:/^wordpress_/ "@eq 0" "t:none,chain"` + "\n" +
		`  SecRule &REQUEST_COOKIES_NAMES:/^w(?:p_w)?oocommerce_/ "@eq 0" "t:none,chain"` + "\n" +
		`  SecRule REQUEST_FILENAME "!@rx /wp-(?:admin|json|content|includes|comments-post|login)" "t:none,t:urlDecodeUni,t:lowercase,chain"` + "\n" +
		fmt.Sprintf(`  SecRule &TX:xg_strict "@eq 0" "t:none,setvar:tx.xg_session=1,setvar:tx.xg_soft=0,setvar:tx.inbound_anomaly_score_threshold=%d"`, sessionThreshold) + "\n" +
		// The same told by the browser's Sec-Fetch-Site and read from the
		// Cookie header: no macro and no cookie collection, which
		// LiteSpeed's engine did not honour (see adminAreaSetup).
		fmt.Sprintf(`SecRule REQUEST_HEADERS:Sec-Fetch-Site "@streq same-origin" "id:%d,phase:1,pass,t:none,t:lowercase,nolog,chain"`, IDSessionSite+1000) + "\n" +
		`  SecRule REQUEST_HEADERS:Cookie "@rx (?i)(?:^|;)\s*(?:[^=;\s]*(?:sess|xsrf|csrf|token|logged_in|auth|remember)[^=;\s]*|[^=;\s]*sid|[0-9a-f]{32})=" "t:none,chain"` + "\n" +
		`  SecRule REQUEST_HEADERS:Cookie "!@rx (?:^|;)\s*(?:wordpress_|wp_woocommerce_|woocommerce_)" "t:none,chain"` + "\n" +
		`  SecRule REQUEST_FILENAME "!@rx /wp-(?:admin|json|content|includes|comments-post|login)" "t:none,t:urlDecodeUni,t:lowercase,chain"` + "\n" +
		fmt.Sprintf(`  SecRule &TX:xg_strict "@eq 0" "t:none,setvar:tx.xg_session=1,setvar:tx.xg_soft=0,setvar:tx.inbound_anomaly_score_threshold=%d"`, sessionThreshold) + "\n"
}

// sessionPost runs after the OWASP CRS: script injection in a relaxed
// same-site request is refused (stored XSS through a public form).
func sessionPost() string {
	return "# Script injection in a same-site request with a session (xPGuard WAF level).\n" +
		fmt.Sprintf(`SecRule TX:xg_session "@eq 1" "id:%d,phase:2,t:none,deny,status:403,log,msg:'xPGuard - Script injection in a same-site request blocked (XSS score: %%{tx.xss_score})',tag:'xpguard/crs',chain"`, IDSessionXSS) + "\n" +
		fmt.Sprintf(`  SecRule TX:xss_score "@ge %d" "t:none"`, sessionXSSCap) + "\n"
}

// AllowedMethods are the HTTP methods the OWASP CRS lets through.
const AllowedMethods = "GET HEAD POST OPTIONS PUT PATCH DELETE"

// AllowedContentTypes is CRS 4's list with what browsers and APIs send in
// normal use: text/plain (sendBeacon, fetch with a string body),
// application/octet-stream, CSP and Reporting API reports, GraphQL and
// CloudEvents.
const AllowedContentTypes = "|application/x-www-form-urlencoded| |multipart/form-data| |multipart/related| |text/xml| |application/xml| |application/soap+xml| " +
	"|application/json| |application/reports+json| |application/csp-report| |text/plain| |application/octet-stream| |application/graphql| " +
	"|application/cloudevents+json| |application/cloudevents-batch+json| |application/x-ndjson|"

// RestrictedExtensions is CRS's list without .com (see rulesets.go).
const RestrictedExtensions = ".ani/ .asa/ .asax/ .ascx/ .backup/ .bak/ .bat/ .cdx/ .cer/ .cfg/ .cmd/ .compositefont/ .config/ .conf/ .crt/ .cs/ .csproj/ .csr/ " +
	".dat/ .db/ .dbf/ .dist/ .dll/ .dos/ .dpkg-dist/ .drv/ .gadget/ .hta/ .htr/ .htw/ .ida/ .idc/ .idq/ .inc/ .inf/ .ini/ .jse/ .key/ .licx/ .lnk/ .log/ " +
	".mdb/ .msc/ .ocx/ .old/ .pass/ .pdb/ .pfx/ .pif/ .pem/ .pol/ .prf/ .printer/ .pwd/ .rdb/ .rdp/ .reg/ .resources/ .resx/ .scr/ .sct/ .shs/ .sql/ " +
	".swp/ .sys/ .tlb/ .tmp/ .url/ .vb/ .vbe/ .vbs/ .vbproj/ .vsdisco/ .vxd/ .webinfo/ .ws/ .wsc/ .wsf/ .wsh/ .xsd/ .xsx/"

// appSaveSetup lifts the threshold again for admin saves marked by the
// exclusions (WHMCS General Settings and other admin pages that save HTML
// and tracking code): the CRS setup, loaded after the exclusions, sets the
// threshold back (900110), and on LiteSpeed the exclusions' rule removal
// does nothing, so without this a save scoring above the session
// threshold was refused there.
func appSaveSetup() string {
	return "# Admin saves of web applications marked by the exclusions (WHMCS).\n" +
		fmt.Sprintf(`SecRule TX:xg_app_save "@eq 1" "id:%d,phase:1,pass,t:none,nolog,chain"`, IDAppSave) + "\n" +
		fmt.Sprintf(`  SecRule &TX:xg_strict "@eq 0" "t:none,setvar:tx.xg_soft=0,setvar:tx.xg_session=0,setvar:tx.xg_editor=1,setvar:tx.inbound_anomaly_score_threshold=%d"`, editorThreshold) + "\n" +
		fmt.Sprintf(`SecRule TX:xg_app_save "@eq 1" "id:%d,phase:1,pass,t:none,nolog,chain"`, IDAppSave+1000) + "\n" +
		fmt.Sprintf(`  SecRule &TX:xg_strict "@ge 1" "t:none,setvar:tx.xg_soft=0,setvar:tx.inbound_anomaly_score_threshold=%d"`, sessionThreshold) + "\n"
}

// autodiscoverSetup lets mail clients' Autodiscover requests through:
// Outlook POSTs an XML document (<Autodiscover><Request><EMailAddress>…)
// to /autodiscover/autodiscover.xml, which the CRS XSS rules (941100,
// libinjection) read as markup; cPanel answers it, no website code runs.
func autodiscoverSetup() string {
	return "# Mail clients asking for their settings (Outlook Autodiscover, xPGuard WAF level).\n" +
		fmt.Sprintf(`SecRule REQUEST_METHOD "@streq POST" "id:%d,phase:1,pass,t:none,nolog,chain"`, IDAutodiscover) + "\n" +
		`  SecRule REQUEST_FILENAME "@rx ^/+autodiscover/autodiscover\.xml$" "t:none,t:urlDecodeUni,t:lowercase,chain"` + "\n" +
		`  SecRule REQUEST_HEADERS:Content-Type "@rx ^(?:text|application)/xml" "t:none,t:lowercase,chain"` + "\n" +
		fmt.Sprintf(`  SecRule &TX:xg_strict "@eq 0" "t:none,setvar:tx.xg_soft=0,setvar:tx.inbound_anomaly_score_threshold=%d"`, editorThreshold) + "\n"
}

// wpUserSetup marks requests of logged-in WordPress users. The login cookie
// is read both by name and from the Cookie header, and the block editor's
// REST calls are also known by their nonce, sent same-origin from the
// site's own wp-admin: on LiteSpeed servers logged-in editors were not
// recognised by the cookie name patterns alone, so their saves (pages,
// menus, SEO fields) and the block editor's user list were refused like a
// visitor's.
func wpUserSetup() string {
	return "# Logged-in WordPress users (read once; the rules below test tx.xg_wp_user / tx.xg_wp_editor).\n" +
		fmt.Sprintf(`SecRule REQUEST_COOKIES_NAMES "@beginsWith wordpress_logged_in_" "id:%d,phase:1,pass,t:none,nolog,setvar:tx.xg_wp_user=1"`, IDWPUser) + "\n" +
		fmt.Sprintf(`SecRule REQUEST_HEADERS:Cookie "@contains wordpress_logged_in_" "id:%d,phase:1,pass,t:none,nolog,setvar:tx.xg_wp_user=1"`, IDWPUser+1) + "\n" +
		fmt.Sprintf(`SecRule REQUEST_COOKIES_NAMES "@rx ^wordpress_logged_in_[0-9a-f]{32}$" "id:%d,phase:1,pass,t:none,nolog,setvar:tx.xg_wp_editor=1"`, IDWPUser+2) + "\n" +
		fmt.Sprintf(`SecRule REQUEST_HEADERS:Cookie "@rx (?:^|;)\s*wordpress_logged_in_[0-9a-f]{32}=" "id:%d,phase:1,pass,t:none,nolog,setvar:tx.xg_wp_editor=1"`, IDWPUser+3) + "\n" +
		// The WordPress admin and REST API, known by the script path or the
		// rest_route argument of a front controller (a folder or index.php),
		// never by "rest_route=" anywhere in the address: appended to any
		// URL it relaxed the OWASP CRS for any script (audit A3 F1).
		fmt.Sprintf(`SecRule REQUEST_FILENAME "@rx /wp-(?:admin|json)/" "id:%d,phase:1,pass,t:none,t:urlDecodeUni,t:lowercase,nolog,setvar:tx.xg_wp_area=1"`, IDWPUser+4) + "\n" +
		fmt.Sprintf(`SecRule ARGS_GET:rest_route "@rx ^/" "id:%d,phase:1,pass,t:none,t:urlDecodeUni,nolog,chain"`, IDWPUser+5) + "\n" +
		`  SecRule REQUEST_FILENAME "@rx (?:^|/)(?:index\.php)?$" "t:none,t:urlDecodeUni,t:lowercase,setvar:tx.xg_wp_area=1,setvar:tx.xg_wp_rest=1"` + "\n" +
		fmt.Sprintf(`SecRule REQUEST_FILENAME "@rx /wp-json/" "id:%d,phase:1,pass,t:none,t:urlDecodeUni,t:lowercase,nolog,setvar:tx.xg_wp_rest=1"`, IDWPUser+2000) + "\n" +
		fmt.Sprintf(`SecRule REQUEST_HEADERS:X-WP-Nonce "@rx ^[0-9a-f]{10}$" "id:%d,phase:1,pass,t:none,t:lowercase,nolog,chain"`, IDWPUser+1000) + "\n" +
		`  SecRule REQUEST_HEADERS:Sec-Fetch-Site "@streq same-origin" "t:none,t:lowercase,chain"` + "\n" +
		`  SecRule REQUEST_HEADERS:Referer "@rx ^https?://([^/?#]+)/(?:[^?#]*/)?wp-admin/" "t:none,t:lowercase,capture,chain"` + "\n" +
		`  SecRule TX:1 "@streq %{REQUEST_HEADERS.Host}" "t:none,t:lowercase,setvar:tx.xg_wp_user=1,setvar:tx.xg_wp_editor=1"` + "\n" +
		// A login cookie inside the admin or REST API: the editor case the
		// IPDB/Tor POST blocks let through.
		fmt.Sprintf(`SecRule TX:xg_wp_user "@eq 1" "id:%d,phase:1,pass,t:none,nolog,chain"`, IDWPUser+3000) + "\n" +
		`  SecRule TX:xg_wp_area "@eq 1" "t:none,setvar:tx.xg_wp_editing=1"` + "\n"
}

// contentTypeRx is AllowedContentTypes as one regular expression of media
// types (parameters such as charset or boundary may follow).
func contentTypeRx() string {
	var alts []string
	for _, t := range strings.Fields(AllowedContentTypes) {
		alts = append(alts, regexp.QuoteMeta(strings.Trim(t, "|")))
	}
	return `^\s*(?:` + strings.Join(alts, "|") + `)\s*(?:[;,]|$)`
}

// contentTypeSetup is the content type policy for CRS 4 (920420 is taken
// out after the CRS is loaded). It scores like 920420 and logs the header,
// so a refused type shows in the WAF log.
func contentTypeSetup() string {
	return "# Content type policy (xPGuard, in place of CRS 920420).\n" +
		fmt.Sprintf(`SecRule REQUEST_HEADERS:Content-Type "!@rx %s" "id:%d,phase:2,block,t:none,t:lowercase,msg:'Request content type is not allowed by policy',logdata:'%%{MATCHED_VAR}',tag:'attack-protocol',tag:'xpguard/crs',severity:'CRITICAL',setvar:'tx.inbound_anomaly_score_pl1=+%%{tx.critical_anomaly_score}'"`, contentTypeRx(), IDContentType) + "\n"
}

// wcRestKeysSetup lifts the threshold for WooCommerce REST API writes sent
// with the shop's API keys: dropshipping and sync services (CJdropshipping,
// ssshoesmaker.com on s1.cobuildhost.com, 2026-10-30/31) post product HTML
// to /wp-json/wc/v3/products, which CRS read as XSS (941100, 941160; score
// 13-15) and refused. WooCommerce checks the keys: a request with wrong
// ones changes nothing. Since 0.24.17 such a write skips the XSS family
// (wcRestFamilies; LiteSpeed raised 13 to 39 under threshold 30); the
// other attack signals still count, from 30 on.
func wcRestKeysSetup() string {
	head := func(id int) string {
		return fmt.Sprintf(`SecRule REQUEST_METHOD "@rx ^(?:POST|PUT|PATCH|DELETE)$" "id:%d,phase:1,pass,t:none,nolog,chain"`, id) + "\n" +
			`  SecRule REQUEST_URI "@rx (?:/wp-json/+|[?&]rest_route=/*)wc/v[1-3]/" "t:none,t:urlDecodeUni,t:lowercase,chain"` + "\n"
	}
	set := fmt.Sprintf("setvar:tx.xg_soft=0,setvar:tx.inbound_anomaly_score_threshold=%d,%s", sessionThreshold, familyFlags(wcRestFamilies...))
	return "# WooCommerce REST API writes with the shop's API keys (xPGuard).\n" +
		// The key read from REQUEST_URI: LiteSpeed's engine does not fill
		// ARGS_GET (self-test, business600).
		head(IDWCRestKeys) + `  SecRule REQUEST_URI "@rx [?&]consumer_key=ck_[0-9a-f]{40}(?:&|$)" "t:none,` + set + `"` + "\n" +
		head(IDWCRestKeys+1000) + `  SecRule REQUEST_URI "@rx [?&]oauth_consumer_key=ck_[0-9a-f]{40}(?:&|$)" "t:none,` + set + `"` + "\n" +
		head(IDWCRestKeys+2000) + `  SecRule REQUEST_HEADERS:Authorization "@rx ^basic\s+[a-z0-9+/=]{20,}$" "t:none,t:lowercase,` + set + `"` + "\n"
}

// IDMechProbe: rules that only answer the self-test's posts to
// /xpguard-crs-selftest/mech/<name>, each relaxing in one way, to learn
// which ways a web server's engine honours (on LiteSpeed, business600,
// 2026-10-31, raising the threshold from a chained rule did nothing).
const IDMechProbe = 7700080

// mechProbes: name, phase and actions of each way.
// A cond probe raises the threshold only after one more condition of the
// kind the relaxations use (cond: that rule without its actions).
var mechProbes = []struct{ name, phase, actions, cond string }{
	{"thr_single", "1", "setvar:tx.xg_soft=0,setvar:tx.inbound_anomaly_score_threshold=10000", ""},
	{"thr_chain", "1", "chain", `SecRule REQUEST_METHOD "@streq POST"`},
	{"thr_phase2", "2", "setvar:tx.xg_soft=0,setvar:tx.inbound_anomaly_score_threshold=10000", ""},
	{"remove_949110", "1", "setvar:tx.xg_soft=0,ctl:ruleRemoveById=949110", ""},
	{"remove_xss_tag", "1", "setvar:tx.xg_soft=0,ctl:ruleRemoveTargetByTag=attack-xss;ARGS", ""},
	{"detection_only", "1", "setvar:tx.xg_soft=0,ctl:ruleEngine=DetectionOnly", ""},
	{"allow", "1", "allow", ""},
	{"cond_tx_lt", "1", "chain", `SecRule TX:inbound_anomaly_score_threshold "@lt 10000"`},
	{"cond_tx_count", "1", "chain", `SecRule &TX:xg_strict "@eq 0"`},
	{"cond_args_get", "1", "chain", `SecRule ARGS_GET:k "@rx ^ck_[0-9a-f]{40}$"`},
	{"cond_args_names", "2", "chain", `SecRule ARGS_NAMES "@rx ^[0-9a-f]{32}$"`},
	{"cond_filename_end", "1", "chain", `SecRule REQUEST_FILENAME "@rx /cond_filename_end$"`},
	{"cond_query_string", "1", "chain", `SecRule QUERY_STRING "@rx (?:^|&)k=ck_[0-9a-f]{40}(?:&|$)"`},
	{"cond_request_uri", "1", "chain", `SecRule REQUEST_URI "@rx [?&]k=ck_[0-9a-f]{40}(?:&|$)"`},
	// Removal by a range of ids and by tag (xPGuard's exclusions and the
	// whitelist use both; the family flags work without them).
	{"remove_range", "1", "setvar:tx.xg_soft=0,ctl:ruleRemoveById=941000-941999", ""},
	{"remove_by_tag", "1", "setvar:tx.xg_soft=0,ctl:ruleRemoveByTag=attack-xss", ""},
	// The family flag xPGuard's relaxations and exclusions set.
	{"family_flag", "1", "setvar:tx.xg_soft=0,setvar:tx.xg_no_xss=1", ""},
}

// IDScoreProbe: the self-test's score probes (/xpguard-crs-selftest/score/
// <body>_<threshold>): the relaxations' own test saves under fixed
// thresholds, to learn what the engine scores them (LiteSpeed has no
// libinjection; the scores differ from Apache's).
const IDScoreProbe = 7700850

var (
	scoreProbeBodies     = []string{"joomla", "wc", "xss"}
	scoreProbeThresholds = []int{20, 30, 45, 60, 100}
)

func mechProbeSetup() string {
	var b strings.Builder
	b.WriteString("# Self-test only: which ways of relaxing this engine honours (xPGuard).\n")
	for i, p := range mechProbes {
		act := "pass," + p.actions
		if p.actions == "allow" {
			act = "allow" // a disruptive action of its own, not with pass
		}
		fmt.Fprintf(&b, `SecRule REQUEST_FILENAME "@beginsWith %s/mech/%s" "id:%d,phase:%s,t:none,nolog,%s"`+"\n", crsTestPath, p.name, IDMechProbe+i, p.phase, act)
		if p.actions == "chain" {
			b.WriteString("  " + p.cond + ` "t:none,setvar:tx.xg_soft=0,setvar:tx.inbound_anomaly_score_threshold=10000"` + "\n")
		}
	}
	for bi, body := range scoreProbeBodies {
		for ti, t := range scoreProbeThresholds {
			fmt.Fprintf(&b, `SecRule REQUEST_FILENAME "@beginsWith %s/score/%s_%d" "id:%d,phase:1,pass,t:none,nolog,setvar:tx.xg_soft=0,setvar:tx.inbound_anomaly_score_threshold=%d"`+"\n",
				crsTestPath, body, t, IDScoreProbe+bi*10+ti, t)
		}
	}
	return b.String()
}

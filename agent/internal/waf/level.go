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
// are not blocked by the CRS for HTML and scripts; visitors on the IPDB, Tor
// or ban lists still are. The login cookie is only a hint (anyone can send
// one): outside the wp-admin screens WordPress guards itself, SQL, command,
// PHP and file inclusion attacks are still refused (IDEditorCap). This
// works by the anomaly threshold, which every ModSecurity engine (Apache,
// LiteSpeed) supports, not by rule removal.

const (
	IDEditorCookie = 7700040
	IDEditorAuth   = 7700041
	// IDWPUser marks a request of a logged-in WordPress user once, early
	// (tx.xg_wp_user any login cookie, tx.xg_wp_editor a real one or the
	// block editor's nonce); the other rules test these variables.
	IDWPUser = 7700046
	// IDWPArea marks requests to WordPress's admin (wp-admin/) and REST API
	// (wp-json/, or ?rest_route= on the front controller) by the path the
	// script is chosen by, never by text anywhere in the address
	// (tx.xg_wp_area, tx.xg_wp_rest for the REST API).
	IDWPArea = 7700060
	// IDWPCore marks requests WordPress checks the login of before any of
	// its own code handles them: wp-admin screens (not admin-ajax.php,
	// admin-post.php or async-upload.php, which run plugin hooks for
	// visitors too) and writes to core content routes of the REST API
	// (tx.xg_wp_core).
	IDWPCore = 7700061
	// IDWPEditing: a login cookie on the WordPress admin or REST API
	// (tx.xg_wp_editing; the IPDB and Tor POST rules skip these).
	IDWPEditing = 7700062
	// IDEditorCap: the login cookie, the WP nonce, Sec-Fetch-Site and the
	// Referer are sent by the client, so anyone can send them. A request
	// relaxed for an editor or an admin area outside WordPress's own login
	// check (admin-ajax.php, plugin REST routes, other applications' admin
	// areas) is still refused when the SQL, command, PHP or file inclusion
	// rules alone reach the level's threshold: only HTML and scripts
	// (what editors save) are let through.
	IDEditorCap = 7700050
	// IDWHMCSArea: saves from a WHMCS admin page (see IDWHMCSAdmin), by the
	// threshold instead of allow (+1000 told by Sec-Fetch-Site).
	IDWHMCSArea = 7700059
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
		`  SecRule &TX:xg_strict "@ge 1" "t:none,chain"` + "\n" +
		fmt.Sprintf(`  SecRule TX:inbound_anomaly_score_threshold "@lt %d" "t:none,setvar:tx.xg_soft=0,setvar:tx.inbound_anomaly_score_threshold=%d"`, sessionThreshold, sessionThreshold) + "\n" +
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
			`  SecRule &REQUEST_COOKIES "@gt 0" "t:none,chain"` + "\n" +
			fmt.Sprintf(`  SecRule REQUEST_HEADERS:Referer "@rx ^https?://([^/?#]+)/(?:[^?#]*/)?%s/" "t:none,t:lowercase,capture,chain"`, adminAreaSegments) + "\n" +
			`  SecRule TX:1 "@streq %{REQUEST_HEADERS.Host}" "t:none,t:lowercase,chain"` + "\n"
	}
	return "# Saves from a web application's own admin area (xPGuard WAF level).\n" +
		head(IDAdminArea) +
		fmt.Sprintf(`  SecRule &TX:xg_strict "@eq 0" "t:none,setvar:tx.xg_soft=0,setvar:tx.xg_session=0,setvar:tx.xg_editor=1,setvar:tx.inbound_anomaly_score_threshold=%d"`, editorThreshold) + "\n" +
		head(IDAdminArea+1000) +
		`  SecRule &TX:xg_strict "@ge 1" "t:none,chain"` + "\n" +
		fmt.Sprintf(`  SecRule TX:inbound_anomaly_score_threshold "@lt %d" "t:none,setvar:tx.xg_soft=0,setvar:tx.inbound_anomaly_score_threshold=%d"`, sessionThreshold, sessionThreshold) + "\n" +
		whmcsSetup()
}

// whmcsSetup: WHMCS admins save HTML and tracking code (General Settings,
// e-mail templates). Formerly let through whole (allow, which also skipped
// the upload scan); now by the threshold, so IDEditorCap still applies.
func whmcsSetup() string {
	head := func(id int) string {
		return fmt.Sprintf(`SecRule REQUEST_METHOD "@streq POST" "id:%d,phase:1,pass,t:none,nolog,chain"`, id) + "\n" +
			fmt.Sprintf(`  SecRule REQUEST_FILENAME "@rx /[^/]+/+(?:%s)\.php$" "t:none,t:urlDecodeUni,t:normalizePath,t:lowercase,chain"`, whmcsAdminFiles) + "\n" +
			`  SecRule REQUEST_COOKIES_NAMES "@rx ^whmcs[a-z0-9]{6,}$" "t:none,t:lowercase,chain"` + "\n"
	}
	set := fmt.Sprintf(`  SecRule &TX:xg_strict "@eq 0" "t:none,setvar:tx.xg_soft=0,setvar:tx.xg_session=0,setvar:tx.xg_editor=1,setvar:tx.inbound_anomaly_score_threshold=%d"`, editorThreshold) + "\n"
	return "# Saves from a WHMCS admin page (xPGuard WAF level).\n" +
		head(IDWHMCSArea) +
		`  SecRule REQUEST_HEADERS:Referer "@rx ^https?://([^/?#]+)/" "t:none,t:lowercase,capture,chain"` + "\n" +
		`  SecRule TX:1 "@streq %{REQUEST_HEADERS.Host}" "t:none,t:lowercase,chain"` + "\n" + set +
		head(IDWHMCSArea+1000) +
		`  SecRule REQUEST_HEADERS:Sec-Fetch-Site "@streq same-origin" "t:none,t:lowercase,chain"` + "\n" + set
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
		`  SecRule &TX:xg_strict "@eq 0" "t:none,chain"` + "\n" +
		fmt.Sprintf(`  SecRule TX:inbound_anomaly_score_threshold "@lt %d" "t:none,setvar:tx.xg_session=1,setvar:tx.xg_soft=0,setvar:tx.inbound_anomaly_score_threshold=%d"`, sessionThreshold, sessionThreshold) + "\n"
}

// sessionPost runs after the OWASP CRS: script injection in a relaxed
// same-site request is refused (stored XSS through a public form), and so
// is an attack other than HTML and scripts in a request relaxed for an
// editor or admin area by markers the client sends (in: the level's
// threshold).
func sessionPost(in int) string {
	return "# Script injection in a same-site request with a session (xPGuard WAF level).\n" +
		fmt.Sprintf(`SecRule TX:xg_session "@eq 1" "id:%d,phase:2,t:none,deny,status:403,log,msg:'xPGuard - Script injection in a same-site request blocked (XSS score: %%{tx.xss_score})',tag:'xpguard/crs',chain"`, IDSessionXSS) + "\n" +
		fmt.Sprintf(`  SecRule TX:xss_score "@ge %d" "t:none"`, sessionXSSCap) + "\n" +
		"# SQL, command, PHP and file inclusion attacks in a request relaxed for an editor or admin area (xPGuard WAF level).\n" +
		fmt.Sprintf(`SecRule TX:xg_editor "@eq 1" "id:%d,phase:2,t:none,deny,status:403,log,msg:'xPGuard - Attack in a request with an editor or admin session blocked (SQL %%{tx.sql_injection_score}, RCE %%{tx.rce_score}, PHP %%{tx.php_injection_score}, LFI %%{tx.lfi_score}, RFI %%{tx.rfi_score})',tag:'xpguard/crs',chain"`, IDEditorCap) + "\n" +
		`  SecRule &TX:xg_wp_core "@eq 0" "t:none,chain"` + "\n" +
		fmt.Sprintf(`  SecRule %s "@ge %d" "t:none"`, editorCapScores, in) + "\n"
}

// editorCapScores are the OWASP CRS attack scores (CRS 3 and 4 name them
// alike) that a client-sent editor marker never relaxes.
const editorCapScores = `TX:sql_injection_score|TX:rce_score|TX:php_injection_score|TX:lfi_score|TX:rfi_score`

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
		fmt.Sprintf(`SecRule REQUEST_HEADERS:X-WP-Nonce "@rx ^[0-9a-f]{10}$" "id:%d,phase:1,pass,t:none,t:lowercase,nolog,chain"`, IDWPUser+1000) + "\n" +
		`  SecRule REQUEST_HEADERS:Sec-Fetch-Site "@streq same-origin" "t:none,t:lowercase,chain"` + "\n" +
		`  SecRule REQUEST_HEADERS:Referer "@rx ^https?://([^/?#]+)/(?:[^?#]*/)?wp-admin/" "t:none,t:lowercase,capture,chain"` + "\n" +
		`  SecRule TX:1 "@streq %{REQUEST_HEADERS.Host}" "t:none,t:lowercase,setvar:tx.xg_wp_user=1,setvar:tx.xg_wp_editor=1"` + "\n" +
		wpAreaSetup()
}

// wpAreaSetup marks WordPress's admin and REST API by the script path
// (REQUEST_FILENAME) and the rest_route argument of the front controller:
// "rest_route=" or "/wp-admin/" anywhere else in the address (the query of
// any page, of any website) is not WordPress's admin.
func wpAreaSetup() string {
	rest := `setvar:tx.xg_wp_area=1,setvar:tx.xg_wp_rest=1`
	core := strings.Join(quoteAll(wpRestRoutes), "|")
	return fmt.Sprintf(`SecRule REQUEST_FILENAME "@rx /wp-admin/" "id:%d,phase:1,pass,t:none,t:urlDecodeUni,t:normalizePath,t:lowercase,nolog,setvar:tx.xg_wp_area=1"`, IDWPArea) + "\n" +
		fmt.Sprintf(`SecRule REQUEST_FILENAME "@rx /wp-json/" "id:%d,phase:1,pass,t:none,t:urlDecodeUni,t:normalizePath,t:lowercase,nolog,%s"`, IDWPArea+1000, rest) + "\n" +
		fmt.Sprintf(`SecRule &ARGS_GET:rest_route "@gt 0" "id:%d,phase:1,pass,t:none,nolog,chain"`, IDWPArea+2000) + "\n" +
		fmt.Sprintf(`  SecRule REQUEST_FILENAME "@rx (?:^|/)(?:index\.php)?$" "t:none,t:urlDecodeUni,t:normalizePath,t:lowercase,%s"`, rest) + "\n" +
		// WordPress itself checks the login first (auth_redirect, REST
		// permission callbacks of core content routes).
		fmt.Sprintf(`SecRule REQUEST_FILENAME "@rx /wp-admin/+(?:[^/]+\.php)?$" "id:%d,phase:1,pass,t:none,t:urlDecodeUni,t:normalizePath,t:lowercase,nolog,chain"`, IDWPCore) + "\n" +
		`  SecRule REQUEST_FILENAME "!@rx /(?:admin-ajax|admin-post|async-upload)\.php$" "t:none,t:urlDecodeUni,t:normalizePath,t:lowercase,setvar:tx.xg_wp_core=1"` + "\n" +
		fmt.Sprintf(`SecRule REQUEST_METHOD "@rx ^(?:POST|PUT|PATCH)$" "id:%d,phase:1,pass,t:none,nolog,chain"`, IDWPCore+1000) + "\n" +
		fmt.Sprintf(`  SecRule REQUEST_FILENAME "@rx /wp-json/+wp/v2/+(?:%s)(?:/|$)" "t:none,t:urlDecodeUni,t:normalizePath,t:lowercase,setvar:tx.xg_wp_core=1"`, core) + "\n" +
		fmt.Sprintf(`SecRule REQUEST_METHOD "@rx ^(?:POST|PUT|PATCH)$" "id:%d,phase:1,pass,t:none,nolog,chain"`, IDWPCore+2000) + "\n" +
		`  SecRule REQUEST_FILENAME "@rx (?:^|/)(?:index\.php)?$" "t:none,t:urlDecodeUni,t:normalizePath,t:lowercase,chain"` + "\n" +
		fmt.Sprintf(`  SecRule ARGS_GET:rest_route "@rx ^/*wp/v2/+(?:%s)(?:/|$)" "t:none,t:urlDecodeUni,t:lowercase,setvar:tx.xg_wp_core=1"`, core) + "\n" +
		fmt.Sprintf(`SecRule TX:xg_wp_user "@eq 1" "id:%d,phase:1,pass,t:none,nolog,chain"`, IDWPEditing) + "\n" +
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

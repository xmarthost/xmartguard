package waf

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/xmarthost/xmartguard/agent/internal/settings"
)

// Exclusions: requests that legitimately carry HTML, JavaScript or code are
// kept away from the injection rules of the OWASP CRS (and other rule sets
// that use the same tags). They are written at the top of the rules file so
// they run before any rule they switch off.
const (
	// IDWPAdminExcl: WordPress admin screens of a logged-in user (WPCode,
	// theme options, page builders save scripts and HTML by design).
	IDWPAdminExcl = 7700010
	// IDWPAjaxExcl: admin-ajax.php and admin-post.php called from the admin
	// screens (editors save through them).
	IDWPAjaxExcl = 7700011
	// IDWPRestExcl: writes to WordPress core content routes of the REST API
	// (block editor, apps and site management tools with application
	// passwords). Core checks the user's rights on these routes itself.
	IDWPRestExcl = 7700012
	// IDWPRestMethods: the REST API uses PUT, PATCH and DELETE and the
	// X-HTTP-Method-Override header (Elementor, WooCommerce block checkout),
	// which the CRS refuses by default.
	IDWPRestMethods = 7700013
	// IDWCStoreExcl: WooCommerce Store API (block cart and checkout): the
	// PHP-injection rules skip it; addresses and order notes trip them, and
	// the data is stored, never run as code.
	IDWCStoreExcl = 7700014
	// IDHostingBase: CRS rules that misfire on ordinary hosting traffic
	// and catch no attack the others miss: 941310 (UTF-8 text such as Urdu,
	// Arabic or emoji in comments, reviews and forms looks like "malformed
	// US-ASCII"), 920600 (search engines and feed readers send a charset in
	// Accept) and 942550 on cookies (consent and shop plugins keep JSON there).
	IDHostingBase = 7700015
	// IDCPanelPaths: cPanel's own pages (mail autodiscover/autoconfig for
	// Outlook and Thunderbird, suspended page, AutoSSL checks) are reached by
	// the server's address, which the CRS numeric-Host rule refuses.
	IDCPanelPaths = 7700016
	// IDStaticCookies: images, styles and scripts are files, not code; the
	// cookies a browser sends with them are not inspected for injections.
	IDStaticCookies = 7700017
	// IDAdminPanel: admin areas of other web applications (SMM panels,
	// Laravel and CodeIgniter back ends, school and shop panels) save HTML,
	// emoji and scripts on purpose: POSTs from a page of the same admin area,
	// with a session cookie, skip the injection rules (the application checks
	// the login itself).
	IDAdminPanel = 7700018
	// IDWPCommentText: the text, name and website of a WordPress comment or
	// WooCommerce review skip the SQL-injection rules. Reviews read like SQL
	// to them ("sweet -- woody; select it if…"), and WordPress stores
	// comments with prepared statements; the XSS and other rules still check
	// them.
	IDWPCommentText = 7700019
	// IDCPanelOff: websites whose ModSecurity the account switched off in
	// cPanel » ModSecurity. Apache already honours that for its virtual host;
	// this makes it certain for every rule set and on LiteSpeed.
	IDCPanelOff = 7700005
	// IDRuleExcl is the first id of the portal's per-site rule exclusions
	// (7704000-7704499) and IDAutoExcl of the learned ones (7704500-7704999).
	IDRuleExcl = 7704000
	IDAutoExcl = 7704500
	// maxAutoExcl is how many learned exclusions a server renders.
	maxAutoExcl = 500
)

// Dynamic are the exclusions this server finds itself rather than the
// portal's settings: learned false positives and cPanel's switches.
type Dynamic struct {
	Auto      []settings.RuleExclusion
	CPanelOff []string
}

// injectionTags are the CRS tags of rules that inspect request content for
// injected code; false positives on real content come from these.
var injectionTags = []string{"attack-xss", "attack-sqli", "attack-rce", "attack-injection-php", "attack-injection-generic",
	"attack-rfi", "attack-lfi", "attack-generic", "attack-fixation"}

// wpRestRoutes are core REST routes whose writes need a logged-in user
// with the right to edit (the comments route is not here: visitors may post).
var wpRestRoutes = []string{"posts", "pages", "blocks", "templates", "template-parts", "global-styles", "navigation",
	"menus", "menu-items", "widgets", "sidebars", "media", "settings", "font-families", "font-collections"}

// overrideTargets lets the method override headers through the CRS
// restricted-header rule (920450 reads the header names in its first link).
func overrideTargets() string {
	var ctl []string
	for _, h := range []string{"x-http-method-override", "x-http-method", "x-method-override"} {
		ctl = append(ctl, "ctl:ruleRemoveTargetById=920450;REQUEST_HEADERS_NAMES:"+h)
	}
	return strings.Join(ctl, ",")
}

func removeTags() string {
	var ctl []string
	for _, t := range injectionTags {
		ctl = append(ctl, "ctl:ruleRemoveByTag="+t)
	}
	return strings.Join(ctl, ",")
}

// removeTagTargets keeps the injection rules away from one collection.
func removeTagTargets(target string) string {
	var ctl []string
	for _, t := range injectionTags {
		ctl = append(ctl, "ctl:ruleRemoveTargetByTag="+t+";"+target)
	}
	return strings.Join(ctl, ",")
}

// adminSegments name the admin area of a web application (wp-admin has its
// own exclusions).
const adminSegments = `(?:admin|administrator|adminpanel|admin-panel|backend|dashboard|panel)`

// staticExts are files a web server sends as they are.
const staticExts = `(?:png|jpe?g|gif|webp|avif|svg|ico|bmp|css|js|mjs|map|woff2?|ttf|otf|eot|mp4|webm|mp3|ogg|pdf|txt|xml)`

// renderExclusions writes the WordPress exclusions (unless switched off)
// and the portal's per-site rule exclusions.
func renderExclusions(w func(string, ...any), c settings.WAF, off map[int]bool, dyn Dynamic) {
	tags := removeTags()
	w("# Ordinary hosting traffic the OWASP CRS misreads (xPGuard hosting defaults).")
	if !off[IDHostingBase] {
		w(`SecAction "id:%d,phase:1,pass,nolog,ctl:ruleRemoveById=941310,ctl:ruleRemoveById=920600,ctl:ruleRemoveTargetById=942550;REQUEST_COOKIES"`, IDHostingBase)
	}
	if !off[IDCPanelPaths] {
		w(`SecRule REQUEST_FILENAME "@rx ^/+(?:cgi-sys/|\.well-known/|autodiscover/autodiscover\.xml$|mail/config-v1\.1\.xml$)" "id:%d,phase:1,t:none,t:urlDecodeUni,t:lowercase,pass,nolog,ctl:ruleRemoveById=920350"`, IDCPanelPaths)
	}
	if !off[IDStaticCookies] {
		w(`SecRule REQUEST_METHOD "@rx ^(?:GET|HEAD)$" "id:%d,phase:1,t:none,pass,nolog,chain"`, IDStaticCookies)
		w(`  SecRule REQUEST_FILENAME "@rx \.%s$" "t:none,t:urlDecodeUni,t:lowercase,%s"`, staticExts, removeTagTargets("REQUEST_COOKIES"))
	}
	if !off[IDWPCommentText] {
		w(`SecRule REQUEST_FILENAME "@rx /wp-comments-post\.php$" "id:%d,phase:1,t:none,t:urlDecodeUni,t:lowercase,pass,nolog,ctl:ruleRemoveTargetByTag=attack-sqli;ARGS:comment,ctl:ruleRemoveTargetByTag=attack-sqli;ARGS:author,ctl:ruleRemoveTargetByTag=attack-sqli;ARGS:url"`, IDWPCommentText)
	}
	if !off[IDAdminPanel] {
		w(`SecRule REQUEST_METHOD "@streq POST" "id:%d,phase:1,t:none,pass,nolog,chain"`, IDAdminPanel)
		w(`  SecRule REQUEST_FILENAME "@rx (?:^|/)%s/" "t:none,t:urlDecodeUni,t:lowercase,chain"`, adminSegments)
		w(`  SecRule &REQUEST_COOKIES "@gt 0" "t:none,chain"`)
		w(`  SecRule REQUEST_HEADERS:Referer "@rx ^https?://([^/?#]+)/(?:[^?#]*/)?%s/" "t:none,t:lowercase,capture,chain"`, adminSegments)
		w(`  SecRule TX:1 "@streq %%{REQUEST_HEADERS.Host}" "t:none,t:lowercase,%s"`, tags)
	}
	w("# Content that is code by design: kept away from injection rules.")
	if !off[IDWPAdminExcl] {
		w(`SecRule REQUEST_FILENAME "@rx /wp-admin/+(?:[^/]+\.php)?$" "id:%d,phase:1,t:none,t:urlDecodeUni,t:lowercase,pass,nolog,chain"`, IDWPAdminExcl)
		w(`  SecRule REQUEST_FILENAME "!@rx /(?:admin-ajax|admin-post|async-upload)\.php$" "t:none,t:urlDecodeUni,t:lowercase,chain"`)
		w(`  SecRule &REQUEST_COOKIES_NAMES:/^wordpress_logged_in_/ "@gt 0" "t:none,%s"`, tags)
	}
	if !off[IDWPAjaxExcl] {
		w(`SecRule REQUEST_FILENAME "@rx /wp-admin/+(?:admin-ajax|admin-post)\.php$" "id:%d,phase:1,t:none,t:urlDecodeUni,t:lowercase,pass,nolog,chain"`, IDWPAjaxExcl)
		w(`  SecRule REQUEST_HEADERS:Referer "@contains /wp-admin/" "t:none,t:lowercase,chain"`)
		w(`  SecRule &REQUEST_COOKIES_NAMES:/^wordpress_logged_in_/ "@gt 0" "t:none,%s"`, tags)
	}
	if !off[IDWPRestExcl] {
		w(`SecRule REQUEST_METHOD "@rx ^(?:POST|PUT|PATCH)$" "id:%d,phase:1,t:none,pass,nolog,chain"`, IDWPRestExcl)
		w(`  SecRule REQUEST_URI "@rx (?:/wp-json/+|[?&]rest_route=/*)wp/v2/+(?:%s)(?:[/?&]|$)" "t:none,t:urlDecodeUni,t:lowercase,%s"`, strings.Join(quoteAll(wpRestRoutes), "|"), tags)
	}
	if !off[IDWPRestMethods] {
		w(`SecRule REQUEST_URI "@rx (?:/wp-json/|[?&]rest_route=)" "id:%d,phase:1,t:none,t:urlDecodeUni,t:lowercase,pass,nolog,ctl:ruleRemoveById=911100,%s"`, IDWPRestMethods, overrideTargets())
	}
	if !off[IDWCStoreExcl] {
		w(`SecRule REQUEST_URI "@rx (?:/wp-json/+|[?&]rest_route=/*)wc/store/" "id:%d,phase:1,t:none,t:urlDecodeUni,t:lowercase,pass,nolog,ctl:ruleRemoveByTag=attack-injection-php"`, IDWCStoreExcl)
	}
	writeExcl := func(id int, e settings.RuleExclusion) {
		ctl := fmt.Sprintf("ctl:ruleRemoveById=%d", e.Rule)
		switch {
		case e.Domain != "" && e.Path != "":
			w(`SecRule SERVER_NAME "@rx %s" "id:%d,phase:1,t:none,t:lowercase,pass,nolog,chain"`, domainRx(e.Domain), id)
			w(`  SecRule REQUEST_FILENAME "@beginsWith %s" "t:none,t:urlDecodeUni,%s"`, e.Path, ctl)
		case e.Domain != "":
			w(`SecRule SERVER_NAME "@rx %s" "id:%d,phase:1,t:none,t:lowercase,pass,nolog,%s"`, domainRx(e.Domain), id, ctl)
		case e.Path != "":
			w(`SecRule REQUEST_FILENAME "@beginsWith %s" "id:%d,phase:1,t:none,t:urlDecodeUni,pass,nolog,%s"`, e.Path, id, ctl)
		default:
			w(`SecAction "id:%d,phase:1,pass,nolog,%s"`, id, ctl)
		}
	}
	for i, e := range settings.CleanExclusions(c.RuleExclusions) {
		if allowRule(e.Rule) {
			continue // switching off an allow rule only blocks more
		}
		writeExcl(IDRuleExcl+i, e)
	}
	if !off[IDAutoExcl] {
		auto := settings.CleanExclusions(dyn.Auto)
		if len(auto) > 0 {
			w("# False positives learned on this server (xPGuard portal » Settings » WAF).")
		}
		for i, e := range auto {
			if i >= maxAutoExcl {
				break
			}
			writeExcl(IDAutoExcl+i, e)
		}
	}
	w("")
}

// renderCPanelOff switches the rule engine off for the websites whose
// ModSecurity is off in cPanel; it is the first rule of the file.
func renderCPanelOff(w func(string, ...any), dyn Dynamic) {
	var alt []string
	for _, d := range dyn.CPanelOff {
		d = strings.ToLower(strings.TrimPrefix(d, "www."))
		if settings.ValidDomain(d) && !strings.HasPrefix(d, "*.") {
			alt = append(alt, regexp.QuoteMeta(d))
		}
	}
	if len(alt) == 0 {
		return
	}
	w("# ModSecurity switched off for these websites in cPanel » ModSecurity.")
	w(`SecRule SERVER_NAME "@rx ^(?:www\.)?(?:%s)$" "id:%d,phase:1,t:none,t:lowercase,pass,nolog,ctl:ruleEngine=Off"`, strings.Join(alt, "|"), IDCPanelOff)
	w("")
}

// domainRx matches a website and its www name; "*.example.com" matches
// example.com and all its subdomains.
func domainRx(d string) string {
	if strings.HasPrefix(d, "*.") {
		return `^(?:[^.]+\.)*` + regexp.QuoteMeta(d[2:]) + `$`
	}
	return `^(?:www\.)?` + regexp.QuoteMeta(d) + `$`
}

// allowRule reports xPGuard's exclusion rules (they let requests through).
func allowRule(id int) bool {
	return (id >= IDWPAdminExcl && id <= IDAdminPanel) || id == IDEditorCookie || id == IDEditorAuth || id == IDAutodiscover
}

// RenderExclusionsOnly is the rules file when xPGuard's own rules are off
// but other rule sets (OWASP CRS, custom rules) are loaded after it.
func RenderExclusionsOnly(c settings.WAF, dyn Dynamic) string {
	var b strings.Builder
	off := map[int]bool{}
	for _, id := range c.DisabledRules {
		off[id] = true
	}
	w := func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }
	b.WriteString("# xPGuard's own rules are turned off; rule sets from the portal follow.\n")
	renderCPanelOff(w, dyn)
	renderExclusions(w, c, off, dyn)
	return b.String()
}

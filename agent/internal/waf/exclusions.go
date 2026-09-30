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
	// IDRuleExcl is the first id of the portal's per-site rule exclusions.
	IDRuleExcl = 7700020
)

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

// renderExclusions writes the WordPress exclusions (unless switched off)
// and the portal's per-site rule exclusions.
func renderExclusions(w func(string, ...any), c settings.WAF, off map[int]bool) {
	tags := removeTags()
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
	id := IDRuleExcl
	for _, e := range settings.CleanExclusions(c.RuleExclusions) {
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
		id++
	}
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

// RenderExclusionsOnly is the rules file when xPGuard's own rules are off
// but other rule sets (OWASP CRS, custom rules) are loaded after it.
func RenderExclusionsOnly(c settings.WAF) string {
	var b strings.Builder
	off := map[int]bool{}
	for _, id := range c.DisabledRules {
		off[id] = true
	}
	b.WriteString("# xPGuard's own rules are turned off; rule sets from the portal follow.\n")
	renderExclusions(func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }, c, off)
	return b.String()
}

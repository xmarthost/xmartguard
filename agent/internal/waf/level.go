package waf

import "fmt"

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
		fmt.Sprintf(`SecRule REQUEST_URI "@rx (?:/wp-admin/|/wp-json/|[?&]rest_route=)" "id:%d,phase:1,pass,t:none,t:urlDecodeUni,t:lowercase,nolog,chain"`, IDEditorCookie) + "\n" +
		`  SecRule REQUEST_COOKIES_NAMES "@rx ^wordpress_logged_in_[0-9a-f]{32}$" "t:none,chain"` + "\n  " + set + "\n" +
		fmt.Sprintf(`SecRule REQUEST_URI "@rx (?:/wp-json/|[?&]rest_route=)" "id:%d,phase:1,pass,t:none,t:urlDecodeUni,t:lowercase,nolog,chain"`, IDEditorAuth) + "\n" +
		`  SecRule REQUEST_HEADERS:Authorization "@rx ^(?:basic|bearer)\s+\S{8,}" "t:none,t:lowercase,chain"` + "\n  " + set + "\n"
}

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
		`  SecRule REQUEST_COOKIES_NAMES "@rx (?i)(?:sess|sid$|xsrf|csrf|token|logged_in|auth|remember)" "t:none,chain"` + "\n" +
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
// same-site request is refused (stored XSS through a public form).
func sessionPost() string {
	return "# Script injection in a same-site request with a session (xPGuard WAF level).\n" +
		fmt.Sprintf(`SecRule TX:xg_session "@eq 1" "id:%d,phase:2,t:none,deny,status:403,log,msg:'xPGuard - Script injection in a same-site request blocked (XSS score: %%{tx.xss_score})',tag:'xpguard/crs',chain"`, IDSessionXSS) + "\n" +
		fmt.Sprintf(`  SecRule TX:xss_score "@ge %d" "t:none"`, sessionXSSCap) + "\n"
}

// AllowedMethods are the HTTP methods the OWASP CRS lets through.
const AllowedMethods = "GET HEAD POST OPTIONS PUT PATCH DELETE"

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

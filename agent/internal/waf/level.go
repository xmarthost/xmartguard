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

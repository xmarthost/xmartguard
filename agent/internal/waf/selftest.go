package waf

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Rules that are "installed" are not necessarily enforced: the include may
// not be loaded, the engine may be off, or the server may not have been
// reloaded. After every change the agent asks the local web server for a
// test URL that a rule of ours denies (and, with OWASP CRS, a harmless
// attack-looking query that CRS must block) and reports what came back.

// IDSelfTest is the rule that denies the self-test URL. It comes first,
// before the whitelist rules can switch rules off.
const IDSelfTest = 7700000

const selfTestPath = "/xpguard-waf-selftest"
const crsTestPath = "/xpguard-crs-selftest"

var selfTestRule = fmt.Sprintf(`SecRule REQUEST_FILENAME "@beginsWith %s" "id:%d,phase:1,t:none,deny,status:403,log,msg:'xPGuard - WAF self-test'"`, selfTestPath, IDSelfTest)

// SelfTest is the result of the last check.
type SelfTest struct {
	At     int64  `json:"at"`
	OK     bool   `json:"ok"`
	Status int    `json:"status"`
	Detail string `json:"detail,omitempty"`
	// CRS: "" when OWASP CRS is not active, else "blocked" or the problem.
	CRS string `json:"crs,omitempty"`
	// Lifts: whether the engine lets through the saves xPGuard's
	// relaxations are for ("passes", or "refused (HTTP 403)"): a rule a
	// web server's engine reads differently shows here (joomlashares.com
	// on LiteSpeed: the header-based lifts never applied).
	Lifts map[string]string `json:"lifts,omitempty"`
	// Ways: which ways of relaxing the engine honours (mechProbes).
	Ways map[string]string `json:"ways,omitempty"`
}

// isSelfTest reports whether an event came from the agent's own check.
func isSelfTest(e Event) bool {
	return e.RuleID == IDSelfTest || strings.Contains(e.URI, selfTestPath) || strings.Contains(e.URI, crsTestPath) ||
		// Names used before xPGuard (old log lines).
		strings.Contains(e.URI, "/xmartguard-waf-selftest") || strings.Contains(e.URI, "/xmartguard-crs-selftest")
}

// SelfTestURLs are tried in order (variables for tests).
var SelfTestURLs = []string{"http://127.0.0.1", "https://127.0.0.1"}

func probe(path string) (int, error) {
	code, _, err := probeLoc(path)
	return code, err
}

// probePost posts a form body (tests of the relaxations).
func probePost(path, body string) (int, error) {
	c := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // local self-test only
			Proxy:           nil,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	var last error
	for _, base := range SelfTestURLs {
		req, err := http.NewRequest("POST", base+path, strings.NewReader(body))
		if err != nil {
			return 0, err
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (xPGuard WAF self-test)")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		res, err := c.Do(req)
		if err != nil {
			last = err
			continue
		}
		res.Body.Close()
		return res.StatusCode, nil
	}
	return 0, last
}

// liftChecks posts what a relaxation is for and must let through, with
// signals the CRS alone refuses: a Joomla administrator save with its form
// token and a WooCommerce REST product write with API keys.
func liftChecks() map[string]string {
	token := "0123456789abcdef0123456789abcdef=1"
	checks := map[string]struct{ path, body string }{
		"joomla_admin_save": {crsTestPath + "/administrator/index.php?option=com_admintools&view=htaccessmaker",
			"task=apply&custhead=" + url.QueryEscape("RewriteCond %{HTTP_USER_AGENT} (wget|curl|python-requests|libwww-perl) [NC]\nRewriteRule .* - [F]") +
				"&cgibin=" + url.QueryEscape("/usr/local/cgi-bin/php.cgi") + "&exceptiondirs=" + url.QueryEscape("cli\nbin\ntmp") + "&" + token},
		"woocommerce_api_write": {crsTestPath + "/wp-json/wc/v3/products?consumer_key=ck_" + strings.Repeat("0a", 20) + "&consumer_secret=cs_" + strings.Repeat("1b", 20),
			"name=Shoes&description=" + url.QueryEscape(`<p onclick="zoom()">Leather shoes</p><img src="x.jpg" onerror="this.style.display='none'">`)},
	}
	out := map[string]string{}
	for name, c := range checks {
		code, err := probePost(c.path, c.body)
		switch {
		case err != nil:
			out[name] = err.Error()
		case code == 403 || code == 406 || (code >= 300 && code < 400):
			out[name] = fmt.Sprintf("refused (HTTP %d)", code)
		default:
			out[name] = "passes"
		}
	}
	return out
}

// probeLoc also returns the redirect target of a 3xx answer.
func probeLoc(path string) (int, string, error) {
	c := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // local self-test only
			Proxy:           nil,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	var last error
	for _, base := range SelfTestURLs {
		req, err := http.NewRequest("GET", base+path, nil)
		if err != nil {
			return 0, "", err
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (xPGuard WAF self-test)")
		res, err := c.Do(req)
		if err != nil {
			last = err
			continue
		}
		res.Body.Close()
		return res.StatusCode, res.Header.Get("Location"), nil
	}
	return 0, "", last
}

// crsProbeQuery is an obvious attack in several classes at once (XSS,
// SQL injection, path traversal, command injection), so it is blocked at
// every WAF level (anomaly threshold up to 20) and by every engine, also
// where some CRS rules do not fire (LiteSpeed has no libinjection).
func crsProbeQuery() string {
	return url.Values{
		"q":    {"<script>alert(document.cookie)</script>"},
		"id":   {"1' UNION SELECT user,password FROM users-- -"},
		"file": {"../../../../etc/passwd"},
		"cmd":  {";cat /etc/passwd"},
	}.Encode()
}

// runSelfTest checks the rules are enforced. LiteSpeed and Apache may take a
// few seconds to reload, so a pass is retried for up to wait.
// captchaURL is the central CAPTCHA page: with soft blocking on, OWASP
// CRS sends GET requests with a weak attack signal there instead of
// answering 403, which counts as blocked too.
func runSelfTest(crs bool, captchaURL string, wait time.Duration) SelfTest {
	st := SelfTest{At: time.Now().Unix()}
	deadline := time.Now().Add(wait)
	for {
		code, err := probe(selfTestPath + "?t=" + fmt.Sprint(time.Now().UnixNano()))
		st.Status = code
		switch {
		case err != nil:
			st.OK, st.Detail = false, "the web server did not answer on 127.0.0.1 ("+err.Error()+")"
		case code == 403 || code == 406:
			st.OK, st.Detail = true, ""
		default:
			st.OK = false
			st.Detail = fmt.Sprintf("the rules are installed but the web server does not apply them (a test request that must be blocked got HTTP %d). "+
				"Check that ModSecurity is enabled (WHM » ModSecurity Configuration: Rules Engine = On) and restart the web server.", code)
		}
		if st.OK || time.Now().After(deadline) {
			break
		}
		time.Sleep(3 * time.Second)
	}
	if st.OK && crs {
		q := crsProbeQuery()
		code, loc, err := probeLoc(crsTestPath + "?" + q)
		switch {
		case err != nil:
			st.CRS = err.Error()
		case code == 403 || code == 406:
			st.CRS = "blocked"
		case code >= 300 && code < 400 && captchaURL != "" && strings.HasPrefix(loc, captchaURL):
			st.CRS = "blocked" // sent to the CAPTCHA (soft blocking)
		default:
			st.CRS = fmt.Sprintf("OWASP CRS did not block a test XSS request (HTTP %d); check the paranoia level and anomaly threshold", code)
		}
		if st.CRS == "blocked" {
			st.Lifts = liftChecks()
			st.Ways = wayChecks()
		}
	}
	return st
}

// wayChecks posts the same weak attack (script in a form field, refused at
// the default threshold) to each way's probe address.
func wayChecks() map[string]string {
	// With a form token and a key in the address for the cond probes.
	body := "description=" + url.QueryEscape(`<p onclick="zoom()">Leather shoes</p><img src="x.jpg" onerror="this.style.display='none'">`) +
		"&0123456789abcdef0123456789abcdef=1"
	key := "?k=ck_" + strings.Repeat("0a", 20)
	out := map[string]string{}
	if code, err := probePost(crsTestPath+"/mech/none"+key, body); err == nil {
		out["none"] = fmt.Sprintf("HTTP %d", code)
	}
	for _, p := range mechProbes {
		code, err := probePost(crsTestPath+"/mech/"+p.name+key, body)
		switch {
		case err != nil:
			out[p.name] = err.Error()
		case code == 403 || code == 406 || (code >= 300 && code < 400):
			out[p.name] = fmt.Sprintf("refused (HTTP %d)", code)
		default:
			out[p.name] = "passes"
		}
	}
	return out
}

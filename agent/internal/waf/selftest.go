package waf

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
	// Scores: whether each test save passes under each threshold (its
	// score is below the lowest that passes).
	Scores map[string]string `json:"scores,omitempty"`
	// Multipart: which parts of an upload form the engine shows to rules
	// ("seen" or "not seen"; multipartProbes).
	Multipart map[string]string `json:"multipart,omitempty"`
}

// isSelfTest reports whether an event came from the agent's own check:
// a self-test path asked from this server (the agent asks 127.0.0.1).
// Before, any request whose address merely contained the name (also in
// its query string) was never counted or banned, so an attacker could
// add "&x=/xpguard-waf-selftest" to every attack (2026-11-05).
func isSelfTest(e Event) bool {
	if e.IP != "" {
		if ip := net.ParseIP(e.IP); ip == nil || !ip.IsLoopback() {
			return false
		}
	}
	path := e.URI
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}
	for _, p := range []string{selfTestPath, crsTestPath,
		// Names used before xPGuard (old log lines).
		"/xmartguard-waf-selftest", "/xmartguard-crs-selftest"} {
		if path == p || strings.HasPrefix(path, p+"/") {
			return true
		}
	}
	return e.RuleID == IDSelfTest
}

// probeHeader carries the agent's key on its self-test requests; the
// probe rules relax only for it (probeGuard).
const probeHeader = "X-XPGuard-Probe"

var (
	probeKeyMu sync.Mutex
	probeKey   string
)

// loadProbeKey reads the self-test key from dir (made once, root only)
// and uses it for the probe rules and requests.
func loadProbeKey(dir string) string {
	probeKeyMu.Lock()
	defer probeKeyMu.Unlock()
	f := filepath.Join(dir, "selftest.key")
	if b, err := os.ReadFile(f); err == nil {
		if k := strings.TrimSpace(string(b)); len(k) == 32 {
			probeKey = k
			return k
		}
	}
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return probeKey
	}
	k := hex.EncodeToString(buf)
	if err := os.WriteFile(f, []byte(k+"\n"), 0o600); err != nil {
		// No place to keep it: a key for this run (the next apply
		// renders the rules with it again).
		if probeKey == "" {
			probeKey = k
		}
		return probeKey
	}
	probeKey = k
	return k
}

// currentProbeKey is the key in use (a fresh one if none was loaded).
func currentProbeKey() string {
	probeKeyMu.Lock()
	k := probeKey
	probeKeyMu.Unlock()
	if k != "" {
		return k
	}
	buf := make([]byte, 16)
	rand.Read(buf)
	probeKeyMu.Lock()
	defer probeKeyMu.Unlock()
	if probeKey == "" {
		probeKey = hex.EncodeToString(buf)
	}
	return probeKey
}

// probeGuard is the condition every relaxing probe rule chains to.
func probeGuard() string {
	return fmt.Sprintf(`SecRule REQUEST_HEADERS:%s "@streq %s"`, probeHeader, currentProbeKey())
}

// SelfTestURLs are tried in order (variables for tests).
var SelfTestURLs = []string{"http://127.0.0.1", "https://127.0.0.1"}

func probe(path string) (int, error) {
	code, _, err := probeLoc(path)
	return code, err
}

// probePost posts a form body (tests of the relaxations).
func probePost(path, body string) (int, error) {
	return probePostType(path, "application/x-www-form-urlencoded", body)
}

// probePostType posts a body of the given content type.
func probePostType(path, ctype, body string) (int, error) {
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
		req.Header.Set("Content-Type", ctype)
		req.Header.Set(probeHeader, currentProbeKey())
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
// The relaxations' test saves (also posted to the score probes), and the
// ways' weak attack, with a form token for the cond probes.
var (
	wayBody = "description=" + url.QueryEscape(`<p onclick="zoom()">Leather shoes</p><img src="x.jpg" onerror="this.style.display='none'">`) +
		"&0123456789abcdef0123456789abcdef=1"
	liftBodyJoomla = "task=apply&custhead=" + url.QueryEscape("RewriteCond %{HTTP_USER_AGENT} (wget|curl|python-requests|libwww-perl) [NC]\nRewriteRule .* - [F]") +
		"&cgibin=" + url.QueryEscape("/usr/local/cgi-bin/php.cgi") + "&exceptiondirs=" + url.QueryEscape("cli\nbin\ntmp") + "&0123456789abcdef0123456789abcdef=1"
	liftBodyWC = "name=Shoes&description=" + url.QueryEscape(`<p onclick="zoom()">Leather shoes</p><img src="x.jpg" onerror="this.style.display='none'">`)
)

func liftChecks() map[string]string {
	checks := map[string]struct{ path, body string }{
		"joomla_admin_save": {crsTestPath + "/administrator/index.php?option=com_admintools&view=htaccessmaker", liftBodyJoomla},
		"woocommerce_api_write": {crsTestPath + "/wp-json/wc/v3/products?consumer_key=ck_" + strings.Repeat("0a", 20) + "&consumer_secret=cs_" + strings.Repeat("1b", 20),
			liftBodyWC},
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
		req.Header.Set(probeHeader, currentProbeKey())
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
			st.Scores = scoreChecks()
			st.Multipart = multipartChecks()
		}
	}
	return st
}

// wayChecks posts the same weak attack (script in a form field, refused at
// the default threshold) to each way's probe address.
func wayChecks() map[string]string {
	body := wayBody
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

// scoreChecks posts each test save under each fixed threshold.
func scoreChecks() map[string]string {
	bodies := map[string]string{"joomla": liftBodyJoomla, "wc": liftBodyWC, "xss": wayBody}
	out := map[string]string{}
	for _, b := range scoreProbeBodies {
		for _, t := range scoreProbeThresholds {
			name := fmt.Sprintf("%s_%d", b, t)
			code, err := probePost(fmt.Sprintf("%s/score/%s", crsTestPath, name), bodies[b])
			switch {
			case err != nil:
				out[name] = err.Error()
			case code == 403 || code == 406 || (code >= 300 && code < 400):
				out[name] = fmt.Sprintf("refused (HTTP %d)", code)
			default:
				out[name] = "passes"
			}
		}
	}
	return out
}

// multipartBoundary and multipartBody: an upload form with a text field and
// a small text file whose part names a Content-Transfer-Encoding (what
// CRS 922120 looks for). Harmless.
const multipartBoundary = "xgprobe7MA4YWxkTrZu0gW"

var multipartBody = strings.Join([]string{
	"--" + multipartBoundary,
	`Content-Disposition: form-data; name="xg_field"`,
	"",
	"xg-mp-value",
	"--" + multipartBoundary,
	`Content-Disposition: form-data; name="xg_upload"; filename="xg-probe.txt"`,
	"Content-Type: text/plain",
	"Content-Transfer-Encoding: 8bit",
	"",
	"xPGuard self-test",
	"--" + multipartBoundary + "--",
	"",
}, "\r\n")

// multipartChecks posts the upload to each multipart probe: refused means
// the engine showed the rule what it tests.
func multipartChecks() map[string]string {
	out := map[string]string{}
	ct := "multipart/form-data; boundary=" + multipartBoundary
	// The control: no probe rule; refused means something else refuses
	// the upload and the answers below say nothing.
	if code, err := probePostType(crsTestPath+"/mp/none", ct, multipartBody); err != nil || code == 403 {
		return map[string]string{"none": fmt.Sprintf("refused (HTTP %d): the probes are unreliable", code)}
	}
	for _, p := range multipartProbes {
		code, err := probePostType(crsTestPath+"/mp/"+p.name, ct, multipartBody)
		switch {
		case err != nil:
			out[p.name] = err.Error()
		case code == 403:
			out[p.name] = "seen"
		default:
			out[p.name] = "not seen"
		}
	}
	return out
}

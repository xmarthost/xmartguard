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
		q := url.Values{"q": {"<script>alert(document.cookie)</script>"}}.Encode()
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
	}
	return st
}

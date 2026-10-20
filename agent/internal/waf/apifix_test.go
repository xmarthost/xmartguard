package waf

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/xmarthost/xmartguard/agent/internal/settings"
)

// Blocks only by CRS protocol/policy rules (a beacon's content type, a
// broken font link) never get the visitor banned; attacks still do.
func TestPolicyOnlyBlocksDoNotBan(t *testing.T) {
	for d, want := range map[string]bool{
		"Matched rules: 920420":         true,
		"Matched rules: 920440, 920420": true,
		"Matched rules: 920440, 930130": false,
		"Matched rules: 942100":         false,
		"":                              false,
		"something else 920420":         false,
	} {
		if got := policyOnly(Event{Detail: d}); got != want {
			t.Errorf("%q: %v", d, got)
		}
	}
	if !noBanRules[IDIPDBPost] {
		t.Error("IPDB POST blocks ban the address")
	}
}

// API calls with an Authorization, key or signature header skip the IPDB
// POST rule; the rule itself stays.
func TestIPDBPostSkipsAPICalls(t *testing.T) {
	c := settings.Defaults().WAF
	c.Enabled, c.IPDBPost = true, true
	out := Render(c, Options{Dir: "/r"})
	l := ruleLine(out, IDIPDBPostAPI)
	if !strings.Contains(l, "REQUEST_HEADERS_NAMES") || !strings.Contains(l, "ctl:ruleRemoveById=7700711,ctl:ruleRemoveById=7701711") {
		t.Fatalf("exemption: %s", l)
	}
	if strings.Index(out, "id:7700714,") > strings.Index(out, "id:7700711,") {
		t.Fatal("exemption after the rule")
	}
	for _, h := range []string{"authorization", "x-api-key", "stripe-signature", "x-hub-signature-256", "x-shopify-hmac-sha256", "x-wc-webhook-signature"} {
		if !reAPIHeader.MatchString(h) {
			t.Errorf("%s not exempt", h)
		}
	}
	for _, h := range []string{"user-agent", "cookie", "content-type", "x-requested-with"} {
		if reAPIHeader.MatchString(h) {
			t.Errorf("%s exempt", h)
		}
	}
}

func TestCRSAllowsBeaconsAndCom(t *testing.T) {
	if !strings.Contains(AllowedContentTypes, "|text/plain|") || !strings.Contains(AllowedContentTypes, "|application/json|") {
		t.Fatal(AllowedContentTypes)
	}
	if strings.Contains(RestrictedExtensions, ".com/") || !strings.Contains(RestrictedExtensions, ".sql/") {
		t.Fatal(RestrictedExtensions)
	}
}

// A ctl action on the first rule of a chain runs as soon as that rule
// matches (every POST), not when the whole chain does: never render one.
func TestNoCtlOnChainStarters(t *testing.T) {
	c := settings.Defaults().WAF
	c.Enabled, c.IPDBPost = true, true
	out := Render(c, Options{Dir: "/r", Trusted: true})
	inChain := false
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "SecRule ") || strings.HasPrefix(l, "SecAction ") {
			if strings.Contains(l, ",chain\"") && strings.Contains(l, "ctl:") && !inChain {
				t.Errorf("ctl on a chain starter: %s", l)
			}
			inChain = strings.Contains(l, ",chain\"")
		} else if strings.HasPrefix(strings.TrimSpace(l), "SecRule ") {
			inChain = strings.Contains(l, ",chain\"")
		}
	}
	// WHMCS admin saves are relaxed by the threshold (whmcsSetup), never
	// let through whole: the cookie and headers are the client's.
	for _, id := range []int{IDWHMCSAdmin, IDWHMCSAdminFetch} {
		if i := strings.Index(out, fmt.Sprintf("id:%d,", id)); i < 0 || strings.Contains(out[i:i+900], ",allow") || strings.Contains(out[i:i+900], "ruleEngine=Off") {
			t.Errorf("WHMCS rule %d lets the request through whole", id)
		}
	}
}

func TestContentTypePolicy(t *testing.T) {
	re := regexp.MustCompile(contentTypeRx())
	for _, ok := range []string{"application/x-www-form-urlencoded; charset=UTF-8", "multipart/form-data; boundary=----WebKitFormBoundaryx", "application/json", "text/plain;charset=UTF-8", " application/csp-report", "application/x-www-form-urlencoded, application/x-www-form-urlencoded"} {
		if !re.MatchString(strings.ToLower(ok)) {
			t.Errorf("%q refused", ok)
		}
	}
	for _, bad := range []string{"text/html", "application/x-php", "application/jsonp", "multipart/form-dataX"} {
		if re.MatchString(bad) {
			t.Errorf("%q allowed", bad)
		}
	}
	if !policyOnly(Event{Detail: ScoredPrefix + "7700052 (Content-Type: text/html)"}) {
		t.Error("the content type policy alone must not ban")
	}
	e, _ := ParseLine(`[client 1.2.3.4:1] ModSecurity: Warning. [file "/x"] [id "7700052"] [msg "Request content type is not allowed by policy"] [data "text/html"] [uri "/"] [unique_id "U1"]`)
	if where(e) != "Content-Type: text/html" {
		t.Errorf("where = %q", where(e))
	}
}

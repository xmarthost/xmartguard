package waf

import (
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

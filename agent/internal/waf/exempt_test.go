package waf

import (
	"strings"
	"testing"

	"github.com/xmarthost/xmartguard/agent/internal/settings"
)

// The server's own addresses, its fleet and the firewall whitelist are
// never inspected by the WAF; proxy networks never are on that list.
func TestExemptAddresses(t *testing.T) {
	m := &Manager{RulesDir: t.TempDir(), ExemptIPs: func() []string {
		return []string{"37.120.176.23", "37.120.176.23", "127.0.0.1", "::1", "104.16.1.1", "162.158.0.0/16", "198.51.100.0/24", "2001:db8::5", "bogus", "0.0.0.0/0"}
	}}
	got := strings.Join(m.exemptList(), ",")
	if got != "198.51.100.0/24,2001:db8::5,37.120.176.23" {
		t.Fatalf("exempt list %s", got)
	}
	if !m.ExemptListChanged() {
		t.Fatal("new list not reported as changed")
	}
	d := Dynamic{ExemptFile: m.RulesDir + "/" + FileExemptIPs}
	rules := Render(settings.WAF{Enabled: true, WhitelistIPs: []string{"203.0.113.9"}}, Options{Dir: m.RulesDir, Dynamic: d})
	want := `SecRule REMOTE_ADDR "@ipMatchFromFile ` + d.ExemptFile + `" "id:7700006,phase:1,t:none,pass,nolog,ctl:ruleEngine=Off"`
	if !strings.Contains(rules, want) {
		t.Fatalf("exempt rule missing:\n%s", rules[:min(len(rules), 1500)])
	}
	if !strings.Contains(rules, `SecRule REMOTE_ADDR "@ipMatch 203.0.113.9" "id:7700001,phase:1,pass,nolog,ctl:ruleEngine=Off"`) {
		t.Fatal("WAF whitelist does not skip every rule")
	}
	if !strings.Contains(RenderLoginWatch(settings.WAF{Enabled: true}, "Malware.Expert", d), "id:7700006,") {
		t.Fatal("exempt rule missing where a vendor's rules are used")
	}
	if strings.Contains(Render(settings.WAF{Enabled: true}, Options{Dir: m.RulesDir}), "id:7700006,") {
		t.Fatal("exempt rule without a list")
	}
}

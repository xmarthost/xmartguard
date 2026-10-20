package waf

import (
	"fmt"
	"strings"
	"testing"

	"github.com/xmarthost/xmartguard/agent/internal/settings"
)

func ruleLine(out string, id int) string {
	for _, l := range strings.Split(out, "\n") {
		if (strings.HasPrefix(l, "SecRule ") || strings.HasPrefix(l, "SecAction ")) && strings.Contains(l, fmt.Sprintf("id:%d,", id)) {
			return l
		}
	}
	return ""
}

// New rules only log until the portal approves them; then they block.
func TestNewRulesWatchUntilApproved(t *testing.T) {
	c := settings.Defaults().WAF
	c.Enabled = true
	out := Render(c, Options{Dir: "/r"})
	for _, id := range []int{IDShopScrape, IDShopScrape + 1000, IDCartSpam, IDNoUAPost} {
		l := ruleLine(out, id)
		if l == "" {
			t.Fatalf("rule %d not rendered", id)
		}
		if strings.Contains(l, "deny") || strings.Contains(l, "status:") || !strings.Contains(l, ",pass,") || !strings.Contains(l, "[watch]") {
			t.Errorf("rule %d does not watch: %s", id, l)
		}
	}
	// Older rules block as before.
	if l := ruleLine(out, IDWebshell); !strings.Contains(l, "deny") {
		t.Errorf("old rule changed: %s", l)
	}
	// The Sec-Fetch exemption keeps working.
	if l := ruleLine(out, IDShopScrape+2000); !strings.Contains(l, "ctl:ruleRemoveById") {
		t.Errorf("exemption changed: %s", l)
	}
	out = Render(c, Options{Dir: "/r", Intel: (&Intel{Enforce: []int{IDShopScrape, 7700001}}).Clean()})
	if l := ruleLine(out, IDShopScrape+1000); !strings.Contains(l, "deny,status:403") {
		t.Errorf("approved rule does not block: %s", l)
	}
	if l := ruleLine(out, IDCartSpam); strings.Contains(l, "deny") {
		t.Errorf("unapproved rule blocks: %s", l)
	}
	if got := MonitoredIDs((&Intel{Enforce: []int{IDShopScrape, IDCartSpam, IDNoUAPost, IDCommentScript, IDCommentLinks, IDCommentManyLinks, IDEditorCap}}).Clean()); len(got) != 0 {
		t.Errorf("monitored %v", got)
	}
}

func TestMonitoredPortalPatch(t *testing.T) {
	in := &Intel{Patches: []PortalPatch{{ID: 7703010, Title: "Test plugin upload", Path: `/wp-content/plugins/x/up\.php$`, Monitor: true}}}
	c := settings.Defaults().WAF
	c.Enabled = true
	out := Render(c, Options{Dir: "/r", Intel: in.Clean()})
	if l := ruleLine(out, 7703010); l == "" || strings.Contains(l, "deny") {
		t.Errorf("watched patch: %q", l)
	}
}

package waf

import (
	"slices"
	"strings"
	"testing"

	"github.com/xmarthost/xmartguard/agent/internal/settings"
)

// Audit A3 F7: LiteSpeed ignores ctl:ruleRemoveById. Exclusions for every
// request are also config-time removals after the CRS, a switched-off
// upload scan is not rendered, and the theme colour stylesheet exception
// is a tx marker the two PHP rules test.
func TestExclusionsWithoutRuleRemovalAtRunTime(t *testing.T) {
	c := settings.Defaults().WAF
	c.RuleExclusions = []settings.RuleExclusion{{Rule: 942100}, {Rule: 941100, Domain: "shop.example.com"}, {Rule: 932100, Path: "/x/"}, {Rule: IDWPAdminExcl}}
	dyn := Dynamic{Auto: []settings.RuleExclusion{{Rule: 920420}}}
	ids := configRemovals(c, dyn)
	for _, want := range []int{941310, 920600, 942550, 942100, 920420, IDContentType} {
		if !slices.Contains(ids, want) {
			t.Errorf("%d not removed: %v", want, ids)
		}
	}
	for _, not := range []int{941100, 932100, IDWPAdminExcl} {
		if slices.Contains(ids, not) {
			t.Errorf("scoped or allow exclusion %d removed everywhere", not)
		}
	}
	c.DisabledRules = []int{IDHostingBase, IDAutoExcl}
	if ids := configRemovals(c, dyn); slices.Contains(ids, 941310) || slices.Contains(ids, 920420) {
		t.Errorf("switched-off defaults still removed: %v", ids)
	}
	if (&Manager{}).configRemovals() != nil {
		t.Error("removals without settings")
	}

	c = settings.Defaults().WAF
	c.Enabled, c.UploadScan, c.Generic, c.WordPress = true, true, true, true
	o := Options{Dir: "/r", UploadScan: true, InspectPath: "/r/inspect.sh"}
	if !strings.Contains(Render(c, o), "id:7700101,") {
		t.Fatal("upload scan not rendered")
	}
	c.DisabledRules = []int{IDUploadMalware}
	out := Render(c, o)
	if strings.Contains(out, "id:7700101,") || strings.Contains(out, "SecTmpSaveUploadedFiles") {
		t.Error("switched-off upload scan still rendered")
	}
	if !strings.Contains(strings.Join(chainOf(out, IDThemeColorCSS), "\n"), "setvar:tx.xg_color_css=1") {
		t.Error("colour stylesheet not marked")
	}
	for _, id := range []int{IDStaticPHP, IDPHPInAssets} {
		if ch := chainOf(out, id); len(ch) < 2 || ch[1] != `SecRule &TX:xg_color_css "@eq 0" "t:none,chain"` {
			t.Errorf("rule %d does not skip colour stylesheets: %q", id, ch)
		}
	}
}

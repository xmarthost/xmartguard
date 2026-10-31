package waf

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// TestFamilyRemoveSetupRealCRS: the removal rules name every rule of the
// families in the installed CRS release (read from its files, so a new
// release's ids come along), in ids 7700880-7700899.
func TestFamilyRemoveSetupRealCRS(t *testing.T) {
	src := os.Getenv("XG_CRS_DIR")
	if src == "" {
		t.Skip("set XG_CRS_DIR to an OWASP CRS 4 checkout")
	}
	s := familyRemoveSetup(src)
	for _, f := range crsFamilies {
		ids := crsFamilyIDs(src, f.file)
		if len(ids) < 10 {
			t.Fatalf("%s: only %d ids", f.file, len(ids))
		}
		for _, id := range ids {
			if !strings.Contains(s, "ctl:ruleRemoveById="+strconv.Itoa(id)+",") && !strings.Contains(s, "ctl:ruleRemoveById="+strconv.Itoa(id)+`"`) {
				t.Errorf("%s: %d not removed", f.file, id)
			}
		}
	}
	for _, m := range regexp.MustCompile(`id:(\d+),phase`).FindAllStringSubmatch(s, -1) {
		id, _ := strconv.Atoi(m[1])
		if id != IDFamilyStrict && (id < IDFamilyRemove || id >= IDFamilyRemove+len(crsFamilies)*5) {
			t.Errorf("id %d outside the range", id)
		}
	}
	// No other family's rules (SQL injection stays checked).
	if strings.Contains(s, "=942") || strings.Contains(s, "=949") {
		t.Fatal("removes SQL injection or the blocking evaluation")
	}
	if !strings.Contains(s, `SecRule &TX:xg_strict "@ge 1"`) {
		t.Fatal("no withdrawal for a bad reputation")
	}
}

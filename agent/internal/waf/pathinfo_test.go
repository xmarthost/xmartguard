package waf

import (
	"regexp"
	"strings"
	"testing"

	"github.com/xmarthost/xmartguard/agent/internal/settings"
)

// normalizePath is what ModSecurity's t:normalizePath does: empty and "."
// segments go, ".." takes the one before it out.
func normalizePath(p string) string {
	var out []string
	for i, seg := range strings.Split(p, "/") {
		switch {
		case i == 0:
			out = append(out, seg)
		case seg == "" || seg == ".":
		case seg == "..":
			if len(out) > 1 {
				out = out[:len(out)-1]
			}
		default:
			out = append(out, seg)
		}
	}
	n := strings.Join(out, "/")
	if strings.HasSuffix(p, "/") && !strings.HasSuffix(n, "/") {
		n += "/"
	}
	return n
}

var reFilenameLink = regexp.MustCompile(`SecRule REQUEST_FILENAME "(!?)@(rx|contains|streq) (.*?)" "([^"]*)"`)

// chainBlocks reports whether the REQUEST_FILENAME tests of a rendered
// chain all hold for path (the other links are taken as true).
func chainBlocks(t *testing.T, chain []string, path string) bool {
	t.Helper()
	for _, l := range chain {
		m := reFilenameLink.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		p := path
		if strings.Contains(m[4], "t:normalizePath") {
			p = normalizePath(p)
		}
		if strings.Contains(m[4], "t:lowercase") {
			p = strings.ToLower(p)
		}
		var hit bool
		switch m[2] {
		case "rx":
			hit = regexp.MustCompile(m[3]).MatchString(p)
		case "contains":
			hit = strings.Contains(p, m[3])
		case "streq":
			hit = p == m[3]
		}
		if hit == (m[1] == "!") {
			return false
		}
	}
	return true
}

// Audit A3 F2: PHP also runs /x.php for /x.php/anything (PATH_INFO), and
// "//" or "/./" in the path reach the same file. Every rule that blocks a
// PHP file blocks it in all these forms.
func TestPHPRulesPathInfo(t *testing.T) {
	c := settings.Defaults().WAF
	c.Enabled, c.SensitiveFiles, c.WordPress, c.Generic, c.Webshell, c.VirtualPatches, c.BadBots = true, true, true, true, true, true, true
	out := Render(c, Options{Dir: "/r", Intel: (&Intel{Names: []string{"xgtest2024.php"}}).Clean()})
	cases := []struct {
		id   int
		path string
	}{
		{IDSensitive, "/wp-config.php"},
		{IDUploadsPHP, "/wp-content/uploads/2024/x.php"},
		{IDPHPInAssets, "/wp-content/themes/t/images/x.php"},
		{IDHiddenPHP, "/blog/.x.php"},
		{IDEmptyUAWP, "/wp-content/plugins/p/x.php"},
		{IDWPCoreDirect, "/wp-admin/includes/x.php"},
		{IDWPAdminFake, "/wp-admin/network/x.php"},
		{IDWPLookalike, "/wp-l0gin.php"},
		{IDWPCachePHP, "/wp-content/cache/x.php"},
		{IDStaticPHP, "/assets/images/x.php"},
		{IDHiddenDirPHP, "/site/.tmb/x.php"},
		{IDVPFileManager, "/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php"},
		{IDWebshell, "/up/alfa.php"},
		{IDFleetNames, "/wp-content/xgtest2024.php"},
		{IDExploitProbe, "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"},
		{IDRootProbe, "/x.php"},
		{IDNoUAPost, "/old/includes/up.php"},
	}
	for _, tc := range cases {
		chain := chainOf(out, tc.id)
		if len(chain) == 0 {
			t.Errorf("rule %d not rendered", tc.id)
			continue
		}
		p := tc.path
		variants := []string{p, p + "/a", p + "/", strings.ReplaceAll(p, "/", "//"), strings.ReplaceAll(p, "/", "/./"), strings.Replace(p, "/", "/x/../", 1)}
		if tc.id == IDRootProbe {
			variants = variants[:5] // only the top folder
		}
		for _, v := range variants {
			if !chainBlocks(t, chain, v) {
				t.Errorf("rule %d does not block %s", tc.id, v)
			}
		}
		// Not a PHP file: a name that only starts like one.
		if chainBlocks(t, chain, p+"x") || chainBlocks(t, chain, strings.TrimSuffix(p, ".php")+".php.jpg") {
			t.Errorf("rule %d blocks a file that is not PHP (%sx)", tc.id, p)
		}
	}
	// IDRepeatDirPHP uses a back-reference (Go's regexp has none): its
	// pattern ends like the others.
	if l := ruleLine(out, IDRepeatDirPHP); !strings.Contains(l, `(?:/|$)" "id:`) || !strings.Contains(l, "t:urlDecodeUni,t:normalizePath,t:lowercase") {
		t.Errorf("repeated-folder rule: %s", l)
	}
	// What these rules let through still passes in every form.
	for _, tc := range []struct {
		id   int
		path string
	}{
		{IDRootProbe, "/index.php/route/x"},
		{IDNoUAPost, "/index.php/api/orders"},
		{IDNoUAPost, "/api/v1/orders.php/x"},
		{IDWPLookalike, "/wp-login.php/x"},
		{IDHiddenDirPHP, "/.well-known/x.php"},
		{IDStaticPHP, "/assets/templates/basic/css/color.php"},
		{IDWPCoreDirect, "/wp-includes/js/tinymce/wp-tinymce.php"},
	} {
		for _, v := range []string{tc.path, strings.ReplaceAll(tc.path, "/", "//")} {
			if chainBlocks(t, chainOf(out, tc.id), v) {
				t.Errorf("rule %d blocks %s", tc.id, v)
			}
		}
	}
	// No blocking rule ends a PHP name at "$" alone any more.
	reEnd := regexp.MustCompile(`^SecRule REQUEST_FILENAME "@rx ([^"]*)" "[^"]*deny`)
	for _, l := range strings.Split(out, "\n") {
		if m := reEnd.FindStringSubmatch(l); m != nil && strings.Contains(m[1], "ph") && strings.HasSuffix(m[1], "$") && !strings.HasSuffix(m[1], "(?:/|$)") {
			t.Errorf("blocking rule ends at the extension: %s", l)
		}
	}
}

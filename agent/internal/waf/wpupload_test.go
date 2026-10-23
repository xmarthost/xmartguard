package waf

import (
	"os"
	"strings"
	"testing"

	"github.com/xmarthost/xmartguard/agent/internal/settings"
)

// multipart builds a one-file upload body as WordPress's uploaders send it.
func multipart(field, name, content string) (ctype, body string) {
	const b = "----xpguardtestboundary"
	body = "--" + b + "\r\nContent-Disposition: form-data; name=\"_wpnonce\"\r\n\r\n0123456789\r\n" +
		"--" + b + "\r\nContent-Disposition: form-data; name=\"" + field + "\"; filename=\"" + name + "\"\r\nContent-Type: application/octet-stream\r\n\r\n" +
		content + "\r\n--" + b + "--\r\n"
	return "multipart/form-data; boundary=" + b, body
}

// The rule is rendered for the WordPress package and watches until it is
// approved, like every new rule.
func TestWPPackagePHPRule(t *testing.T) {
	c := settings.Defaults().WAF
	c.Enabled, c.WordPress = true, true
	out := Render(c, Options{Dir: "/r"})
	if l := ruleLine(out, IDWPPackagePHP); l == "" || strings.Contains(l, "deny") {
		t.Fatalf("not watched before approval: %q", l)
	}
	out = Render(c, Options{Dir: "/r", Intel: (&Intel{Enforce: []int{IDWPPackagePHP}}).Clean()})
	if l := ruleLine(out, IDWPPackagePHP); !strings.Contains(l, "deny,status:403") {
		t.Fatalf("approved rule does not block: %q", l)
	}
}

// A PHP file sent to the plugin uploader (update.php?action=upload-plugin)
// with a logged-in admin's cookie: CRS 933110 scored it 5 under the
// threshold of 10 and it passed on business200. The plugin, theme and media
// uploaders only take zip files and media, so the PHP file is refused,
// while a real plugin zip and a media image from the same admin pass.
func TestWPPackagePHPOnApache(t *testing.T) {
	src := os.Getenv("XG_CRS_DIR")
	if src == "" {
		t.Skip("set XG_CRS_DIR to an OWASP CRS 4 checkout")
	}
	m := crsManager(t, src, `{"waf":{"enabled":true,"level":"normal","wordpress":true,"generic":true}}`, "off", func(m *Manager) {
		m.Intel = func() *Intel { return &Intel{Enforce: []int{IDWPPackagePHP}} }
	})
	if st := m.Status(); st.Error != "" {
		t.Fatalf("WAF error: %s", st.Error)
	}
	admin := []string{"Cookie: wordpress_logged_in_0123456789abcdef0123456789abcdef=admin%7C1792583154%7Ctoken%7Chash",
		"Origin: https://shop.example.com", "Referer: https://shop.example.com/wp-admin/plugin-install.php?tab=upload", "Sec-Fetch-Site: same-origin",
		"User-Agent: " + browserUA}
	cases := []struct {
		name, uri, field, file, content string
		refused                         bool
	}{
		{"PHP file as a plugin", "/wp-admin/update.php?action=upload-plugin", "pluginzip", "cache-helper.php", "<?php echo 'inert fixture';", true},
		{"PHP file as a theme", "/wp-admin/update.php?action=upload-theme", "themezip", "style.phtml", "<?php echo 'inert fixture';", true},
		{"PHP file to the media library", "/wp-admin/async-upload.php", "async-upload", "image.PHP5", "<?php echo 'inert fixture';", true},
		{"plugin zip", "/wp-admin/update.php?action=upload-plugin", "pluginzip", "contact-form.zip", "PK\x03\x04 inert zip fixture", false},
		{"media image", "/wp-admin/async-upload.php", "async-upload", "logo.png", "\x89PNG inert image fixture", false},
	}
	for _, c := range cases {
		ctype, body := multipart(c.field, c.file, c.content)
		got := sendBody(t, "shop.example.com", "POST", c.uri, ctype, body, admin...)
		if (got == 403) != c.refused || got == 0 {
			t.Errorf("%s: got %d, want refused %v", c.name, got, c.refused)
		}
	}
}

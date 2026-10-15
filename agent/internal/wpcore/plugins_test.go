package wpcore

import "testing"

// Copies WordPress and UpdraftPlus keep of a plugin are verified like it.
func TestPluginOfCopies(t *testing.T) {
	cases := map[string][2]string{
		"/home/u/public_html/wp-content/plugins/wordfence/lib/wfUtils.php":                                     {"wordfence", "lib/wfUtils.php"},
		"/home/u/site/wp-content/upgrade-temp-backup/plugins/wp-fastest-cache/wpFastestCache.php":              {"wp-fastest-cache", "wpFastestCache.php"},
		"/home/u/public_html/wp-content/updraft/plugins-old/updraftplus/class-updraftplus.php":                 {"updraftplus", "class-updraftplus.php"},
		"/home/u/public_html/wp-content/upgrade-temp-backup/plugins/woocommerce-paypal-payments/modules/a.php": {"woocommerce-paypal-payments", "modules/a.php"},
	}
	for p, want := range cases {
		_, slug, rel := pluginOf(p)
		if slug != want[0] || rel != want[1] {
			t.Errorf("%s: got %q %q", p, slug, rel)
		}
	}
	if _, slug, _ := pluginOf("/home/u/public_html/wp-content/themes/x/functions.php"); slug != "" {
		t.Error("a theme file taken for a plugin")
	}
}

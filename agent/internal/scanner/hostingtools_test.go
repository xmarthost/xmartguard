package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sappSignon = `<?php
@unlink(__FILE__);
$pass = 'a7Gd92Kq0Lm3Zx81Pq0';
if(empty($_REQUEST['pass']) || $_REQUEST['pass'] != $pass){
	die('Unauthorized Access');
}
require('wp-blog-header.php');
require('wp-includes/pluggable.php');
$user_info = get_userdata(1);
wp_set_current_user($user_info->ID, $user_info->user_login);
wp_set_auth_cookie($user_info->ID);
do_action('wp_login', $user_info->user_login, $user_info);
wp_safe_redirect(admin_url());
exit;
`

// Softaculous's one-time login file and WP Toolkit's mu-plugin are left
// alone; the same names carrying a backdoor are not.
func TestHostingLoginHelpers(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "wp-config.php"), []byte("<?php define('WP_TOOLKIT_API_TOKEN','x');"), 0o644)
	sapp := filepath.Join(root, "sapp-wp-signon.php")
	mu := filepath.Join(root, "wp-content", "mu-plugins", "wp-toolkit.php")
	os.MkdirAll(filepath.Dir(mu), 0o755)
	cases := []struct {
		path, content string
		trusted       bool
	}{
		{sapp, sappSignon, true},
		{sapp, sappSignon + "\neval($_POST['x']);", false},
		{sapp, strings.Replace(sappSignon, "@unlink(__FILE__);", "", 1), false},
		{filepath.Join(root, "wp-content", "uploads", "sapp-wp-signon.php"), sappSignon, false},
		{mu, "<?php\n/* Plugin Name: WP Toolkit */\nif (defined('WP_TOOLKIT_API_TOKEN')) { add_action('init', 'wpt_init'); }", true},
		{mu, "<?php\n/* Plugin Name: WP Toolkit */\n@system($_GET['c']);", false},
	}
	for i, c := range cases {
		os.MkdirAll(filepath.Dir(c.path), 0o755)
		if got := trustedHostingTool(c.path, []byte(c.content)); got != c.trusted {
			t.Errorf("case %d (%s): trusted %v, want %v", i, c.path, got, c.trusted)
		}
	}
}

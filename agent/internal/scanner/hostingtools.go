package scanner

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Hosting panels log their users into WordPress with files that look like
// login backdoors to a scanner, because that is what they are for:
//
//   - Softaculous ("Login" next to an installation, and its WordPress
//     Manager) writes sapp-wp-signon.php into the site's root with a random
//     one-time password, opens it, and the file logs the user in as the
//     admin and deletes itself (unlink(__FILE__)).
//   - WP Toolkit (cPanel and Plesk) logs in through its must-use plugin
//     wp-content/mu-plugins/wp-toolkit.php, which checks the
//     WP_TOOLKIT_API_TOKEN that WP Toolkit put into wp-config.php.
//
// Quarantining them breaks those logins, so they are recognised by name,
// place and shape. Anything else in them (a command, eval, a decoder, a
// download, a file write) makes them ordinary files again, so a backdoor
// using the same name is still caught.

var (
	reSappName = regexp.MustCompile(`^sapp-[a-z0-9_]+-signon\.php$`)
	// Never part of these tools.
	reToolDanger = regexp.MustCompile(`(?i)\b(?:eval|assert|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|create_function|base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|hex2bin|convert_uudecode|move_uploaded_file|file_put_contents|fwrite|fputs|curl_exec|fsockopen|stream_socket_client|call_user_func(?:_array)?)\s*\(|\$_FILES|` + "`" + `|\binclude\s*\(?\s*\$_|\brequire(?:_once)?\s*\(?\s*\$_|preg_replace\s*\(\s*['"].*/[a-z]*e[a-z]*['"]`)
)

// trustedHostingTool reports a panel's own login file (see above).
func trustedHostingTool(path string, content []byte) bool {
	if len(content) > 64<<10 || reToolDanger.Match(content) {
		return false
	}
	name := filepath.Base(path)
	dir := filepath.Dir(path)
	switch {
	case reSappName.MatchString(name):
		// In the site's root, password-checked, self-deleting.
		return isWPRoot(dir) &&
			strings.Contains(string(content), "wp_set_auth_cookie") &&
			strings.Contains(string(content), "unlink") &&
			(strings.Contains(string(content), "$_REQUEST") || strings.Contains(string(content), "$_GET") || strings.Contains(string(content), "$_POST"))
	case name == "wp-toolkit.php" && filepath.Base(dir) == "mu-plugins" && filepath.Base(filepath.Dir(dir)) == "wp-content":
		return strings.Contains(string(content), "WP_TOOLKIT_API_TOKEN") || strings.Contains(strings.ToLower(string(content)), "wp toolkit")
	}
	return false
}

func isWPRoot(dir string) bool {
	for _, f := range []string{"wp-config.php", "wp-blog-header.php", "wp-load.php"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err == nil {
			return true
		}
	}
	// wp-config.php may sit one folder up.
	_, err := os.Stat(filepath.Join(filepath.Dir(dir), "wp-config.php"))
	return err == nil && func() bool { _, e := os.Stat(filepath.Join(dir, "wp-includes")); return e == nil }()
}

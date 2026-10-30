package scanner

import (
	"bytes"
	"regexp"
)

// The plugin upload campaign of 2026-10-28 (server1: logins with known
// passwords, then wp-admin's own plugin uploader; none of its files had a
// finding). xPGuard's own rules, built from how each works:
//
//   - "wp-warden" (system-defence.php): removes itself from the plugin list
//     and prints a 193 KB base64 script, its <script> tag cut in two, on
//     every page for visitors who are not administrators;
//   - "WP-CORE" (core-wp.zip/wp-core.php): a fake core plugin loading a
//     script whose URL is kept as XOR-ed byte arrays;
//   - a one-page uploader saving any file under the name it was sent with;
//   - a file manager for anyone (no login), switching off open_basedir;
//   - a goto-obfuscated file manager and admin creator reading the request
//     through escaped names ($_GET["\x76\151..."]).

var (
	// The plugin removes its own entry from the list, whatever the settings.
	reSelfHide = regexp.MustCompile(`add_filter\s*\(\s*['"]all_plugins['"]\s*,\s*function\s*\(\s*\$(\w+)\s*\)\s*\{\s*unset\s*\(\s*\$\w+\s*\[\s*plugin_basename\s*\(\s*__FILE__\s*\)\s*\]\s*\)\s*;\s*return\s+\$\w+\s*;\s*\}`)
	// A script tag cut in two in PHP output.
	reSplitScript = regexp.MustCompile(`(?i)['"]<scr['"]\s*\.\s*['"]ipt`)
	reFrontPrint  = regexp.MustCompile(`add_action\s*\(\s*['"](?:wp_head|wp_footer|wp_body_open|login_head|login_footer|wp_print_footer_scripts)['"]`)

	// Byte arrays turned into text by XOR with a key, and a script loaded
	// from a URL the file does not write out.
	reXorKey      = regexp.MustCompile(`(?i)chr\s*\(\s*\$\w+(?:\[[^\]]+\])?\s*\^\s*ord\s*\(|chr\s*\(\s*ord\s*\([^)]*\)\s*\^`)
	reByteArray   = regexp.MustCompile(`\[\s*(?:\d{1,3}\s*,\s*){24,}\d{1,3}\s*\]|array_map\s*\(\s*['"]chr['"]`)
	reScriptByVar = regexp.MustCompile(`wp_(?:enqueue|register)_script\s*\(\s*[^,]+,\s*\$\w+`)

	// The uploader: its own form, the file kept under the name it came
	// with, nothing checked.
	reUploadForm   = regexp.MustCompile(`(?i)enctype\s*=\s*\\?["']?multipart/form-data`)
	reOrigName     = regexp.MustCompile(`\$_FILES\s*\[[^\]]+\]\s*\[\s*['"]name['"]\s*\]`)
	reUploadChecks = regexp.MustCompile(`(?i)\b(?:pathinfo|wp_check_filetype\w*|wp_handle_upload|in_array|preg_match|getimagesize|finfo_\w+|mime_content_type|strrchr|sanitize_file_name)\s*\(|PATHINFO_EXTENSION`)
	reAuth         = regexp.MustCompile(`(?i)\b(?:session_start|password_verify|current_user_can|wp_verify_nonce|check_admin_referer|is_user_logged_in)\s*\(|\$_SESSION\b|PHP_AUTH_USER|\bABSPATH\b|['"](?:pass|password|pwd|passwd|auth|token)['"]`)

	// open_basedir (or disable_functions) switched off from the script.
	reBasedirOff = regexp.MustCompile(`(?i)ini_set\s*\(\s*['"](?:open_basedir|disable_functions)['"]\s*,\s*(?:null|''|""|false|0)\s*\)`)
	reFileOps    = []*regexp.Regexp{
		regexp.MustCompile(`\b(?:scandir|opendir|glob)\s*\(`),
		regexp.MustCompile(`\bfile_put_contents\s*\(`),
		regexp.MustCompile(`\bmove_uploaded_file\s*\(`),
		regexp.MustCompile(`\bunlink\s*\(`),
		regexp.MustCompile(`\brename\s*\(`),
		regexp.MustCompile(`\bchmod\s*\(`),
	}

	// A request variable whose name is written as escapes.
	reEscapedInput = regexp.MustCompile(`\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\s*\[\s*["'](?:\\x[0-9a-fA-F]{2}|\\[0-7]{1,3}){2,}["']\s*\]`)
)

// pluginInjectors judges PHP content alone (kitFamilies).
func pluginInjectors(content []byte, has func(string) bool) *Detection {
	if has("all_plugins") && reSelfHide.Match(content) && reFrontPrint.Match(content) &&
		(reSplitScript.Match(content) || bigBase64(content)) {
		return &Detection{CatVirus, "PHP.Backdoor.SelfHidingInjector"}
	}
	if has("chr") && has("_script") && reXorKey.Match(content) && reByteArray.Match(content) && reScriptByVar.Match(content) {
		return &Detection{CatVirus, "PHP.Injector.HiddenScriptURL"}
	}
	if has("_FILES") {
		if len(reEscapedInput.FindAllIndex(content, 3)) >= 2 {
			return &Detection{CatVirus, "PHP.Obfuscated.EscapedInput"}
		}
		if len(content) < 8<<10 && has("move_uploaded_file") && reUploadForm.Match(content) && reOrigName.Match(content) &&
			!reUploadChecks.Match(content) && !reAuth.Match(content) {
			return &Detection{CatVirus, "PHP.Webshell.Uploader"}
		}
	} else if bytes.Contains(content, []byte(`$_GET["\`)) || bytes.Contains(content, []byte(`$_POST["\`)) {
		if len(reEscapedInput.FindAllIndex(content, 3)) >= 2 {
			return &Detection{CatVirus, "PHP.Obfuscated.EscapedInput"}
		}
	}
	if has("ini_set") && reBasedirOff.Match(content) && has("$_") {
		ops := 0
		for _, r := range reFileOps {
			if r.Match(content) {
				ops++
			}
		}
		if ops >= 4 {
			return &Detection{CatVirus, "PHP.Webshell.FileManager"}
		}
	}
	return nil
}

// bigBase64: a base64 block of 20 KB or more (a heredoc in lines, or one
// string).
func bigBase64(content []byte) bool {
	run := 0
	for _, c := range content {
		switch {
		case 'A' <= c && c <= 'Z', 'a' <= c && c <= 'z', '0' <= c && c <= '9', c == '+', c == '/':
			run++
			if run >= 20000 {
				return true
			}
		case c == '\n', c == '\r':
		default:
			run = 0
		}
	}
	return false
}

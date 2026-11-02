package scanner

import (
	"bytes"
	"errors"
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
	reUploadForm = regexp.MustCompile(`(?i)enctype\s*=\s*\\?["']?multipart/form-data`)
	reOrigName   = regexp.MustCompile(`\$_FILES\s*\[[^\]]+\]\s*\[\s*['"]name['"]\s*\]`)
	// (A comparison of the extension with fixed names is a check too:
	// $ext == "jpg" || $ext == "png", the image pages of a site's own admin.)
	reUploadChecks = regexp.MustCompile(`(?i)\b(?:pathinfo|wp_check_filetype\w*|wp_handle_upload|in_array|preg_match|getimagesize|finfo_\w+|mime_content_type|strrchr|sanitize_file_name)\s*\(|PATHINFO_EXTENSION|\$\w+\s*[!=]==?\s*["']\.?(?:jpe?g|png|gif|webp|bmp|pdf|docx?|xlsx?|csv|txt|mp[34]|svg|zip)["']`)
	// (A page of a site's own admin often checks the login in a file it
	// includes: include_once("chksession.php").)
	reAuth = regexp.MustCompile(`(?i)\b(?:session_start|password_verify|current_user_can|wp_verify_nonce|check_admin_referer|is_user_logged_in)\s*\(|\$_SESSION\b|PHP_AUTH_USER|\bABSPATH\b|['"](?:pass|password|pwd|passwd|auth|token)['"]|\b(?:include|require)(?:_once)?\s*\(?\s*['"][^'"]*(?:session|auth|login|logged)[^'"]*\.php['"]`)
	// A page of a site's own application: it writes a record about the
	// upload to its database. The one-page uploaders dropped by attackers
	// keep no records.
	reDBWrite = regexp.MustCompile(`(?i)\b(?:INSERT\s+INTO|UPDATE\s+` + "`?" + `\w+` + "`?" + `\s+SET|REPLACE\s+INTO)\b`)
	reDBCall  = regexp.MustCompile(`(?i)\bmysqli?_query\s*\(|->\s*(?:query|prepare|exec|execute)\s*\(|\bpg_query\s*\(`)

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

// The fake Cloudflare check of October 2026 (server1.superfast, 2026-11-02:
// expresswrap.ae and five other sites, three waves from 2026-10-09): one
// line appended to the active theme's functions.php, a wp_footer hook that
// prints only a script loading another script, named by a few random
// mixed-case letters, from the attacker's domain (karmazarbaza.com,
// franfrbar.com, frclau.com: kbS0.js, cA.js). The page it shows is built
// in the visitor's browser, so no text of it is ever on the server.
// A site's own chat or analytics snippet sets its options first
// (window.$crisp, dataLayer) or names its script (l.js, gtm.js, widget.js).
var reFooterLoader = regexp.MustCompile(`add_action\s*\(\s*['"](?:wp_footer|wp_head|wp_body_open|login_footer|login_head|admin_footer)['"]\s*,\s*function\s*\([^)]*\)\s*\{\s*echo\s*['"]\s*<script[^>]*>\s*(?:var|let|const)\s+\w+\s*=\s*document\.createElement\s*\(\s*\\?["']script\\?["']\s*\)\s*;\s*\w+\.src\s*=\s*\\?["']https?://[A-Za-z0-9.-]+\.[A-Za-z]{2,}/([A-Za-z0-9]{1,10})\.js\\?["']`)

// footerLoader: a hook printing only a loader for a randomly named script
// at the root of another domain (both cases in its name: kbS0, cA).
func footerLoader(content []byte) bool {
	for _, m := range reFooterLoader.FindAllSubmatch(content, 20) {
		name := m[1]
		if bytes.ContainsAny(name, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") && bytes.ContainsAny(name, "abcdefghijklmnopqrstuvwxyz") {
			return true
		}
	}
	return false
}

// footerLoaderCuts: the lines that hold only a loader hook (the campaign
// appends each as one line of its own).
func footerLoaderCuts(content []byte) []Cut {
	var cuts []Cut
	for i, line := range bytes.Split(content, []byte("\n")) {
		l := bytes.TrimSpace(line)
		if bytes.HasPrefix(l, []byte("add_action")) && bytes.HasSuffix(l, []byte(";")) && bytes.Count(l, []byte("add_action")) == 1 && footerLoader(l) {
			cuts = append(cuts, Cut{From: i + 1, To: i + 1})
		}
	}
	return cuts
}

// trimFooterLoader puts a quarantined file back without its loader lines.
func (s *Scanner) trimFooterLoader(id int64, maxPercent int) error {
	r, err := s.load(id)
	if err != nil {
		return err
	}
	content, err := readFinding(r.qpath)
	if err != nil {
		return err
	}
	cuts := footerLoaderCuts(content)
	if len(cuts) == 0 {
		return errors.New("the loader is not on lines of its own")
	}
	return s.Trim(id, cuts, maxPercent)
}

// pluginInjectors judges PHP content alone (kitFamilies).
func pluginInjectors(content []byte, has func(string) bool) *Detection {
	if has("createElement") && footerLoader(content) {
		return &Detection{CatVirus, "PHP.Injector.FooterScriptLoader"}
	}
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
			!reUploadChecks.Match(content) && !reAuth.Match(content) && !(reDBWrite.Match(content) && reDBCall.Match(content)) &&
			savesUnderSentName(content) {
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

var (
	reTempName   = regexp.MustCompile(`(?i)^\s*tempnam\s*\(\s*sys_get_temp_dir\s*\(\s*\)`)
	reMoveUpload = regexp.MustCompile(`\bmove_uploaded_file\s*\(([^;]{0,300})`)
	reAssignVar  = regexp.MustCompile(`\$(\w+)\s*=\s*([^;]{0,300});`)
)

// savesUnderSentName: a move_uploaded_file() call (not a function of a
// longer name: Chamilo's move_uploaded_file_collection_into_directory)
// whose destination is built from the name the file was sent with,
// directly or through variables.
func savesUnderSentName(content []byte) bool {
	tainted := map[string]bool{}
	assigns := reAssignVar.FindAllSubmatch(content, 400)
	for round := 0; round < 3; round++ {
		for _, a := range assigns {
			rhs := a[2]
			// A random name in the system's temporary folder, made from the
			// sent name only as a seed (PHPMailer's examples:
			// tempnam(sys_get_temp_dir(), sha1($_FILES['userfile']['name']))).
			if reTempName.Match(rhs) {
				continue
			}
			hit := reOrigName.Match(rhs)
			for v := range tainted {
				if hit {
					break
				}
				hit = regexp.MustCompile(`\$` + regexp.QuoteMeta(v) + `\b`).Match(rhs)
			}
			if hit {
				tainted[string(a[1])] = true
			}
		}
	}
	for _, m := range reMoveUpload.FindAllSubmatch(content, 20) {
		args := m[1]
		i := bytes.IndexByte(args, ',')
		if i < 0 {
			continue
		}
		dest := args[i+1:]
		if reOrigName.Match(dest) {
			return true
		}
		for v := range tainted {
			if regexp.MustCompile(`\$` + regexp.QuoteMeta(v) + `\b`).Match(dest) {
				return true
			}
		}
	}
	return false
}

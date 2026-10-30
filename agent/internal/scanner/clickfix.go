package scanner

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"io"
	"path/filepath"
	"regexp"
)

// The ClickFix campaign of October 2026 (server1 and server100, 2026-10-30:
// 365 fake plugin folders, 1,986 files, one finding). xPGuard's own rules,
// built from how the kit works:
//
//   - a fake "verify you are human" page (a Cloudflare look-alike) that puts
//     a command on the visitor's clipboard and tells them to open Windows'
//     Run box or PowerShell and paste it (Ctrl+V) - the visitor runs the
//     malware themselves. As a plugin's .html/.php, a must-use plugin or a
//     plugin's script;
//   - the plugin serving it writes Cloudflare's own clearance cookie
//     (cf_clearance) so the page shows once; only Cloudflare's edge sets it;
//   - a plugin answering visitors with a TXT record of the attacker's domain
//     (the command to paste, changed without touching the server);
//   - a must-use plugin keeping a hidden administrator: it creates the user,
//     resets its password to a hash written in the file, and hides it from
//     the user list and counts;
//   - a must-use plugin locking the owner out: every login, password reset
//     and REST login refused;
//   - an .htaccess sending the whole site to the fake page;
//   - a hidden file holding only base64 of compressed PHP (eval'd by a
//     loader), and doorway loaders asking a remote host what to show bots.

var (
	// What a page copies to the clipboard with.
	reClipWrite = regexp.MustCompile(`clipboard\.writetext\s*\(|clipboarddata\.setdata\s*\(|execcommand\s*\(\s*\\?['"]copy\\?['"]`)
	// The steps (tags removed): paste, and the window it is pasted into.
	rePasteStep = regexp.MustCompile(`\b(?:ctrl|cmd|command)\s*\+\s*v\b|⌘\s*\+?\s*v\b`)
	reRunStep   = regexp.MustCompile(`windows\s*(?:key|logo|button|\+)|\bwin\s*\+\s*[rx]\b|⊞|\bpowershell\b|run dialog|\bterminal\b`)
	// The lure: a human check (never a step of a real CAPTCHA).
	reHumanLure = regexp.MustCompile(`not a (?:ro)?bot|(?:verify|prove|confirm) (?:that )?you(?: are|'re| re) (?:a )?human|(?:you are|you're|i am|i'm) (?:a )?human|human (?:verification|check)|verification (?:id|code|steps)|are you a (?:ro)?bot|ray id`)
	reTag       = regexp.MustCompile(`<[^<>]{0,400}>`)
	reSpaces    = regexp.MustCompile(`\s+`)

	// Only Cloudflare's edge sets this cookie.
	reCFClearance = regexp.MustCompile(`document\.cookie\s*=\s*['"` + "`" + `]cf_clearance=|\bsetcookie\s*\(\s*['"]cf_clearance['"]`)

	// A TXT record of a fixed domain sent to anyone who asks.
	reTXTFixed = regexp.MustCompile(`\bdns_get_record\s*\(\s*['"][A-Za-z0-9.-]+\.[A-Za-z]{2,}['"]\s*,\s*DNS_TXT\b`)
	reTXTOut   = regexp.MustCompile(`\[\s*['"]txt['"]\s*\]`)
	reNoPriv   = regexp.MustCompile(`['"]wp_ajax_nopriv_`)

	// A user made or its password written straight into the users table.
	reUsersWrite = regexp.MustCompile(`\$wpdb->(?:update|query)\s*\(\s*\$wpdb->users\b[^;]{0,200}user_pass|\bwp_set_password\s*\(\s*['"]`)
	// Hidden from the user list, its counts or the REST users list.
	reHidesUser = regexp.MustCompile(`['"](?:pre_user_query|pre_get_users|pre_count_users|views_users|users_list_table_query_args|rest_user_query)['"]`)
	// A WordPress password hash written in the file, or a password given.
	rePassHash  = regexp.MustCompile(`['"]\$(?:wp\$)?2y\$\d\d\$[./A-Za-z0-9]{53}['"]|['"]\$P\$[./A-Za-z0-9]{31}['"]`)
	rePassGiven = regexp.MustCompile(`['"]user_pass['"]\s*=>\s*['"][^'"]{6,}['"]`)

	// The lockout: every login, reset and REST login refused. A login
	// policy (a setting, an address) never refuses every REST request: the
	// owner's editor would stop working.
	reAuthFilter  = regexp.MustCompile(`add_filter\s*\(\s*['"]authenticate['"]`)
	reNoReset     = regexp.MustCompile(`add_filter\s*\(\s*['"]allow_password_reset['"]\s*,\s*['"]__return_false['"]`)
	reRESTRefused = regexp.MustCompile(`add_filter\s*\(\s*['"]rest_authentication_errors['"]\s*,\s*function\s*\([^)]*\)\s*\{\s*return\s+new\s+WP_Error\b`)

	// A doorway's request to its host: the visitor's address and whether it
	// is a search engine bot, in one URL.
	reDoorwayURI = regexp.MustCompile(`['"]&?uri=['"]\s*\.\s*\$`)
	reDoorwayBot = regexp.MustCompile(`\.\s*\w*bot\w*\s*\(\s*\)\s*\.\s*['"]&`)
	reDoorwayArg = regexp.MustCompile(`['"]&(?:lang|http|zz)=['"]`)

	reBase64Only = regexp.MustCompile(`^[A-Za-z0-9+/]{256,}={0,2}$`)
	rePHPInside  = regexp.MustCompile(`\beval\s*\(|\bbase64_decode\s*\(|<\?php|\bgzinflate\s*\(|\bassert\s*\(`)
)

// clickFix: a human check telling the visitor to paste what it put on the
// clipboard into the Run box or PowerShell (low is the lowercased content).
// A page showing how to run a command (a support article with a copy
// button) asks no one to prove they are human; a real CAPTCHA asks no one
// to paste anything.
func clickFix(low []byte) bool {
	if !bytes.Contains(low, []byte("ctrl")) && !bytes.Contains(low, []byte("cmd")) && !bytes.Contains(low, []byte("⌘")) {
		return false
	}
	if !bytes.Contains(low, []byte("writetext")) && !bytes.Contains(low, []byte("setdata")) && !bytes.Contains(low, []byte("execcommand")) {
		return false
	}
	if !reClipWrite.Match(low) {
		return false
	}
	// Steps are written with tags (<b>Ctrl</b> + <b>V</b>) and escaped
	// quotes inside script strings.
	text := reTag.ReplaceAll(low, []byte(" "))
	text = bytes.ReplaceAll(text, []byte(`\'`), []byte("'"))
	text = reSpaces.ReplaceAll(text, []byte(" "))
	return rePasteStep.Match(text) && reRunStep.Match(text) && reHumanLure.Match(text)
}

// ClickFixPage reports a stored page or block that is the fake human check
// (the DB scan: posts, options and widgets hold the kit's page too).
func ClickFixPage(v []byte) bool { return clickFix(lowerASCII(v)) }

// clickFixKit judges content alone (kitFamilies).
func clickFixKit(ext string, content, low []byte, has func(string) bool) *Detection {
	switch ext {
	case ".php", ".html", ".htm", ".js", ".phtml", "":
	default:
		return nil
	}
	if len(content) > 2<<20 {
		return nil
	}
	if clickFix(low) {
		return &Detection{CatVirus, "Phishing.ClickFix.FakeVerification"}
	}
	if has("cf_clearance") && reCFClearance.Match(content) {
		return &Detection{CatVirus, "Phishing.ClickFix.FakeClearance"}
	}
	if !has("<?") {
		return nil
	}
	if has("DNS_TXT") && has("wp_ajax_nopriv_") && reTXTFixed.Match(content) && reTXTOut.Match(content) && reNoPriv.Match(content) {
		return &Detection{CatVirus, "PHP.Backdoor.DNSTXTDeadDrop"}
	}
	if (has("user_pass") || has("wp_set_password")) && reHidesUser.Match(content) && reAdminRole.Match(content) &&
		(reUsersWrite.Match(content) || reAddUser.Match(content) && rePassGiven.Match(content)) &&
		(rePassHash.Match(content) || rePassGiven.Match(content) || bytes.Contains(content, []byte("wp_set_password("))) {
		return &Detection{CatVirus, "PHP.Backdoor.HiddenAdmin"}
	}
	if len(content) < 8<<10 && has("allow_password_reset") && reAuthFilter.Match(content) && reNoReset.Match(content) &&
		reRESTRefused.Match(content) {
		return &Detection{CatVirus, "PHP.Backdoor.LoginLockdown"}
	}
	if len(content) < 64<<10 && has("uri=") && reDoorwayURI.Match(content) && reDoorwayBot.Match(content) && reDoorwayArg.Match(content) {
		return &Detection{CatVirus, "PHP.SEOSpam.RemoteDoorway"}
	}
	return nil
}

// hiddenPayload: a hidden file of nothing but base64 of deflated PHP (a
// loader reads, inflates and evals it).
func hiddenPayload(path string, content []byte) bool {
	base := filepath.Base(path)
	if len(base) < 2 || base[0] != '.' || len(content) > 4<<20 {
		return false
	}
	s := bytes.TrimSpace(content)
	if !reBase64Only.Match(s) {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(string(s))
	if err != nil {
		return false
	}
	out, err := io.ReadAll(io.LimitReader(flate.NewReader(bytes.NewReader(raw)), 8<<20))
	if err != nil || len(out) == 0 {
		return false
	}
	return rePHPInside.Match(out)
}

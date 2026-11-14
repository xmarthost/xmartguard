package scanner

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Shapes of the second wave on superfast (2026-11-13/14: legalcokemdma.com,
// 26 accounts, incident-wave2 report). Each rule names a behaviour, not a
// file name, so a renamed copy is caught too.

var (
	// A stream wrapper registered by the file itself, then a file "included"
	// from that scheme: the payload never touches the disk.
	reWrapperRegister = regexp.MustCompile(`(?i)\bstream_wrapper_register\s*\(`)
	reIncludeScheme   = regexp.MustCompile(`(?i)\b(?:include|require)(?:_once)?\b\s*\(?\s*(?:[\w:$>-]+\s*\.\s*['"]://|['"][a-z][a-z0-9]{0,24}://)`)
	// Decoders, also spelled as base64 strings ('Z3pkZWNvZGU=' is gzdecode).
	reStreamDecoder = regexp.MustCompile(`(?i)\b(?:base64_decode|gzinflate|gzdecode|gzuncompress|str_rot13|openssl_decrypt|hex2bin)\s*\(|['"]Z3pk|['"]YmFzZTY0`)
)

// decodedStreamInclude: a payload decoded in memory and run through a
// stream wrapper of the file's own (dildarte: "WP Security Guard" and
// "WP Snapshot Store" fake plugins, 123 copies, 72-74 KB, no request data:
// they read their payload from their own blob or the network).
func decodedStreamInclude(s []byte) bool {
	return reWrapperRegister.Match(s) && reIncludeScheme.Match(s) && reStreamDecoder.Match(s)
}

var reIdent = regexp.MustCompile(`\b[A-Za-z_][A-Za-z0-9_]{3,}\b`)

// mixedCaseNames are PHP functions and keywords; PHP does not mind their
// case, people and tools write them in lower case (or Title/UPPER).
var mixedCaseNames = map[string]bool{
	"include": true, "require": true, "return": true, "extract": true, "fopen": true, "fwrite": true, "fclose": true,
	"eval": true, "assert": true, "base64_decode": true, "gzinflate": true, "gzuncompress": true, "unlink": true, "glob": true,
	"array_map": true, "file_put_contents": true, "file_get_contents": true, "tempnam": true, "sys_get_temp_dir": true,
	"function": true, "hex2bin": true, "pack": true, "str_rot13": true, "strrev": true, "create_function": true, "system": true,
	"exec": true, "passthru": true, "shell_exec": true, "popen": true, "proc_open": true, "chmod": true, "touch": true,
}

// mixedCaseCalls counts PHP names written in mixed case with at least two
// case changes inside them (fOpEn, iNcLuDe, eXtRaCt: trionmar's .tmb shell).
func mixedCaseCalls(s []byte) int {
	seen := map[string]bool{}
	for _, m := range reIdent.FindAll(s, 4000) {
		w := string(m)
		lw := strings.ToLower(w)
		if !mixedCaseNames[lw] || seen[lw] || w == lw || w == strings.ToUpper(w) {
			continue
		}
		changes := 0
		for i := 1; i < len(w); i++ {
			a, b := w[i-1], w[i]
			if isLetter(a) && isLetter(b) && isUpper(a) != isUpper(b) {
				changes++
			}
		}
		if changes >= 3 {
			seen[lw] = true
		}
	}
	return len(seen)
}

func isLetter(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }
func isUpper(c byte) bool  { return c >= 'A' && c <= 'Z' }

var (
	reEndlessLoop = regexp.MustCompile(`(?i)\bwhile\s*\(\s*(?:true|1)\s*\)|\bfor\s*\(\s*;\s*;\s*\)`)
	reLockMode    = regexp.MustCompile(`(?i)\bchmod\s*\([^;]{1,200},\s*0?[45][45][45]\s*\)`)
	reBackdate    = regexp.MustCompile(`(?i)\btouch\s*\([^;]{1,200}(?:strtotime\s*\(\s*['"]-|\btime\s*\(\s*\)\s*-|\bfilemtime\s*\()`)
	reRewrite     = regexp.MustCompile(`(?i)\bfile_put_contents\s*\(`)
)

// fileGuardLoop: a script that never ends and keeps writing files back,
// read-only and dated in the past (fillvent's l.php restoring its index.php
// and .htaccess every second against any cleanup; dildarte's files locked
// to 555).
func fileGuardLoop(s []byte) bool {
	return reEndlessLoop.Match(s) && reRewrite.Match(s) && reLockMode.Match(s) && reBackdate.Match(s)
}

// placeRules judge a file by where it is (wave 2): core files replaced,
// static gambling pages put inside a WordPress site, and .htaccess files
// that serve such pages.
func placeRules(path, ext string, content []byte) *Detection {
	base := filepath.Base(path)
	dir := filepath.Dir(path)
	switch {
	case base == ".htaccess":
		if isWPRoot(dir) && staticDoorwayHtaccess(content) {
			return &Detection{CatVirus, "Htaccess.Hacked.StaticDoorway"}
		}
	case base == "wp-load.php" || base == "wp-blog-header.php" || base == "wp-settings.php":
		// WordPress's own bootstrap replaced by a page (abmover1: wp-load.php
		// a 75-byte meta refresh to tinyurl.com, every page redirected).
		if wpCoreDir(dir) && !rePhpOpen.Match(content) && len(bytes.TrimSpace(content)) > 0 {
			return &Detection{CatVirus, "WP.Core.BootstrapReplaced"}
		}
	case base == "index.php" && wpCoreDir(dir):
		// The site's front controller replaced by a page (pushopper.com: a
		// 1.8 MB slot page, wp-blog-header.php no longer loaded).
		if !bytes.Contains(content, []byte("wp-blog-header.php")) && (gamblingHead(content) || reMetaRefresh.Match(content) || reJSRedirect.Match(content)) {
			return &Detection{CatVirus, "WP.Core.IndexReplaced"}
		}
	}
	if (base == "index.html" || base == "index.htm" || base == "index.php") && gamblingHead(content) && insideWPSite(dir) {
		// A gambling page in a folder named like one of the site's pages, so
		// the web server serves it instead of WordPress (AGUSTOTO, SEMUTWIN:
		// 323 pages on 24 accounts, legalcok's /product-category/mdma/).
		return &Detection{CatVirus, "HTML.SEOSpam.StaticDoorway"}
	}
	return nil
}

var (
	reMetaRefresh = regexp.MustCompile(`(?i)<meta[^>]{0,80}http-equiv\s*=\s*["']?refresh["']?[^>]{0,120}url\s*=\s*['"]?https?://`)
	reJSRedirect  = regexp.MustCompile(`(?i)\b(?:window\.|document\.)?location(?:\.href)?\s*(?:=|\.replace\s*\(|\.assign\s*\()\s*['"]https?://`)
	// RewriteRule ^(.+\.html)/+$ $1: a flat .html file served for a
	// permalink-like address.
	reStaticHTMLRule = regexp.MustCompile(`(?im)^\s*RewriteRule\s+\S*\\\.html\S*\s+\$1\b`)
)

// staticDoorwayHtaccess: a WordPress root's .htaccess serving flat .html
// files for page addresses with WordPress's own rule gone (the
// "LP-JOOMLA-STATIC" block of 12 accounts): the static pages win.
func staticDoorwayHtaccess(content []byte) bool {
	return reStaticHTMLRule.Match(content) && !reWPRewrite.Match(content)
}

// wpCoreDir: a WordPress install's own folder (its wp-includes beside it).
func wpCoreDir(dir string) bool {
	st, err := os.Stat(filepath.Join(dir, "wp-includes"))
	return err == nil && st.IsDir()
}

// insideWPSite: a folder below a WordPress install's root, not one of
// WordPress's own folders (caches and exports live under wp-content).
func insideWPSite(dir string) bool {
	d := dir
	for i := 0; i < 8; i++ {
		switch filepath.Base(d) {
		case "wp-content", "wp-admin", "wp-includes":
			return false
		}
		parent := filepath.Dir(d)
		if parent == d {
			return false
		}
		if wpCoreDir(parent) {
			return true
		}
		d = parent
	}
	return false
}

var (
	reUnicodeIdent = regexp.MustCompile(`(?:\$|\bfunction\s+|\bgoto\s+)[\p{L}_][\p{L}\p{N}_]*`)
)

// unicodeGoto: goto-flattened code whose variables, functions and labels
// are named in another script (fillvent's index.php: Japanese and Korean
// names, a phishing redirector). Plugins are written with ASCII names.
func unicodeGoto(s []byte) bool {
	if len(reGoto.FindAllIndex(s, 4)) < 3 {
		return false
	}
	n := 0
	for _, m := range reUnicodeIdent.FindAll(s, 2000) {
		for _, c := range m {
			if c >= 0x80 {
				n++
				break
			}
		}
		if n >= 8 {
			return true
		}
	}
	return false
}

var (
	reShowTables   = regexp.MustCompile(`(?i)\bSHOW\s+TABLES\b`)
	reSelectAll    = regexp.MustCompile(`(?i)SELECT\s+\*\s+FROM\s+[` + "`" + `'"]?\$`)
	reEncodedOut   = regexp.MustCompile(`(?i)\b(?:echo|print|exit|die)\s*\(?\s*base64_encode\s*\(`)
	reLoadsWP      = regexp.MustCompile(`(?i)\b(?:require|include)(?:_once)?\b[^;]{0,120}(?:wp-load|wp-config)`)
	reWPAuthChecks = regexp.MustCompile(`(?i)\b(?:current_user_can|is_user_logged_in|wp_verify_nonce|check_admin_referer|check_ajax_referer|hash_equals|password_verify)\s*\(`)
)

// wpDatabaseDump: loads WordPress and hands every table (users and their
// password hashes included) to whoever asks, packed so it does not read as
// data (dildarte's wt_fm_*_plugin-utils.php). Backup plugins check who
// asks first.
func wpDatabaseDump(s []byte) bool {
	return len(s) < 40000 && reLoadsWP.Match(s) && reShowTables.Match(s) && reSelectAll.Match(s) && reEncodedOut.Match(s) && !reWPAuthChecks.Match(s)
}

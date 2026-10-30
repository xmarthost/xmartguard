package ai

import (
	"database/sql"
	"path/filepath"
	"regexp"
	"strings"
)

// The AI is wrong about some malware: fake plugins of one large file of
// wrapped, encoded code look like a "licensing framework" to it, and a file
// manager hidden in wp-admin looks like a tool. Its clean verdict is only
// advice (no restore, nothing learned) for those signatures and for files
// where malware hides; an administrator decides.

// untrustedSignatures catch real malware nearly always (thousands of
// malicious verdicts on the fleet): a clean verdict is the exception.
var untrustedSignatures = map[string]bool{
	"PHP.Backdoor.GlobalsDispatch":         true,
	"PHP.Obfuscated.CompressedPayload":     true,
	"Archive.PHP.Backdoor.GlobalsDispatch": true,
	// The fake-plugin campaign of October 2026 (random three-word plugin
	// and mu-plugin names, wp-content drop-ins, random .zip copies): the
	// AI cleared some of its files as "backup" or "audit" plugins.
	"PHP.Obfuscated.SplitFunctionName":          true,
	"Archive.PHP.Obfuscated.SplitFunctionName":  true,
	"PHP.Obfuscated.EvalDecodedPayload":         true,
	"Archive.PHP.Obfuscated.EvalDecodedPayload": true,
	// Attack kits lock every folder with an .htaccess that refuses all PHP
	// but their own file names; the AI reads it as hardening.
	"Htaccess.Hacked.PHPLock":      true,
	"Htaccess.Webshell.CGIHandler": true,
	// The ClickFix kit (server1, 2026-10-30): its plugins pass for a
	// Cloudflare or CAPTCHA plugin, its hidden administrator for a
	// support account.
	"Phishing.ClickFix.FakeVerification": true,
	"Phishing.ClickFix.FakeClearance":    true,
	"PHP.Backdoor.HiddenAdmin":           true,
	"Htaccess.Hacked.CaptchaRedirect":    true,
	// Uploaded through wp-admin with known passwords (server1,
	// 2026-10-28): a self-hiding "dashboard branding" plugin and a fake
	// core plugin.
	"PHP.Backdoor.SelfHidingInjector": true,
	"PHP.Injector.HiddenScriptURL":    true,
	// Search engine cloaking in .htaccess reads as SEO configuration.
	"Htaccess.Hacked.SearchCloaking": true,
}

// wpDropIns are wp-content files WordPress loads on its own: malware
// replaces them to run on every page.
var reWPDropIn = regexp.MustCompile(`/wp-content/(?:db|object-cache|advanced-cache|maintenance|sunrise|blog-deleted|blog-inactive|blog-suspended|fatal-error-handler)\.php$`)

var scriptExt = map[string]bool{".php": true, ".phtml": true, ".phar": true, ".pht": true, ".php5": true, ".php7": true, ".inc": true, ".zip": true}

// Untrusted says why a clean verdict for a file found by signature at path
// must not stand without an administrator ("" = it may stand).
func Untrusted(path, signature string) string {
	if untrustedSignatures[signature] {
		return signature + " nearly always catches real malware"
	}
	return RiskyPath(path)
}

// RiskyPath says why path is where malware hides ("" = an ordinary place).
func RiskyPath(path string) string {
	p := strings.ToLower(filepath.ToSlash(path))
	ext := filepath.Ext(p)
	switch {
	case strings.Contains(p, "/wp-content/uploads/") && scriptExt[ext]:
		return "a script in the uploads folder"
	case (strings.Contains(p, "/wp-admin/") || strings.Contains(p, "/wp-includes/")) && scriptExt[ext]:
		return "a file in WordPress core folders that is not part of WordPress"
	case reWPDropIn.MatchString(p):
		return "a WordPress drop-in (loaded on every page)"
	case strings.Contains(p, "/wp-content/mu-plugins/"):
		return "a must-use plugin (loaded on every page, not listed with the plugins)"
	}
	// A hidden folder inside a website (not .well-known).
	for _, root := range []string{"/public_html/", "/wp-content/"} {
		if i := strings.Index(p, root); i >= 0 {
			for _, seg := range strings.Split(p[i+len(root):], "/")[0:] {
				if strings.HasPrefix(seg, ".") && seg != ".well-known" && seg != "." && seg != ".." && !strings.Contains(seg, ".htaccess") {
					if seg == filepath.Base(p) {
						break // a hidden file itself is judged by its content
					}
					return "a hidden folder inside the website"
				}
			}
		}
	}
	return ""
}

// untrustedSigList is the signatures as an SQL list.
func untrustedSigList() string {
	var q []string
	for s := range untrustedSignatures {
		q = append(q, "'"+s+"'")
	}
	return strings.Join(q, ",")
}

// untrustedHash reports content an untrusted signature caught here.
func untrustedHash(db *sql.DB, sha string) bool {
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM findings WHERE sha256 = ? AND signature IN (`+untrustedSigList()+`)`, sha).Scan(&n)
	return n > 0
}

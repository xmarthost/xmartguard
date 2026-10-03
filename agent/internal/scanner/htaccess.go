package scanner

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Hacked .htaccess files. After a site is taken over, attack kits write an
// .htaccess into every folder that refuses all PHP (so cleanup tools and
// other attackers' shells stop working) and allows only the attacker's own
// file names, or that runs a web shell as a CGI program:
//
//	<FilesMatch ".(py|exe|php)$"> Deny from all </FilesMatch>
//	<FilesMatch "^(lock360.php|wp-l0gin.php|index.php)$"> Allow from all </FilesMatch>
//
//	AddType application/x-httpd-cgi .alfa
//	AddHandler cgi-script .alfa
//
// Outside a WordPress root such a file is quarantined. The root .htaccess
// also holds the site's own rules (permalinks, caching), so there only the
// attack's blocks are removed and the WordPress rules are kept (or added).

var (
	reFilesMatch = regexp.MustCompile(`(?is)<FilesMatch\s+["']?([^"'>]*)["']?\s*>(.*?)</FilesMatch>`)
	reDenyAll    = regexp.MustCompile(`(?i)\bDeny\s+from\s+all\b|\bRequire\s+all\s+denied\b`)
	reAllowAll   = regexp.MustCompile(`(?i)\bAllow\s+from\s+all\b|\bRequire\s+all\s+granted\b`)
	// A list of .php names: ^(index.php|wp-l0gin.php|...)$
	rePHPNames = regexp.MustCompile(`(?i)\.php\b[^|)]*\|[^)]*\.php\b`)
	// Extension lists only attack kits write: PHP with py and exe, PHP in
	// mixed case, or the .suspected that cleanup tools give shells.
	reKitExts  = regexp.MustCompile(`(?i)\b(?:py\|exe|exe\|py)\b|\bsuspected\b`)
	reMixedPHP = regexp.MustCompile(`\b(?:Php|PHp|pHp|pHP|phP|PhP)\b`)
	// A CGI handler for an extension that is not a usual CGI script.
	reCGIHandler = regexp.MustCompile(`(?im)^\s*(?:AddHandler\s+cgi-script|AddType\s+application/x-httpd-cgi)\s+(.+)$`)
	// Extensions that are scripts anyway: hardening files (Magento's
	// pub/media) list them with Options -ExecCGI so they never run.
	cgiExts = map[string]bool{".cgi": true, ".pl": true, ".py": true, ".sh": true, ".rb": true, ".fcgi": true, ".php": true, ".jsp": true,
		".asp": true, ".aspx": true, ".htm": true, ".html": true, ".shtml": true, ".phtml": true}
	reNoExecCGI  = regexp.MustCompile(`(?im)^\s*Options\s+[^\n]*-ExecCGI\b`)
	reWPRewrite  = regexp.MustCompile(`(?i)RewriteRule\s+\.\s+\S*index\.php`)
	reBlankLines = regexp.MustCompile(`\n{3,}`)
)

// htaccessHack reports an .htaccess written by an attack kit.
func htaccessHack(content []byte) *Detection {
	if cgiShellHandler(content) {
		return &Detection{CatVirus, "Htaccess.Webshell.CGIHandler"}
	}
	if phpLock(content) {
		return &Detection{CatVirus, "Htaccess.Hacked.PHPLock"}
	}
	for _, m := range reFilesMatch.FindAllSubmatch(content, -1) {
		if kitDenyBlock(m[1], m[2]) {
			return &Detection{CatVirus, "Htaccess.Hacked.PHPLock"}
		}
	}
	return nil
}

// phpLock reports the whole lock: all PHP refused, then a list of PHP
// names allowed. (Hardening plugins refuse PHP in a folder and allow one
// file with <Files name.php>, never a list.)
func phpLock(content []byte) bool {
	var deny, allow bool
	for _, m := range reFilesMatch.FindAllSubmatch(content, -1) {
		deny = deny || denyPHPBlock(m[1], m[2])
		allow = allow || lockAllowBlock(m[1], m[2])
	}
	return deny && allow
}

func denyPHPBlock(pattern, body []byte) bool {
	return reDenyAll.Match(body) && bytes.Contains(bytes.ToLower(pattern), []byte("php"))
}

// kitDenyBlock reports a FilesMatch block only attack kits write: PHP
// refused together with py and exe, in mixed case, or with .suspected.
func kitDenyBlock(pattern, body []byte) bool {
	return denyPHPBlock(pattern, body) && (reKitExts.Match(pattern) || reMixedPHP.Match(pattern))
}

// lockAllowBlock is the second half of the lock: a list of PHP file names
// allowed after all PHP was refused.
func lockAllowBlock(pattern, body []byte) bool {
	return reAllowAll.Match(body) && rePHPNames.Match(pattern)
}

func cgiShellHandler(content []byte) bool {
	if reNoExecCGI.Match(content) {
		return false
	}
	for _, m := range reCGIHandler.FindAllSubmatch(content, -1) {
		for _, e := range strings.Fields(strings.ToLower(string(m[1]))) {
			if !strings.HasPrefix(e, ".") {
				e = "." + e
			}
			if !cgiExts[e] {
				return true
			}
		}
	}
	return false
}

// CleanHtaccess removes an attack kit's blocks from a site's .htaccess and
// keeps everything else; a WordPress root without its rewrite rules gets
// WordPress's default rules (base is the site's URL path, "/" or "/blog/").
func CleanHtaccess(content []byte, base string) []byte {
	lock := phpLock(content)
	out := reFilesMatch.ReplaceAllFunc(content, func(block []byte) []byte {
		m := reFilesMatch.FindSubmatch(block)
		if kitDenyBlock(m[1], m[2]) || (lock && (denyPHPBlock(m[1], m[2]) || lockAllowBlock(m[1], m[2]))) {
			return nil
		}
		return block
	})
	var lines []string
	for _, l := range strings.Split(string(out), "\n") {
		t := strings.TrimSpace(l)
		low := strings.ToLower(t)
		if reCGIHandler.MatchString(l) && cgiShellHandler([]byte(l)) {
			continue
		}
		// The kit's banner and the options it needs for the CGI shell.
		if strings.HasPrefix(t, "#") && strings.Contains(low, "coded by") {
			continue
		}
		if strings.HasPrefix(low, "options ") && strings.Contains(low, "execcgi") && cgiShellHandler(content) {
			continue
		}
		lines = append(lines, l)
	}
	clean := strings.TrimSpace(reBlankLines.ReplaceAllString(strings.Join(lines, "\n"), "\n\n"))
	if !reWPRewrite.MatchString(clean) {
		if base == "" || !strings.HasPrefix(base, "/") {
			base = "/"
		}
		if !strings.HasSuffix(base, "/") {
			base += "/"
		}
		wp := "# BEGIN WordPress\n<IfModule mod_rewrite.c>\nRewriteEngine On\nRewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]\n" +
			"RewriteBase " + base + "\nRewriteRule ^index\\.php$ - [L]\nRewriteCond %{REQUEST_FILENAME} !-f\nRewriteCond %{REQUEST_FILENAME} !-d\n" +
			"RewriteRule . " + base + "index.php [L]\n</IfModule>\n# END WordPress"
		if clean == "" {
			clean = wp
		} else {
			clean += "\n\n" + wp
		}
	}
	return []byte(clean + "\n")
}

// NoteHtaccess is the note of a cleaned WordPress .htaccess.
const NoteHtaccess = "Attack rules removed; the site's own and WordPress's rules kept"

// CleanHackedHtaccess puts a quarantined WordPress root .htaccess back
// without the attack's blocks (CleanHtaccess); the hacked copy stays in
// quarantine and Restore can bring it back.
func (s *Scanner) CleanHackedHtaccess(id int64) error {
	r, err := s.load(id)
	if err != nil {
		return err
	}
	if r.status != "quarantined" {
		return fmt.Errorf("cannot clean a %s file", r.status)
	}
	if _, err := os.Lstat(r.path); err == nil {
		return fmt.Errorf("a file already exists at %s", r.path)
	}
	orig, err := os.ReadFile(r.qpath)
	if err != nil {
		return err
	}
	if err := s.replaceLive(id, r, orig, CleanHtaccess(orig, siteBase(filepath.Dir(r.path))), "cleaned"); err != nil {
		return err
	}
	return s.SetNote(id, NoteHtaccess)
}

// SetNote records how a file was cleaned.
func (s *Scanner) SetNote(id int64, note string) error {
	_, err := s.DB.Exec(`UPDATE findings SET note = ? WHERE id = ?`, note, id)
	return err
}

// siteBase guesses the URL path of a site folder from the cPanel layout
// (/home/user/public_html/blog -> /blog/); "/" for an addon domain's root.
func siteBase(dir string) string {
	parts := strings.Split(filepath.ToSlash(dir), "/")
	for i, p := range parts {
		if p == "public_html" || p == "www" || p == "htdocs" {
			rest := strings.Join(parts[i+1:], "/")
			if rest == "" {
				return "/"
			}
			return "/" + rest + "/"
		}
	}
	return "/"
}

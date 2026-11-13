package scanner

import (
	"bytes"
	"errors"
	"regexp"
)

// Shapes of the "RAHASIA NEGARA" campaign (halaltech.co.uk on superfast,
// 2026-11-13). A mass injector (MassEvasion) put a password-gated file
// manager in front of the code of 84 theme, plugin and core files and set
// their dates back. Core files were replaced with the official copies, but
// the scanner quarantined the plugin and theme files whole: the gate is
// 49 KB, far over the trim limit, and the site went down on the missing
// require_once files. The gate ends where the original file starts, so it
// is cut off and the file stays (PasswordGateCut).

var (
	// A bcrypt hash written into the code: the gate's password.
	reBcryptLiteral  = regexp.MustCompile(`['"]\$2[aby]\$\d\d\$[./A-Za-z0-9]{53}['"]`)
	rePasswordVerify = regexp.MustCompile(`(?i)\bpassword_verify\s*\(`)
	reSessionStart   = regexp.MustCompile(`(?i)\bsession_start\s*\(`)
	reSessionVar     = regexp.MustCompile(`\$_SESSION\s*\[`)
	reHTMLEnd        = regexp.MustCompile(`(?i)</html\s*>`)
)

// gateHead: the file opens with PHP that checks a hard-coded bcrypt
// password from the request and keeps the visitor in a session, within
// its first few kilobytes.
func gateHead(content []byte) bool {
	t := bytes.TrimLeft(bytes.TrimPrefix(content, []byte("\xef\xbb\xbf")), " \t\r\n")
	if len(t) < 5 || !bytes.EqualFold(t[:5], []byte("<?php")) {
		return false
	}
	head := t[:min(len(t), 6000)]
	return reBcryptLiteral.Match(head) && rePasswordVerify.Match(head) && reSessionStart.Match(head) &&
		reSessionVar.Match(head) && reInput.Match(head)
}

// PasswordGateCut returns where the original file starts after a gate put
// in front of it (-1: no such gate). The gate is a complete page: the cut
// is after the first </html> outside PHP with every PHP block closed, and
// what follows must not carry the gate again and must not be empty.
func PasswordGateCut(content []byte) int {
	if !gateHead(content) {
		return -1
	}
	for _, end := range htmlEndsAtTop(content) {
		rest := content[end:]
		if len(bytes.TrimSpace(rest)) == 0 {
			return -1
		}
		if reBcryptLiteral.Match(rest) && rePasswordVerify.Match(rest) {
			continue // a second copy of the gate: cut further on
		}
		return end
	}
	return -1
}

// passwordGate: a gate with a clean end in front of other code.
func passwordGate(content []byte) bool { return PasswordGateCut(content) > 0 }

// htmlEndsAtTop lists the offsets just after each </html> found in HTML
// mode (outside <?php ... ?>) with no PHP brace left open. A small PHP
// lexer: strings, comments and close tags; nothing for heredocs, which
// end the search (the cut is then not certain).
func htmlEndsAtTop(b []byte) []int {
	var out []int
	inPHP, depth := false, 0
	for i := 0; i < len(b); {
		if !inPHP {
			j := bytes.Index(b[i:], []byte("<?"))
			k := reHTMLEnd.FindIndex(b[i:])
			if k != nil && (j < 0 || k[0] < j) {
				if depth == 0 {
					out = append(out, i+k[1])
				}
				i += k[1]
				continue
			}
			if j < 0 {
				return out
			}
			i += j + 2
			if i+3 <= len(b) && bytes.EqualFold(b[i:i+3], []byte("php")) {
				i += 3
			} else if i < len(b) && b[i] == '=' {
				i++
			}
			inPHP = true
			continue
		}
		switch c := b[i]; {
		case c == '?' && i+1 < len(b) && b[i+1] == '>':
			inPHP = false
			i += 2
		case c == '\'' || c == '"':
			i = skipString(b, i)
		case c == '#' || (c == '/' && i+1 < len(b) && b[i+1] == '/'):
			for i < len(b) && b[i] != '\n' && !(b[i] == '?' && i+1 < len(b) && b[i+1] == '>') {
				i++
			}
		case c == '/' && i+1 < len(b) && b[i+1] == '*':
			e := bytes.Index(b[i+2:], []byte("*/"))
			if e < 0 {
				return out
			}
			i += e + 4
		case c == '<' && bytes.HasPrefix(b[i:], []byte("<<<")):
			return out
		case c == '{':
			depth++
			i++
		case c == '}':
			depth--
			i++
		default:
			i++
		}
	}
	return out
}

// skipString returns the offset after the quoted string starting at i.
func skipString(b []byte, i int) int {
	q := b[i]
	for i++; i < len(b); i++ {
		switch b[i] {
		case '\\':
			i++
		case q:
			return i + 1
		}
	}
	return len(b)
}

// gateCuts turns the gate's end into Trim's line cuts: the whole lines
// before it, and on its last line the part up to the end of </html>.
func gateCuts(content []byte) ([]Cut, error) {
	end := PasswordGateCut(content)
	if end <= 0 {
		return nil, errors.New("no password gate with a clean end")
	}
	line := bytes.Count(content[:end], []byte("\n")) + 1
	start := bytes.LastIndexByte(content[:end], '\n') + 1
	var cuts []Cut
	if line > 1 {
		cuts = append(cuts, Cut{From: 1, To: line - 1})
	}
	part := content[start:end]
	lineEnd := len(content)
	if nl := bytes.IndexByte(content[end:], '\n'); nl >= 0 {
		lineEnd = end + nl + 1
	}
	if len(bytes.TrimSpace(content[end:lineEnd])) == 0 {
		// </html> ends its line: the whole line goes.
		cuts = append(cuts, Cut{From: line, To: line})
	} else if len(part) > 0 {
		cuts = append(cuts, Cut{From: line, To: line, Text: string(part)})
	}
	return cuts, nil
}

// trimPasswordGate puts a quarantined file back without the gate in front
// of it. The engine knows the gate's exact end, so the trim limit does not
// apply (the gate is often most of the file); the PHP syntax check and a
// new scan of the result still do.
func (s *Scanner) trimPasswordGate(id int64) error {
	r, err := s.load(id)
	if err != nil {
		return err
	}
	content, err := readFinding(r.qpath)
	if err != nil {
		return err
	}
	cuts, err := gateCuts(content)
	if err != nil {
		return err
	}
	return s.Trim(id, cuts, 100)
}

var (
	// MassEvasion-style injector: every PHP file of a tree gets the posted
	// code in front of its own, and its date put back.
	reGateDirWalk  = regexp.MustCompile(`(?i)\bRecursive(?:Directory|Iterator)Iterator\b|\bglob\s*\([^;]{0,80}\*\.\{?php`)
	reKeepMtime    = regexp.MustCompile(`(?i)\btouch\s*\(\s*\$\w+\s*,\s*\$\w+\s*\)|\btouch\s*\(\s*\$\w+\s*,\s*filemtime\s*\(`)
	reReadMtime    = regexp.MustCompile(`(?i)\bfilemtime\s*\(\s*\$\w+\s*\)`)
	rePrependOwn   = regexp.MustCompile(`(?i)\.=\s*file_get_contents\s*\(\s*\$\w+\s*\)`)
	rePutContents  = regexp.MustCompile(`(?i)\bfile_put_contents\s*\(\s*\$\w+\s*,\s*\$\w+`)
	reUploadedBody = regexp.MustCompile(`(?i)file_get_contents\s*\(\s*\$_FILES\s*\[|\$_(?:POST|REQUEST)\s*\[`)
)

// massPrepender: walks a tree, puts request-supplied code in front of each
// file's content and restores each file's date (the injector of the
// RAHASIA campaign: wp-content/plugin-editor.php).
func massPrepender(s []byte) bool {
	return reGateDirWalk.Match(s) && rePrependOwn.Match(s) && rePutContents.Match(s) && reReadMtime.Match(s) &&
		reKeepMtime.Match(s) && reUploadedBody.Match(s)
}

var (
	// "wp-" . "load.php" and the like: string pieces glued together.
	reGlue           = regexp.MustCompile(`['"]\s*\.\s*['"]`)
	reWPLoadGlued    = regexp.MustCompile(`(?i)['"](?:[./]*)wp-load\.php['"]`)
	reGateAuthCookie = regexp.MustCompile(`(?i)['"]wp_set_auth_cookie['"]|\bwp_set_auth_cookie\s*\(`)
	// Request data, not the server's own variables ($_SERVER: the
	// document root).
	reGateRequest   = regexp.MustCompile(`\$_(?:POST|GET|REQUEST|COOKIE|FILES)\b|php://input`)
	reAdminRoleWant = regexp.MustCompile(`(?i)['"]role['"]\s*=>\s*['"]administrator['"]|get_users\s*\(\s*[^)]{0,80}administrator|['"]administrator['"]`)
)

// openAdminLogin: a file that loads WordPress and logs whoever opens it in
// as an administrator, without reading any request data (no token, no
// password): data.php of the RAHASIA campaign, its names split in pieces.
func openAdminLogin(s []byte) (found, hidden bool) {
	if len(s) > 20000 || reGateRequest.Match(s) {
		return false, false
	}
	g := reGlue.ReplaceAll(s, nil)
	if !reWPLoadGlued.Match(g) || !reGateAuthCookie.Match(g) || !reAdminRoleWant.Match(g) {
		return false, false
	}
	return true, !reGateAuthCookie.Match(s) || !reWPLoadGlued.Match(s)
}

var (
	reHaltOffset   = regexp.MustCompile(`\b__COMPILER_HALT_OFFSET__\b`)
	reOwnFileRead  = regexp.MustCompile(`(?i)\b(?:fopen|file_get_contents)\s*\(\s*(?:__FILE__|\$\w+)`)
	reTmpInclude   = regexp.MustCompile(`(?i)\b(?:include|require)(?:_once)?\b[^;]{0,120}(?:socket_get_status|stream_get_meta_data)\s*\([^;]{0,60}\[\s*['"]uri['"]\s*\]`)
	reHaltDecoders = regexp.MustCompile(`(?i)\bgz(?:inflate|uncompress|decode)\s*\(|\bbase64_decode\s*\(|\bstr_rot13\s*\(|\bord\s*\(`)
)

// haltPayloadLoader: code after __halt_compiler() in the file itself is
// decoded and run from a temporary file (wp-content/geck.php, a "Composer
// Compiler" wrapper). A phar stub maps its archive; it does not include a
// temporary file's address.
func haltPayloadLoader(s []byte) bool {
	return reHaltOffset.Match(s) && reOwnFileRead.Match(s) && reHaltDecoders.Match(s) && reTmpInclude.Match(s)
}

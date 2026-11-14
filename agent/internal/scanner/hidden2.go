package scanner

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"regexp"
	"strings"
)

// Web shells found on server1.superfastcloudhosting (2026-11-11) that had
// no finding:
//   - 01.php keeps every function name it uses base64-encoded in a
//     variable ($FN_UNLINK = base64_decode('...'); $FN_UNLINK($f)).
//   - 04.php builds its decoder's name from two variables
//     ($a = 'base'; $b = '64_decode'; $c = $a.$b) and evals what it decodes.
//   - bootstrap.inc.php evals what curl_exec() fetched, in one expression;
//     options-media.php reads it through fopen() with a stream context.
//   - css.php evals the XOR of two strings.
//   - rum.php and editUsers.php write a decoded payload to a temporary file
//     and include it.
//   - hmhfm.php is a file manager with a command console behind a password.
//   - zip.php takes a ZIP upload and unpacks it where the request says.

var (
	// $name = <expression>; (one statement, short)
	reAnyAssign = regexp.MustCompile(`\$([A-Za-z_]\w*)\s*=\s*([^;=][^;]{0,299});`)
	// One part of a concatenation: a literal, a variable, or a decoder
	// applied to a literal.
	rePart = regexp.MustCompile(`^\s*(?:("(?:[^"\\\n]|\\.)*"|'[^'\n]*')|\$([A-Za-z_]\w*)|(base64_decode|str_rot13|strrev|hex2bin)\s*\(\s*("(?:[^"\\\n]|\\.)*"|'[^'\n]*')\s*\))\s*$`)
)

// hiddenNamed are the functions a shell hides by name: the runners and the
// file, network and decoding functions it works with.
var hiddenNamed = map[string]bool{"file_put_contents": true, "file_get_contents": true, "fopen": true, "fwrite": true,
	"fputs": true, "unlink": true, "rename": true, "rmdir": true, "mkdir": true, "copy": true, "chmod": true, "touch": true,
	"move_uploaded_file": true, "scandir": true, "opendir": true, "curl_exec": true, "curl_init": true, "fsockopen": true,
	"stream_socket_client": true, "base64_decode": true, "gzinflate": true, "str_rot13": true, "call_user_func": true}

// resolvedNames resolves the variables a file assigns from literals,
// other such variables and decoders applied to literals. disguised holds
// those whose value was hidden: concatenated, escaped or decoded.
func resolvedNames(s []byte) (val map[string]string, disguised map[string]bool) {
	val, disguised = map[string]string{}, map[string]bool{}
	for _, m := range reAnyAssign.FindAllSubmatch(s, 400) {
		name, expr := string(m[1]), string(m[2])
		parts := splitConcat(expr)
		if len(parts) == 0 || len(parts) > 40 {
			continue
		}
		var b strings.Builder
		hidden, ok := len(parts) > 1, true
		for _, p := range parts {
			pm := rePart.FindStringSubmatch(p)
			if pm == nil {
				ok = false
				break
			}
			switch {
			case pm[1] != "":
				lit := pm[1][1 : len(pm[1])-1]
				if pm[1][0] == '"' {
					if strings.Contains(lit, `\`) {
						hidden = true
					}
					lit = unescapePHP(lit)
				}
				b.WriteString(lit)
			case pm[2] != "":
				v, known := val[pm[2]]
				if !known {
					ok = false
				}
				hidden = hidden || disguised[pm[2]]
				b.WriteString(v)
			default:
				lit := pm[4][1 : len(pm[4])-1]
				if pm[4][0] == '"' {
					lit = unescapePHP(lit)
				}
				d, good := decodeLiteral(pm[3], lit)
				if !good {
					ok = false
				}
				hidden = true
				b.WriteString(d)
			}
			if !ok {
				break
			}
		}
		if !ok || b.Len() > 200 {
			continue
		}
		val[name] = strings.ToLower(strings.TrimSpace(b.String()))
		disguised[name] = hidden
	}
	return val, disguised
}

// splitConcat splits an expression at the dots outside string literals.
func splitConcat(e string) []string {
	var out []string
	start, q := 0, byte(0)
	for i := 0; i < len(e); i++ {
		c := e[i]
		switch {
		case q != 0 && c == '\\':
			i++
		case q != 0 && c == q:
			q = 0
		case q == 0 && (c == '\'' || c == '"'):
			q = c
		case q == 0 && c == '.':
			out = append(out, e[start:i])
			start = i + 1
		}
	}
	return append(out, e[start:])
}

func decodeLiteral(fn, lit string) (string, bool) {
	switch fn {
	case "base64_decode":
		b, err := base64.StdEncoding.DecodeString(lit)
		if err != nil {
			return "", false
		}
		return string(b), true
	case "hex2bin":
		b, err := hex.DecodeString(lit)
		if err != nil {
			return "", false
		}
		return string(b), true
	case "strrev":
		r := []byte(lit)
		for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
			r[i], r[j] = r[j], r[i]
		}
		return string(r), true
	case "str_rot13":
		r := []byte(lit)
		for i, c := range r {
			switch {
			case c >= 'a' && c <= 'z':
				r[i] = 'a' + (c-'a'+13)%26
			case c >= 'A' && c <= 'Z':
				r[i] = 'A' + (c-'A'+13)%26
			}
		}
		return string(r), true
	}
	return "", false
}

// hiddenDecoderVar: a decoder's name hidden in a variable ($c = $a.$b).
func hiddenDecoderVar(s []byte) bool {
	val, dis := resolvedNames(s)
	for v, d := range dis {
		if d && hiddenDecoders[val[v]] {
			return true
		}
	}
	return false
}

// hiddenRunnerOnInput: a runner's name hidden in a variable, called with
// request data.
func hiddenRunnerOnInput(s []byte) bool {
	val, dis := resolvedNames(s)
	for v, d := range dis {
		if !d || !hiddenRunners[val[v]] {
			continue
		}
		call := regexp.MustCompile(`\$` + regexp.QuoteMeta(v) + `\s*\(([^;]{0,300})`)
		for _, c := range call.FindAllSubmatch(s, 20) {
			if reRequestArg.Match(c[1]) {
				return true
			}
		}
	}
	return false
}

// hiddenFunctionNames counts the distinct functions whose names a file
// hides (decoded or pieced together) and then calls through the variable.
func hiddenFunctionNames(s []byte) int {
	val, dis := resolvedNames(s)
	seen := map[string]bool{}
	for v, d := range dis {
		f := val[v]
		if !d || seen[f] || !(hiddenNamed[f] || hiddenRunners[f]) {
			continue
		}
		if regexp.MustCompile(`\$` + regexp.QuoteMeta(v) + `\s*\(`).Match(s) {
			seen[f] = true
		}
	}
	return len(seen)
}

var (
	// eval('?>' . curl_exec($ch)) and the like: fetched code run at once.
	// file_get_contents() counts only for what is not a local file: a URL,
	// request data or decoded text (Smarty, in WHMCS, evaluates its own
	// compiled template: eval('?>' . file_get_contents($tpl->cached->filepath));
	// cloud2, 2026-11-14).
	reEvalFetchCall = regexp.MustCompile(`(?i)\beval\s*\(\s*(['"])\?>['"]\s*\.\s*@?\s*(?:curl_exec|stream_get_contents)\s*\(`)
	reEvalFileGet   = regexp.MustCompile(`(?i)\beval\s*\(\s*['"]\?>['"]\s*\.\s*@?\s*file_get_contents\s*\(\s*(['"]\s*(?:https?|ftp)://|\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\b|(?:base64_decode|str_rot13|hex2bin|gzinflate|urldecode)\s*\(|\$(\w+)\s*\))`)
	// Code read from a URL through a stream context (fopen($u, 'r', false, $ctx)).
	reStreamFetch = regexp.MustCompile(`(?i)\bstream_context_create\s*\(`)
	reStreamRead  = regexp.MustCompile(`(?i)\b(?:fread|fgets|stream_get_contents)\s*\(`)
	// eval of the XOR of two values.
	reXorEval = regexp.MustCompile(`(?i)\beval\s*\([^;]{0,60}\(\s*\$\w+\s*\^\s*\$\w+\s*\)`)
	// A temporary file: written, then included.
	reTempPath = regexp.MustCompile(`(?i)\b(?:tempnam|sys_get_temp_dir|tmpfile)\s*\(`)
)

// remoteEvalDirect: fetched code evaluated without a variable in between,
// or read from a URL through a stream context and evaluated.
func remoteEvalDirect(s []byte) bool {
	if reEvalFetchCall.Match(s) {
		return true
	}
	for _, m := range reEvalFileGet.FindAllSubmatch(s, 5) {
		if len(m[2]) == 0 {
			return true // a URL, request data or decoded text
		}
		// A plain variable: only when it holds a URL or request data.
		v := regexp.QuoteMeta(string(m[2]))
		if regexp.MustCompile(`(?i)\$` + v + `\s*=\s*(?:['"]\s*(?:https?|ftp)://|\$_(?:GET|POST|REQUEST|COOKIE)\b|(?:base64_decode|str_rot13|hex2bin|urldecode)\s*\()`).Match(s) {
			return true
		}
	}
	return reEvalFetched.Match(s) && reStreamFetch.Match(s) && reStreamRead.Match(s)
}

// tempIncludeLoader: decoded data written to a temporary file that is then
// included (the payload never sits in the file itself).
func tempIncludeLoader(s []byte) bool {
	if !reTempPath.Match(s) || !reDynInclude.Match(s) || !reDecoder.Match(s) {
		return false
	}
	for _, m := range reDynIncludeVar.FindAllSubmatch(s, 10) {
		v := regexp.QuoteMeta(string(m[1]))
		write := regexp.MustCompile(`(?i)\b(?:file_put_contents|fopen)\s*\(\s*\$` + v + `\b`)
		temp := regexp.MustCompile(`(?i)\$` + v + `\s*=[^;]{0,200}\b(?:tempnam|sys_get_temp_dir)\s*\(`)
		if write.Match(s) && temp.Match(s) {
			return true
		}
	}
	return false
}

var reDynIncludeVar = regexp.MustCompile(`(?i)\b(?:include|require)(?:_once)?\s*\(?\s*\$(\w+)\s*\)?\s*;`)

var (
	// A command run from a variable (the console of a file manager).
	reConsoleRun = regexp.MustCompile(`(?i)\b(?:proc_open|shell_exec|passthru|popen|system)\s*\(\s*\$\w+`)
	reZipExtract = regexp.MustCompile(`(?i)->\s*extractTo\s*\(`)
	reUploadTmp  = regexp.MustCompile(`(?i)\$_FILES\s*\[[^\]]+\]\s*\[\s*['"]tmp_name['"]\s*\]`)
	reAppLoad    = regexp.MustCompile(`(?i)\b(?:include|require)(?:_once)?\s*\(?\s*(?:__DIR__\s*\.\s*)?['"][^'"]*(?:wp-load|wp-config|config|bootstrap|autoload|init|db|database|functions|header)[^'"]*\.php['"]`)
)

// fileManagerShell: a one-file manager (browse, delete, rename, upload by
// request) with a command console. A login does not make it the site's own:
// applications' managers have no console, the dropped ones do.
func fileManagerShell(s []byte) bool {
	if !reConsoleRun.Match(s) || reClassDef.Match(s) || reAppLoad.Match(s) {
		return false
	}
	ops := 0
	for _, r := range reFileOps {
		if r.Match(s) {
			ops++
		}
	}
	return ops >= 4 && len(reFMParam.FindAll(s, 6)) >= 3
}

// zipDropper: a one-page ZIP uploader that unpacks the upload, with no
// login, into a folder the request names or its own.
func zipDropper(s []byte) bool {
	return len(s) < 20000 && reZipExtract.Match(s) && reUploadTmp.Match(s) && !reAuth.Match(s) &&
		!reClassDef.Match(s) && !reAppLoad.Match(s) && !bytes.Contains(s, []byte("wp_"))
}

// reFMOps are a file manager's operations: list, write, upload, delete,
// rename, make and remove folders.
var reFMOps = []*regexp.Regexp{
	regexp.MustCompile(`\b(?:scandir|opendir|glob)\s*\(`),
	regexp.MustCompile(`\bfile_put_contents\s*\(`),
	regexp.MustCompile(`\bmove_uploaded_file\s*\(`),
	regexp.MustCompile(`\bunlink\s*\(`),
	regexp.MustCompile(`\brename\s*\(`),
	regexp.MustCompile(`\bmkdir\s*\(`),
	regexp.MustCompile(`\brmdir\s*\(`),
}

// standaloneFileManager: one page that does everything a file manager does
// (all of reFMOps) and belongs to no application: no class, no database,
// loads no site file. The ones dropped on 2026-11-11 (kl.php, itu.php) had
// a login of their own, so a login alone does not clear it; it is then
// reported as suspicious for a look.
func standaloneFileManager(s []byte) bool {
	if len(s) > 120000 || reClassDef.Match(s) || reAppLoad.Match(s) || reDBCall.Match(s) || bytes.Contains(s, []byte("wp_")) {
		return false
	}
	for _, r := range reFMOps {
		if !r.Match(s) {
			return false
		}
	}
	return true
}

// reEvalDynCall: eval of what a function named by a variable returned
// (eval($a[70]($x)), eval($f($y))).
var reEvalDynCall = regexp.MustCompile(`(?i)\beval\s*\(\s*\$\w+(?:\s*\[[^\]]{1,20}\])?\s*\(`)

var (
	reZipRead     = regexp.MustCompile(`(?i)->\s*(?:extractTo|getFromIndex|getFromName)\s*\(`)
	reHtaccessLit = regexp.MustCompile(`['"][^'"\n]{0,80}\.htaccess['"]`)
)

// zipSiteDeployer: one page that takes a ZIP upload, unpacks it and writes
// .htaccess rules (setup.php, which put the gambling pages and their
// redirects into sites on 2026-11-11). A secret in the request does not
// make it the site's own.
func zipSiteDeployer(s []byte) bool {
	return len(s) < 60000 && bytes.Contains(s, []byte("ZipArchive")) && reZipRead.Match(s) && bytes.Contains(s, []byte("$_FILES")) &&
		bytes.Contains(s, []byte("tmp_name")) && reHtaccessLit.Match(s) && reFileOps[1].Match(s) && !reClassDef.Match(s) && !reAppLoad.Match(s) && !bytes.Contains(s, []byte("wp_"))
}

var (
	// WordPress loaded by a page of its own (not a plugin or theme).
	reWPLoadOwn = regexp.MustCompile(`(?i)\b(?:require|include)(?:_once)?\s*\(?\s*(?:dirname\s*\(\s*__FILE__\s*\)|__DIR__)\s*\.\s*['"]/wp-(?:load|blog-header)\.php['"]`)
	// What it does as the site: posts, users, logins.
	reWPActAs  = regexp.MustCompile(`\b(?:wp_insert_post|wp_update_post|wp_insert_user|wp_update_user|wp_set_auth_cookie|wp_set_current_user)\s*\(`)
	reWPLogsIn = regexp.MustCompile(`\b(?:wp_set_auth_cookie|wp_insert_user)\s*\(`)
	// A plugin's or theme's header, or a capability check.
	reWPOwnGuard = regexp.MustCompile(`(?i)Plugin Name:|Theme Name:|\bcurrent_user_can\s*\(|\bwp_verify_nonce\s*\(|\bcheck_admin_referer\s*\(|\bis_user_logged_in\s*\(`)
)

// wpRemoteActor: a page that loads WordPress itself and creates posts or
// users (or logs someone in) for whoever sends the request, checking no
// login (wp-actions.php posted the gambling pages as the administrator,
// 2026-11-11). Logging in or making users is a backdoor; posting only is
// reported for a look (a site's own import script can look the same).
func wpRemoteActor(s []byte) (found, login bool) {
	if len(s) > 40000 || !reWPLoadOwn.Match(s) || !reWPActAs.Match(s) || reWPOwnGuard.Match(s) || !reInput.Match(s) {
		return false, false
	}
	return true, reWPLogsIn.Match(s)
}

var (
	// copy(__FILE__, 'a.php'): the file copies itself.
	reCopySelf = regexp.MustCompile(`(?i)\bcopy\s*\(\s*__FILE__\s*,`)
	// touch() years into the future (time()+315360000): a date that keeps
	// the file out of "recently changed" lists.
	reTouchFuture = regexp.MustCompile(`(?i)\btouch\s*\([^;]{0,80}\btime\s*\(\s*\)\s*\+\s*\d{7,}`)
)

// selfReplicating: a file that copies itself under other names and dates
// itself years ahead (a.php, bots.php, wp-check.php; 2026-11-11).
func selfReplicating(s []byte) bool {
	return reCopySelf.Match(s) && reTouchFuture.Match(s)
}

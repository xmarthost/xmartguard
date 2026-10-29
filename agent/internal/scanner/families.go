package scanner

import (
	"bytes"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// Behavioural detections for malware families seen on shared hosting that
// the scoring rules in heuristics.go do not cover: loaders that silently
// include a hidden or non-PHP file, lookup-table and XOR obfuscation,
// character-builder decoders, droppers that spread into every writable
// directory, and SEO cloaking. Each rule describes a behaviour rather than a
// particular sample, so renamed and re-encoded variants are caught too.

var (
	// if (@is_file("/literal/path")) @include_once "…";
	reSilentLoader = regexp.MustCompile(`(?i)if\s*\(\s*@?\s*(?:is_file|file_exists|is_readable)\s*\(\s*["'][^"']{3,300}["']\s*\)\s*\)\s*\{?\s*@\s*(?:include|require)(?:_once)?\b`)
	// include/require of an image, archive, font, log or data file.
	reIncludeNonPHP = regexp.MustCompile(`(?i)\b(?:include|require)(?:_once)?\b\s*\(?[^;]{0,200}?\.(?:ico|png|jpe?g|gif|tiff?|bmp|webp|zip|gz|log|dat|tmp|bak|swp|mp3|mp4|pdf|woff2?|ttf|eot)['"]\s*\)?\s*;`)
	// include/require through a stream wrapper that runs code from inside an
	// archive, the request body or the address itself: zip://up.jpg#x.php,
	// data://text/plain;base64,…, php://input.
	reIncludeWrapper = regexp.MustCompile(`(?i)\b(?:include|require)(?:_once)?\b\s*\(?\s*[^;]{0,120}?['"](?:zip|data|expect|compress\.zlib|compress\.bzip2)://|\b(?:include|require)(?:_once)?\b\s*\(?\s*['"]php://(?:input|filter)`)
	// phar:// includes: a few libraries ship as a .phar and load from it
	// (and phar stubs, __HALT_COMPILER, include their own contents), so
	// this alone is only suspicious.
	reIncludePhar = regexp.MustCompile(`(?i)\b(?:include|require)(?:_once)?\b\s*\(?\s*[^;]{0,120}?['"]phar://`)
	// include/require of a hidden file: ".../.name.php" or ".name.php"
	// (not a ". '.json.php'" suffix).
	reIncludeHidden = regexp.MustCompile(`(?i)\b(?:include|require)(?:_once)?\b\s*\(?(?:[^;]{0,200}?/|\s*['"])(\.[a-z0-9_-][\w.-]*\.(?:php\d?|phtml|inc))['"]\s*\)?\s*;`)
	// f(40)($x): functions fetched from a lookup table by number.
	reFuncTable = regexp.MustCompile(`\b[a-zA-Z_]\w*\(\s*\d{1,4}\s*\)\s*\(`)
	// (212^222): constants hidden behind arithmetic.
	reXorConst = regexp.MustCompile(`\(\s*\d{1,5}\s*[\^|&]\s*\d{1,5}\s*\)`)
	// chr(ord($s[$i]) ^ $k): XOR string decoder.
	reXorChr = regexp.MustCompile(`(?i)chr\s*\(\s*ord\s*\([^()]*(?:\([^()]*\)[^()]*)*\)\s*\^`)
	// $out .= chr(...): builds a string one computed character at a time.
	reChrBuild  = regexp.MustCompile(`(?i)\.=\s*chr\s*\(\s*[^)'"]`)
	reCharBuild = orRe(reChrBuild, reXorChr)
	// include/require of a path computed by a decode function: f('…', 109).
	reDecodedInclude = regexp.MustCompile(`(?i)\b(?:include|require)(?:_once)?\b[^;]{0,120}\b[a-zA-Z_]\w*\(\s*['"][^'"]{3,}['"]\s*,\s*\d{1,4}\s*\)`)
	reIsWritable     = regexp.MustCompile(`(?i)\bis_writable\s*\(`)
	reDirWalk        = regexp.MustCompile(`(?i)\b(?:scandir|opendir|glob|readdir|RecursiveDirectoryIterator)\b|\bis_dir\s*\(`)
	reUserAgent      = regexp.MustCompile(`HTTP_USER_AGENT`)
	reSearchBots     = regexp.MustCompile(`(?i)googlebot|bingbot|yandex|baiduspider|google\.com/bot`)
	reRemoteFetch    = regexp.MustCompile(`(?i)\bcurl_exec\s*\(|\bfile_get_contents\s*\(\s*['"]https?://|\bfile_get_contents\s*\(\s*\$\w+\s*\.\s*['"]|\bfsockopen\s*\(|\bstream_socket_client\s*\(`)
	reEcho           = regexp.MustCompile(`(?i)\b(?:echo|print|die|exit)\b`)
	// $gml6imj8tur6a6sp: machine-generated variable names.
	reVarName = regexp.MustCompile(`\$([a-zA-Z_][a-zA-Z0-9_]{9,})`)
	reHashVar = regexp.MustCompile(`\$[a-z_]*[0-9a-f]{32}\b`)

	// eval("?>" . $x): runs decoded PHP/HTML.
	reEvalTemplate = regexp.MustCompile(`(?i)\beval\s*\(\s*["']\?>["']\s*\.`)
	reWPLoad       = regexp.MustCompile(`(?i)wp-load\.php|wp-blog-header\.php`)
	reAuthCookie   = regexp.MustCompile(`(?i)\bwp_set_auth_cookie\s*\(|\bwp_set_current_user\s*\(`)
	reCreateUser   = regexp.MustCompile(`(?i)\bwp_(?:create|insert)_user\s*\(`)
	reAdminRole    = regexp.MustCompile(`(?i)['"]administrator['"]|->set_role\s*\(`)
	reDisableFuncs = regexp.MustCompile(`(?i)\bini_set\s*\(\s*['"](?:disable_functions|open_basedir|safe_mode)['"]`)
	// A list of exec-family names: 'system', 'exec', 'shell_exec', …
	reExecList   = regexp.MustCompile(`(?i)(?:['"](?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)['"]\s*,\s*){3,}['"](?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)['"]`)
	reSelfDelete = regexp.MustCompile(`(?i)\bunlink\s*\(\s*(?:__FILE__|\$_SERVER\s*\[\s*['"]SCRIPT_FILENAME)`)
	reUpload     = regexp.MustCompile(`(?i)\bmove_uploaded_file\s*\(`)
	// 'gz'.'in'.'fla'.'te': string pieces joined into one literal.
	// Three or more pieces: 'base64' . '_decode' (two) is how some plugins
	// (Freemius) avoid the WordPress.org review scanner.
	reStrPieces = regexp.MustCompile(`(?:'[a-zA-Z0-9_]{1,12}'|"[a-zA-Z0-9_]{1,12}")(?:\s*\.\s*(?:'[a-zA-Z0-9_]{1,12}'|"[a-zA-Z0-9_]{1,12}")){2,8}`)
	splitNames  = []string{"base64_decode", "base64", "gzinflate", "gzuncompress", "gzdecode", "str_rot13", "create_function", "shell_exec", "passthru", "assert", "eval", "system", "file_put_contents", "move_uploaded_file", "call_user_func", "preg_replace"}
	// A hook that prints remote content: add_action('template_redirect'/'init' …
	// wp_remote_get(…'sslverify' => false…) … echo wp_remote_retrieve_body.
	reRemoteEcho  = regexp.MustCompile(`(?i)\becho\s+wp_remote_retrieve_body\s*\(`)
	reNoSSLVerify = regexp.MustCompile(`(?i)['"]sslverify['"]\s*=>\s*false`)
	reBotPattern  = regexp.MustCompile(`(?i)preg_match\s*\(\s*['"][^'"]*(?:google|bing|yandex|baidu|bot|crawl|spider|slurp)`)
	reIncludePage = regexp.MustCompile(`(?i)\b(?:include|require|readfile)(?:_once)?\b\s*\(?\s*['"][^'"]+\.(?:html?|shtml|txt|tpl)['"]`)
	reExit        = regexp.MustCompile(`(?i)\b(?:exit|die)\b`)
	reFrontHook   = regexp.MustCompile(`(?i)add_action\s*\(\s*['"](?:template_redirect|init|wp|wp_loaded|parse_request|send_headers)['"]`)

	// "\x2f\150…": string literals written as escapes.
	reEscapedChar = regexp.MustCompile(`\\(?:x[0-9a-fA-F]{1,2}|[0-7]{1,3})`)
	reDQLiteral   = regexp.MustCompile(`"((?:[^"\\]|\\.)+)"`)
	// cPanel keeps a domain's mail passwords in ~/etc/<domain>/shadow.
	reMailShadow = regexp.MustCompile(`(?i)/etc/[^/"'\n]{1,120}/shadow\b`)
	reMailStore  = regexp.MustCompile(`(?i)dovecot|/mail/[^"'\n]{0,120}/(?:cur|new|tmp|\.trash|\.sent)\b`)
	// A payload file fetched from a web address: https://host/x/wso.txt.
	reRemotePayload = regexp.MustCompile(`(?i)https?://[a-z0-9.-]+/[^"'\s]*\.(?:txt|php\d?|phtml)\b`)
	reSiteFolders   = regexp.MustCompile(`(?i)public_html|httpdocs|htdocs`)
	reFetch         = regexp.MustCompile(`(?i)\b(?:file_get_contents|curl_exec|fopen|copy)\s*\(`)
)

// escapedLiterals decodes the double-quoted literals of a source that hides
// its strings as escapes ("\x2f\x68…"); nil for ordinary sources.
func escapedLiterals(s []byte) []byte {
	if len(reEscapedChar.FindAllIndex(s, 40)) < 40 {
		return nil
	}
	var out bytes.Buffer
	for _, m := range reDQLiteral.FindAllSubmatch(s, 20000) {
		lit := m[1]
		for i := 0; i < len(lit); i++ {
			if lit[i] != '\\' || i+1 >= len(lit) {
				out.WriteByte(lit[i])
				continue
			}
			j, base, max := i+1, 8, 3
			if lit[j] == 'x' || lit[j] == 'X' {
				j, base, max = j+1, 16, 2
			}
			v, k := 0, j
			for ; k < len(lit) && k-j < max; k++ {
				d := hexVal(lit[k])
				if d < 0 || d >= base {
					break
				}
				v = v*base + d
			}
			if k == j {
				out.WriteByte(lit[i+1])
				i++
				continue
			}
			out.WriteByte(byte(v))
			i = k - 1
		}
		out.WriteByte('\n')
	}
	return out.Bytes()
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

// kitBehaviour: mass-infection kits (a sample from another product's
// quarantine, 2026-10-24: a goto-flattened script with every string
// escaped) that create mail accounts for spam in every domain of an account
// (writing ~/etc/<domain>/shadow and the mailbox folders) and copy shells
// fetched from a web address into every site. Judged on the source and on
// its decoded literals.
func kitBehaviour(s []byte) *verdict {
	decoded := escapedLiterals(s)
	view := s
	if decoded != nil {
		view = append(append(append([]byte{}, s...), '\n'), decoded...)
	}
	if !reWriteSink.Match(s) {
		return nil
	}
	if reMailShadow.Match(view) && reMailStore.Match(view) {
		return &verdict{CatVirus, "PHP.Spam.MailAccountCreator"}
	}
	if decoded != nil && reRemotePayload.Match(decoded) && reFetch.Match(s) && reSiteFolders.Match(decoded) && reDirWalk.Match(s) {
		return &verdict{CatVirus, "PHP.Dropper.RemoteSpreader"}
	}
	return nil
}

// families runs the behavioural rules. s is the comment-stripped source,
// n its length, library whether it looks like a legitimate library.
func families(s, low []byte, n int, library, compiledView, evalOrAssert, varFunc, hasInput bool, decoders int) *verdict {
	m := func(re *regexp.Regexp) bool { return may(re, low) && re.Match(s) }
	count := func(re *regexp.Regexp) int {
		if !may(re, low) {
			return 0
		}
		return len(re.FindAllIndex(s, -1))
	}
	if v := kitBehaviour(s); v != nil {
		return v
	}
	// Tiny loaders whose only job is to pull in another file.
	if m(reSilentLoader) && n < 4096 {
		return &verdict{CatVirus, "PHP.Loader.SilentInclude"}
	}
	if m(reIncludeNonPHP) {
		return &verdict{CatVirus, "PHP.Loader.IncludeNonPHP"}
	}
	if m(reIncludeWrapper) {
		return &verdict{CatVirus, "PHP.Loader.StreamWrapperInclude"}
	}
	if m(reIncludePhar) && !library && !bytes.Contains(s, []byte("__HALT_COMPILER")) && n < 8192 {
		return &verdict{CatSuspicious, "PHP.Suspicious.PharInclude"}
	}
	// (Developer tools' own settings include each other: .php-cs-fixer.dist.php
	// requires .php-cs-fixer.common.php.)
	if may(reIncludeHidden, low) && slices.ContainsFunc(reIncludeHidden.FindAllSubmatch(s, 20), func(m [][]byte) bool { return !devDotfile(string(m[1])) }) {
		if n < 4096 {
			return &verdict{CatVirus, "PHP.Loader.HiddenInclude"}
		}
		return &verdict{CatSuspicious, "PHP.Suspicious.HiddenInclude"}
	}
	sink := evalOrAssert || varFunc || decoders >= 1 || m(reWriteSink) || m(reDynInclude) || m(reRemoteFetch)
	// Lookup-table obfuscation: many calls through f(N)(…).
	if count(reFuncTable) >= 6 && sink {
		return &verdict{CatVirus, "PHP.Obfuscated.FunctionTable"}
	}
	// WebSocket clients build their frame header with chr(len | 0x80): not a decoder.
	chrBuild := m(reChrBuild) && !onlyFrameHeaders(s)
	xor := m(reXorChr)
	// Include of a path produced by a character-building decoder.
	if chrBuild && m(reDecodedInclude) {
		return &verdict{CatVirus, "PHP.Loader.DecodedInclude"}
	}
	// XOR/char decoders feeding an executor, a dynamic call or request data.
	// Closures the file defines itself ($uniq = fn(…)) are not dynamic calls.
	if varFunc && (xor || chrBuild) {
		varFunc = foreignVarCall(s)
	}
	// Without eval the built string must be called near where it is built
	// (Unyson's random-string helper builds with chr() far from any call).
	if (xor || chrBuild) && !library && (evalOrAssert || varFunc && (hasInput || m(reWriteSink)) && near(s, reCharBuild, reVarFunc, 1500)) {
		return &verdict{CatVirus, "PHP.Obfuscated.CharDecoder"}
	}
	// Droppers that write a decoded payload into every writable directory.
	if (xor || chrBuild) && m(reIsWritable) && m(reDirWalk) && m(reWriteSink) && !library {
		return &verdict{CatVirus, "PHP.Dropper.WritableDirs"}
	}
	// Machine-generated identifiers around an executor.
	if !compiledView && gibberish(s) && (evalOrAssert || varFunc || decoders >= 1 || count(reXorConst) >= 5) {
		return &verdict{CatVirus, "PHP.Obfuscated.RandomIdentifiers"}
	}
	if !compiledView && count(reHashVar) >= 4 && (m(reRemoteFetch) || evalOrAssert) {
		return &verdict{CatVirus, "PHP.Obfuscated.HashNamedVariables"}
	}
	// eval("?>" . decoded): runs a decoded page or PHP payload.
	if m(reEvalTemplate) && !library && (decoders >= 1 || varFunc || m(reLongB64) || m(reB64Blob)) {
		return &verdict{CatVirus, "PHP.Obfuscated.EvalTemplate"}
	}
	// Small scripts that load WordPress to log in as, or create, an admin.
	if n < 20000 && m(reWPLoad) && m(reAdminRole) {
		if m(reAuthCookie) {
			return &verdict{CatVirus, "PHP.Backdoor.WPAdminLogin"}
		}
		if m(reCreateUser) {
			return &verdict{CatVirus, "PHP.Backdoor.WPAdminCreator"}
		}
	}
	// Web shells: trying to lift disable_functions, or tables of exec
	// alternatives called dynamically.
	if m(reDisableFuncs) && (evalOrAssert || varFunc || m(reSink) || m(reExecBare)) {
		return &verdict{CatVirus, "PHP.WebShell.FunctionBypass"}
	}
	if m(reExecList) && varFunc && !library {
		return &verdict{CatVirus, "PHP.WebShell.ExecAlternatives"}
	}
	// Tiny script that takes request data, writes or uploads, and deletes itself.
	if n < 4096 && m(reSelfDelete) && m(reUserInput) && (m(reWriteSink) || m(reUpload)) {
		return &verdict{CatVirus, "PHP.Dropper.SelfDeleting"}
	}
	// Function names split into pieces so text searches miss them.
	if name := splitName(s); name != "" && (evalOrAssert || varFunc || decoders >= 1) {
		return &verdict{CatVirus, "PHP.Obfuscated.SplitFunctionName"}
	}
	// A front-end hook that prints content fetched from elsewhere with TLS
	// verification off (injected spam/redirect pages).
	if m(reFrontHook) && m(reRemoteEcho) && m(reNoSSLVerify) {
		return &verdict{CatVirus, "PHP.Injector.RemoteContent"}
	}
	// Cloaking: crawlers matched by User-Agent get a different page file.
	if m(reUserAgent) && m(reBotPattern) && m(reIncludePage) && m(reExit) {
		return &verdict{CatVirus, "PHP.SEO.UserAgentCloaking"}
	}
	// SEO cloaking: search engines get remote content, visitors another page.
	if m(reUserAgent) && m(reSearchBots) && m(reRemoteFetch) && m(reEcho) {
		return &verdict{CatSuspicious, "PHP.SEO.Cloaking"}
	}
	return nil
}

// gibberish reports source whose variable names are mostly machine
// generated: long, mixing letters and digits with no word structure.
func gibberish(s []byte) bool {
	names := map[string]bool{}
	for _, m := range reVarName.FindAllSubmatch(s, 4000) {
		names[string(m[1])] = true
	}
	if len(names) < 8 {
		return false
	}
	odd := 0
	for name := range names {
		if randomName(name) {
			odd++
		}
	}
	return odd >= 8 && odd*100/len(names) >= 40
}

func randomName(name string) bool {
	digits, switches := 0, 0
	prevDigit := false
	for i, c := range name {
		d := c >= '0' && c <= '9'
		if d {
			digits++
		}
		if i > 0 && d != prevDigit {
			switches++
		}
		prevDigit = d
	}
	// "var2", "item10", "sha256Sum" are words with a number; generated names
	// switch between letters and digits several times.
	return digits >= 3 && switches >= 4 && !strings.Contains(name, "_") || digits >= 3 && switches >= 6
}

var (
	// The value on the same line only: an empty setting (auto_prepend_file =
	// "", which cPanel's MultiPHP INI editor writes) loads nothing.
	reAutoPrepend = regexp.MustCompile(`(?im)^[ \t]*(?:php_value[ \t]+auto_(?:prepend|append)_file[ \t]+|auto_(?:prepend|append)_file[ \t]*=[ \t]*)["']?([^"'\s;#]+)`)
	// Security plugins that legitimately load through auto_prepend_file.
	knownPrepend = []string{"wordfence-waf.php", "ninjafirewall", "nfwlog", "malcare", "bv-", "sucuri", "wp-defender", "patchstack", "/usr/local/", "/opt/"}
	// A redirect or a frame: what SEO-spam and phishing pages hidden under
	// image names do. Scripts alone are not enough: CDN challenge and error
	// pages saved as .jpg by image importers (template kits, optimizers)
	// carry scripts too, and the web server sends .jpg files as images.
	reActiveMarkup   = regexp.MustCompile(`(?i)<iframe|http-equiv\s*=\s*["']?refresh|(?:window|document|top|self)\.location(?:\.href)?\s*=|location\.(?:replace|assign)\s*\(`)
	reSavedErrorPage = regexp.MustCompile(`(?i)cloudflare|_cf_chl|cf-browser-verification|just a moment|attention required|access denied|captcha|404 not found|403 forbidden|<title>[^<]*(?:error|not found)`)
	imageExts        = map[string]bool{".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".ico": true, ".bmp": true, ".tif": true, ".tiff": true, ".webp": true}
)

// configLoader flags php.ini, .user.ini and .htaccess files that make PHP
// load a file before (or after) every script.
func configLoader(content []byte) *Detection {
	for _, m := range reAutoPrepend.FindAllSubmatch(content, 5) {
		target := strings.ToLower(string(m[1]))
		if target == "none" || target == "" {
			continue
		}
		known := false
		for _, k := range knownPrepend {
			if strings.Contains(target, k) {
				known = true
			}
		}
		// Really Simple Security writes its headers file this way, with
		// its marker around the setting.
		if strings.HasSuffix(target, "/wp-content/advanced-headers.php") && bytes.Contains(content, []byte("Really Simple Auto Prepend File")) {
			known = true
		}
		if known {
			continue
		}
		base := filepath.Base(target)
		ext := filepath.Ext(base)
		if strings.HasPrefix(base, ".") || (ext != ".php" && ext != "") || strings.HasPrefix(target, "/tmp") || strings.HasPrefix(target, "/dev/shm") {
			return &Detection{CatVirus, "PHP.Config.AutoPrependLoader"}
		}
		return &Detection{CatSuspicious, "PHP.Config.AutoPrepend"}
	}
	return nil
}

// markupInImage flags image files that are really HTML or script pages
// (SEO spam and phishing pages hidden under image names).
func markupInImage(ext string, content []byte) *Detection {
	if !imageExts[ext] {
		return nil
	}
	head := bytes.TrimLeft(content[:min(len(content), 512)], " \t\r\n\ufeff")
	if len(head) > 0 && head[0] == '<' {
		low := bytes.ToLower(head[:min(len(head), 64)])
		if bytes.HasPrefix(low, []byte("<svg")) || bytes.HasPrefix(low, []byte("<?xml")) {
			return nil // an SVG saved with the wrong extension
		}
		// A cached HTML error page (a CDN or avatar cache saving a 404 page as
		// .jpg) is harmless; spam and phishing pages carry scripts,
		// frames or redirects.
		if reActiveMarkup.Match(content) && !reSavedErrorPage.Match(content) {
			return &Detection{CatSuspicious, "Disguised.MarkupInImage"}
		}
	}
	return nil
}

// splitName returns a sensitive function name that the source spells as
// several joined string pieces ('gz'.'in'.'fla'.'te'), or "".
func splitName(s []byte) string {
	if !quotedJoins(s) {
		return ""
	}
	for _, m := range reStrPieces.FindAll(s, 200) {
		var joined strings.Builder
		pieces := 0
		for _, part := range bytes.Split(m, []byte(".")) {
			part = bytes.Trim(bytes.TrimSpace(part), `'"`)
			joined.Write(part)
			pieces++
		}
		word := strings.ToLower(joined.String())
		for _, name := range splitNames {
			if strings.Contains(word, name) && !bytes.Contains(bytes.ToLower(m), []byte(name)) {
				return name
			}
		}
	}
	return ""
}

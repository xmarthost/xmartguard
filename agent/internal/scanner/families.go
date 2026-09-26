package scanner

import (
	"bytes"
	"path/filepath"
	"regexp"
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
	// include/require of a hidden file: ".../.name.php" or ".name.php"
	// (not a ". '.json.php'" suffix).
	reIncludeHidden = regexp.MustCompile(`(?i)\b(?:include|require)(?:_once)?\b\s*\(?(?:[^;]{0,200}?/|\s*['"])\.[a-z0-9_-][\w.-]*\.(?:php\d?|phtml|inc)['"]\s*\)?\s*;`)
	// f(40)($x): functions fetched from a lookup table by number.
	reFuncTable = regexp.MustCompile(`\b[a-zA-Z_]\w*\(\s*\d{1,4}\s*\)\s*\(`)
	// (212^222): constants hidden behind arithmetic.
	reXorConst = regexp.MustCompile(`\(\s*\d{1,5}\s*[\^|&]\s*\d{1,5}\s*\)`)
	// chr(ord($s[$i]) ^ $k): XOR string decoder.
	reXorChr = regexp.MustCompile(`(?i)chr\s*\(\s*ord\s*\([^()]*(?:\([^()]*\)[^()]*)*\)\s*\^`)
	// $out .= chr(...): builds a string one computed character at a time.
	reChrBuild = regexp.MustCompile(`(?i)\.=\s*chr\s*\(\s*[^)'"]`)
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
	reStrPieces = regexp.MustCompile(`(?:'[a-zA-Z0-9_]{1,12}'|"[a-zA-Z0-9_]{1,12}")(?:\s*\.\s*(?:'[a-zA-Z0-9_]{1,12}'|"[a-zA-Z0-9_]{1,12}")){1,8}`)
	splitNames  = []string{"base64_decode", "base64", "gzinflate", "gzuncompress", "gzdecode", "str_rot13", "create_function", "shell_exec", "passthru", "assert", "eval", "system", "file_put_contents", "move_uploaded_file", "call_user_func", "preg_replace"}
	// A hook that prints remote content: add_action('template_redirect'/'init' …
	// wp_remote_get(…'sslverify' => false…) … echo wp_remote_retrieve_body.
	reRemoteEcho  = regexp.MustCompile(`(?i)\becho\s+wp_remote_retrieve_body\s*\(`)
	reNoSSLVerify = regexp.MustCompile(`(?i)['"]sslverify['"]\s*=>\s*false`)
	reBotPattern  = regexp.MustCompile(`(?i)preg_match\s*\(\s*['"][^'"]*(?:google|bing|yandex|baidu|bot|crawl|spider|slurp)`)
	reIncludePage = regexp.MustCompile(`(?i)\b(?:include|require|readfile)(?:_once)?\b\s*\(?\s*['"][^'"]+\.(?:html?|shtml|txt|tpl)['"]`)
	reExit        = regexp.MustCompile(`(?i)\b(?:exit|die)\b`)
	reFrontHook   = regexp.MustCompile(`(?i)add_action\s*\(\s*['"](?:template_redirect|init|wp|wp_loaded|parse_request|send_headers)['"]`)
)

// families runs the behavioural rules. s is the comment-stripped source,
// n its length, library whether it looks like a legitimate library.
func families(s, low []byte, n int, library, evalOrAssert, varFunc, hasInput bool, decoders int) *verdict {
	m := func(re *regexp.Regexp) bool { return may(re, low) && re.Match(s) }
	count := func(re *regexp.Regexp) int {
		if !may(re, low) {
			return 0
		}
		return len(re.FindAllIndex(s, -1))
	}
	// Tiny loaders whose only job is to pull in another file.
	if m(reSilentLoader) && n < 4096 {
		return &verdict{CatVirus, "PHP.Loader.SilentInclude"}
	}
	if m(reIncludeNonPHP) {
		return &verdict{CatVirus, "PHP.Loader.IncludeNonPHP"}
	}
	if m(reIncludeHidden) {
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
	chrBuild := m(reChrBuild)
	xor := m(reXorChr)
	// Include of a path produced by a character-building decoder.
	if chrBuild && m(reDecodedInclude) {
		return &verdict{CatVirus, "PHP.Loader.DecodedInclude"}
	}
	// XOR/char decoders feeding an executor, a dynamic call or request data.
	if (xor || chrBuild) && !library && (evalOrAssert || (varFunc && hasInput) || (varFunc && m(reWriteSink))) {
		return &verdict{CatVirus, "PHP.Obfuscated.CharDecoder"}
	}
	// Droppers that write a decoded payload into every writable directory.
	if (xor || chrBuild) && m(reIsWritable) && m(reDirWalk) && m(reWriteSink) && !library {
		return &verdict{CatVirus, "PHP.Dropper.WritableDirs"}
	}
	// Machine-generated identifiers around an executor.
	if gibberish(s) && (evalOrAssert || varFunc || decoders >= 1 || count(reXorConst) >= 5) {
		return &verdict{CatVirus, "PHP.Obfuscated.RandomIdentifiers"}
	}
	if count(reHashVar) >= 4 && (m(reRemoteFetch) || evalOrAssert) {
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
	reAutoPrepend = regexp.MustCompile(`(?im)^\s*(?:php_value\s+)?auto_(?:prepend|append)_file\s*=?\s*["']?([^"'\s]+)`)
	// Security plugins that legitimately load through auto_prepend_file.
	knownPrepend = []string{"wordfence-waf.php", "ninjafirewall", "nfwlog", "malcare", "bv-", "sucuri", "wp-defender", "patchstack", "/usr/local/", "/opt/"}
	imageExts    = map[string]bool{".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".ico": true, ".bmp": true, ".tif": true, ".tiff": true, ".webp": true}
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
		return &Detection{CatSuspicious, "Disguised.MarkupInImage"}
	}
	return nil
}

// splitName returns a sensitive function name that the source spells as
// several joined string pieces ('gz'.'in'.'fla'.'te'), or "".
func splitName(s []byte) string {
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

package scanner

import (
	"bytes"
	"math"
	"regexp"
	"strings"
)

// This file implements XMart Guard's own heuristic PHP/JS analyzer. It scores
// several independent signals (obfuscation, decoders, dangerous sinks, input
// flow) and flags a file only when the combination is characteristic of
// malware, keeping false positives on legitimate code low. All patterns are
// our own, written from the behaviour of common backdoor/webshell techniques.

var (
	reEvalSink   = regexp.MustCompile(`(?i)\b(?:eval|assert)\s*\(`)
	reCreateFunc = regexp.MustCompile(`(?i)\bcreate_function\s*\(`)
	rePregE      = pregEvalModifier()
	reDecoder    = regexp.MustCompile(`(?i)\b(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|hex2bin|convert_uu(?:decode)?|urldecode|rawurldecode|bzdecompress|base_convert|pack)\s*\(`)
	reInput      = regexp.MustCompile(`\$_(?:POST|GET|REQUEST|COOKIE|SERVER|FILES)\b`)
	// Functions, not methods: "->exec(" and "Hook::exec(" are ordinary code.
	reSink          = regexp.MustCompile(`(?i)(?:^|[^\w$>:\\])(?:system|shell_exec|passthru|proc_open|popen|pcntl_exec)\s*\(`)
	reExecBare      = regexp.MustCompile(`(?i)(?:^|[^\w$>:\\])exec\s*\(`)
	reVarFunc       = regexp.MustCompile(`\$(?:[a-zA-Z_]\w*|_(?:POST|GET|REQUEST|COOKIE|SERVER)\s*\[[^\]]+\])\s*\(`)
	reCallUserFunc  = regexp.MustCompile(`(?i)\bcall_user_func(?:_array)?\s*\(`)
	reUploader      = regexp.MustCompile(`(?i)move_uploaded_file\s*\(`)
	reFilesName     = regexp.MustCompile(`\$_FILES\b`)
	reWriteSink     = regexp.MustCompile(`(?i)\b(?:file_put_contents|fwrite|fputs)\s*\(`)
	reWriteSinkFile = regexp.MustCompile(`(?i)\b(?:file_put_contents|fwrite|fputs)\s*\(\s*[^'"\s]|\b(?:file_put_contents|fwrite|fputs)\s*\(\s*['"](?:[^p'"]|p[^h]|ph[^p]|php[^:])`)
	reUserInput     = regexp.MustCompile(`\$_(?:POST|GET|REQUEST|COOKIE|FILES)\b`)
	reGoto          = regexp.MustCompile(`(?i)\bgoto\s+[a-zA-Z_]\w*\s*;`)
	reHex           = regexp.MustCompile(`\\x[0-9A-Fa-f]{2}`)
	reOct           = regexp.MustCompile(`\\[0-3][0-7]{2}`)
	reChr           = regexp.MustCompile(`(?i)\bchr\s*\(`)
	reConcatChar    = regexp.MustCompile(`['"]\s*\.\s*['"]`)
	reLongB64       = regexp.MustCompile(`['"][A-Za-z0-9+/]{260,}={0,2}['"]`)
	reB64Blob       = regexp.MustCompile(`[A-Za-z0-9+/]{120,}={0,2}`)
	// A real statement, not the text "__halt_compiler();" inside a string.
	reHalt         = regexp.MustCompile(`(?im)(?:^|[;{}\s])__halt_compiler\s*\(\s*\)\s*;`)
	reGzUncompress = regexp.MustCompile(`(?i)\bgz(?:inflate|uncompress|decode)\s*\(`)
	reDynInclude   = regexp.MustCompile(`(?i)\b(?:include|require)(?:_once)?\s*\(?\s*\$`)
	reMailInput    = regexp.MustCompile(`(?i)\bmail\s*\(`)
	reGlobalsCall  = regexp.MustCompile(`\$GLOBALS\s*\[[^\]]+\]\s*(?:\[[^\]]+\]\s*)*\(`)
	reAssertVar    = regexp.MustCompile(`(?i)\bassert\s*\(\s*(?:@\s*)?\$`)
	reOrdChr       = regexp.MustCompile(`(?i)\b(?:ord|chr|pack|base_convert)\s*\(`)
	reStrReplace   = regexp.MustCompile(`(?i)\bstr_replace\s*\(`)
	reDefineArr    = regexp.MustCompile(`\$\w+\s*=\s*(?:array\s*\(|\[)\s*(?:['"\x60][^'"\x60]{0,4}['"\x60]\s*,\s*){12,}`)
	reEvalGz       = regexp.MustCompile(`(?i)\b(?:eval|assert|create_function)\s*\(`)
	// A function name taken straight from request data: $_POST['f'](...) or
	// call_user_func($_GET['f'], ...).
	reInputCall     = regexp.MustCompile(`\$_(?:POST|GET|REQUEST|COOKIE|SERVER)\s*\[[^\]]+\]\s*\(`)
	reCallUserInput = regexp.MustCompile(`(?i)\bcall_user_func(?:_array)?\s*\(\s*(?:@\s*)?\$_(?:POST|GET|REQUEST|COOKIE|SERVER)\b`)
	// $f = $_POST['f'] (optionally through trim/stripslashes/decoders).
	reTaintAssign = regexp.MustCompile(`(?i)\$([a-zA-Z_]\w*)\s*=\s*(?:@\s*)?(?:(?:trim|stripslashes|base64_decode|str_rot13|strrev|urldecode|rawurldecode|hex2bin|gzinflate|gzuncompress|strtolower)\s*\(\s*)*\$_(?:POST|GET|REQUEST|COOKIE|SERVER)\b`)
	rePhpOpen     = regexp.MustCompile(`<\?(?:php|=)`)
	reWpNonce     = regexp.MustCompile(`(?i)wp_(?:nonce|verify_nonce|enqueue|register)`)
	// A backtick command substitution on a real code line (assignment, echo,
	// return or print) that embeds attacker input — not a docblock example.
	reBacktickExec = regexp.MustCompile("(?i)(?:=|echo|return|print|exec|system)\\s*`[^`]{0,200}\\$_(?:POST|GET|REQUEST|COOKIE)")
	// move_uploaded_file whose destination is the raw client-supplied filename.
	reUploadRaw = regexp.MustCompile(`(?is)move_uploaded_file\s*\([^;]{0,200}\$_FILES\s*\[[^\]]+\]\s*\[\s*['"]name['"]`)
	// Markers of a legitimate framework/library file.
	reNamespace = regexp.MustCompile(`(?m)^\s*namespace\s+[A-Za-z_\\]`)
	reClassDef  = regexp.MustCompile(`(?m)^\s*(?:abstract\s+|final\s+)?(?:class|interface|trait)\s+\w`)
	reFuncDef   = regexp.MustCompile(`(?i)\bfunction\s+\w+\s*\(`)

	reSinkOrExec = orRe(reSink, reExecBare)
	reExecutors  = orRe(reEvalSink, reVarFunc, reGlobalsCall)
)

// heuristic result codes map to signature names.
type verdict struct {
	category  string
	signature string
}

// analyzePHP scores a PHP/script file. Returns nil when nothing fires.
func analyzePHP(content []byte) *verdict {
	// Only analyse files that actually contain PHP.
	if !rePhpOpen.Match(content) {
		return nil
	}
	s := stripPHPComments(content)
	n := len(s)
	low := lowerASCII(s)
	m := func(re *regexp.Regexp) bool { return may(re, low) && re.Match(s) }
	cnt := func(re *regexp.Regexp) int {
		if !may(re, low) {
			return 0
		}
		return countMatches(re, s)
	}
	nr := func(a, b *regexp.Regexp, window int) bool { return may(a, low) && may(b, low) && near(s, a, b, window) }

	evalOrAssert := m(reEvalSink)
	decoders := cnt(reDecoder)
	hasInput := m(reInput)
	longBlob := m(reLongB64)
	hex := cnt(reHex)
	oct := cnt(reOct)
	chr := cnt(reChr)
	// Only consulted together with eval/assert (reAssertVar implies it too).
	concat := 0
	if evalOrAssert {
		concat = cnt(reConcatChar)
	}
	goto_ := cnt(reGoto)
	varFunc := m(reVarFunc)
	// A file with a namespace, or several functions plus a class/interface, and
	// little obfuscation, is almost certainly a legitimate library. The strong
	// input-flow rules below still apply to it; only the ambiguous
	// obfuscation-density rules consult this guard.
	library := m(reNamespace) ||
		(cnt(reFuncDef) >= 4 && m(reClassDef) && !longBlob && goto_ < 4)

	// 1. preg_replace with the /e modifier (executes its replacement).
	// (Old libraries such as phpseclib still carry /e code paths for PHP 5.)
	if m(rePregE) && !library {
		return &verdict{CatVirus, "PHP.Backdoor.PregReplaceEval"}
	}
	// 2. create_function with attacker input.
	if m(reCreateFunc) && hasInput && argOnInput(reCreateFuncArg, s) {
		return &verdict{CatVirus, "PHP.Backdoor.CreateFunction"}
	}
	// 3. eval/assert of a decoded payload: a long encoded blob, or a decoder
	// chain right next to the executor.
	if evalOrAssert && decoders >= 1 && (longBlob || (decoders >= 2 && nr(reEvalSink, reDecoder, 200))) && !library {
		return &verdict{CatVirus, "PHP.Obfuscated.EvalDecodedPayload"}
	}
	// 4. eval/assert whose argument is attacker input (directly, or a variable
	// assigned from it). eval($code) merely near $_POST is not enough.
	if evalOrAssert && hasInput && evalOnInput(s) {
		return &verdict{CatVirus, "PHP.Backdoor.EvalInput"}
	}
	// 5. Command execution driven by attacker input (incl. backticks).
	if (m(reSink) || m(reExecBare)) && hasInput && nr(reSinkOrExec, reInput, 200) {
		return &verdict{CatVirus, "PHP.Backdoor.CommandInjection"}
	}
	if m(reBacktickExec) {
		return &verdict{CatVirus, "PHP.Backdoor.BacktickInput"}
	}
	// 6. A function whose NAME comes from the request: $_POST['f'](...),
	// call_user_func($_GET['f']), or $f = $_POST['f']; ... $f(...).
	// (Calling a callback with request data as arguments is ordinary code.)
	if hasInput && (m(reInputCall) || m(reCallUserInput) || (may(reTaintAssign, low) && taintedCall(s))) {
		return &verdict{CatVirus, "PHP.Backdoor.DynamicCall"}
	}
	// 7. goto-flattened obfuscation with an execution sink.
	if goto_ >= 8 && (evalOrAssert || decoders >= 1 || m(reSink)) {
		return &verdict{CatVirus, "PHP.Obfuscated.GotoFlow"}
	}
	// 8. Heavy hex/octal/chr obfuscation building code.
	dens := float64(hex*4+oct*4+chr*4) / float64(max64(n, 1))
	if (hex+oct >= 40 || chr >= 40) && dens > 0.10 && (evalOrAssert || decoders >= 1 || varFunc) {
		return &verdict{CatVirus, "PHP.Obfuscated.CharEncoded"}
	}
	// 9. eval/assert after __halt_compiler (payload appended to the file).
	if m(reHalt) && evalOrAssert {
		return &verdict{CatVirus, "PHP.Obfuscated.HaltCompilerPayload"}
	}
	// 10. Compressed payload include (gzinflate blob without eval, still executed).
	if m(reGzUncompress) && longBlob && (evalOrAssert || m(reDynInclude) || varFunc) {
		return &verdict{CatVirus, "PHP.Obfuscated.CompressedPayload"}
	}
	// 11. Uploader that saves the raw client-supplied filename (lets the
	// attacker choose the .php destination).
	// Standalone uploader scripts are small; in a large application file
	// (an admin import controller) it is only worth a look.
	if m(reUploadRaw) && !m(reWpNonce) {
		if n < 20000 {
			return &verdict{CatVirus, "PHP.Uploader.MoveUploadedFile"}
		}
		return &verdict{CatSuspicious, "PHP.Suspicious.RawUploadName"}
	}
	// 12. Drop-and-write shell: writes a file from attacker input.
	// ($_SERVER and writes to php:// streams are request logging, not dropping.)
	if m(reWriteSink) && m(reUserInput) && (m(reChr) || decoders >= 1) && nr(reWriteSinkFile, reUserInput, 200) {
		return &verdict{CatVirus, "PHP.Backdoor.FileDropper"}
	}
	// 13. Spam mailer: mail() fed attacker input, in a small standalone script
	// (not a mail library, which defines classes).
	// Only when the recipient comes from the request: a contact form sends
	// visitor text to a fixed address, a spam relay sends to anyone.
	if m(reMailInput) && hasInput && argOnInput(reMailTo, s) && !library && n < 60000 {
		return &verdict{CatSuspicious, "PHP.Spam.Mailer"}
	}

	// 14. $GLOBALS['x'][y](...) dynamic dispatch (very common in packed shells).
	if m(reGlobalsCall) && (decoders >= 1 || evalOrAssert || hasInput) {
		return &verdict{CatVirus, "PHP.Backdoor.GlobalsDispatch"}
	}
	// 15. assert() on a variable expression built by the file.
	if m(reAssertVar) && !library && (decoders >= 1 || chr >= 10 || concat >= 20 || goto_ >= 4) {
		return &verdict{CatVirus, "PHP.Backdoor.AssertVariable"}
	}
	// 16. Character-array decoder: builds code from ord/chr/pack next to an
	// executor. Excludes crypto/encoding libraries, which use ord/pack heavily.
	ordChr := cnt(reOrdChr)
	if ordChr >= 25 && !library && (evalOrAssert || varFunc || m(reGlobalsCall)) &&
		nr(reOrdChr, reExecutors, 400) {
		return &verdict{CatVirus, "PHP.Obfuscated.CharArrayDecoder"}
	}
	// 17. Large inline character/string array feeding an executor.
	if m(reDefineArr) && m(reEvalGz) && !library {
		return &verdict{CatVirus, "PHP.Obfuscated.PackedArray"}
	}
	// 18. Minified single-line PHP with an executor (packed one-liner).
	if evalOrAssert && longestLine(s) > 2000 && n < 300000 && (decoders >= 1 || concat >= 15 || varFunc) {
		return &verdict{CatVirus, "PHP.Obfuscated.PackedOneLiner"}
	}
	// Laravel compiled Blade views end with /**PATH … ENDPATH**/ and use
	// hash-named variables ($__componentOriginal<md5>).
	compiledView := bytes.Contains(content, []byte("ENDPATH**/"))
	if v := families(s, low, n, library, compiledView, evalOrAssert, varFunc, hasInput, decoders); v != nil {
		return v
	}
	// ---- weaker signals -> suspicious (report only) ----
	if longBlob && (decoders >= 1 || evalOrAssert) {
		return &verdict{CatSuspicious, "PHP.Suspicious.EncodedPayload"}
	}
	if concat >= 40 && evalOrAssert && !library {
		return &verdict{CatSuspicious, "PHP.Suspicious.ConcatObfuscation"}
	}
	if evalOrAssert && n < 200000 && entropyOfLongestToken(s) > 5.4 {
		return &verdict{CatSuspicious, "PHP.Suspicious.HighEntropyEval"}
	}
	return nil
}

var (
	reJSHexArray = regexp.MustCompile(`(?i)eval\s*\(\s*(?:function|String\.fromCharCode|unescape|atob)\b`)
	reJSMiner    = regexp.MustCompile(`(?i)(?:coinhive|cryptoloot|coin-hive|webmine\.pro|crypto-loot|deepMiner|CoinImp|JSECoin)`)
	reJSHexBlob  = regexp.MustCompile(`(?:\\x[0-9A-Fa-f]{2}){80,}`)
	reJSDocWrite = regexp.MustCompile(`(?i)document\.write\s*\(\s*unescape\s*\(`)
)

// analyzeJS scores JavaScript.
func analyzeJS(content []byte) *verdict {
	low := lowerASCII(content)
	m := func(re *regexp.Regexp) bool { return may(re, low) && re.Match(content) }
	if m(reJSMiner) {
		return &verdict{CatVirus, "JS.Miner.Browser"}
	}
	if m(reJSHexArray) && (m(reJSHexBlob) || m(reLongB64)) {
		return &verdict{CatSuspicious, "JS.Obfuscated.EvalPacked"}
	}
	if m(reJSDocWrite) {
		return &verdict{CatSuspicious, "JS.Injection.DocumentWriteUnescape"}
	}
	return nil
}

// taintedCall reports a variable assigned from request data and then
// called as a function (or passed as the callback of call_user_func).
func taintedCall(s []byte) bool {
	for _, m := range reTaintAssign.FindAllSubmatch(s, 20) {
		name := regexp.QuoteMeta(string(m[1]))
		// $f(…), not $this->$f(…) or Class::$f(…) (dispatch to own methods).
		re := regexp.MustCompile(`(?:(?:^|[^>:\w$])\$` + name + `\s*\(|(?i:call_user_func(?:_array)?)\s*\(\s*\$` + name + `\b)`)
		if re.Match(s) {
			return true
		}
	}
	return false
}

func countMatches(re *regexp.Regexp, s []byte) int { return len(re.FindAllIndex(s, -1)) }

// near reports whether a match of a and a match of b occur within window bytes.
func near(s []byte, a, b *regexp.Regexp, window int) bool {
	am := a.FindAllIndex(s, -1)
	bm := b.FindAllIndex(s, -1)
	if len(am) == 0 || len(bm) == 0 {
		return false
	}
	for _, x := range am {
		for _, y := range bm {
			d := x[0] - y[0]
			if d < 0 {
				d = -d
			}
			if d <= window {
				return true
			}
		}
	}
	return false
}

func orRe(res ...*regexp.Regexp) *regexp.Regexp {
	// Combine sources into one alternation for near() use.
	src := ""
	for i, r := range res {
		if i > 0 {
			src += "|"
		}
		src += "(?:" + r.String() + ")"
	}
	return regexp.MustCompile(src)
}

// entropyOfLongestToken returns the Shannon entropy of the longest base64-ish
// run, a proxy for an encrypted/packed payload.
func entropyOfLongestToken(s []byte) float64 {
	m := reB64Blob.Find(s)
	if len(m) < 64 {
		return 0
	}
	var freq [256]int
	for _, c := range m {
		freq[c]++
	}
	var h float64
	L := float64(len(m))
	for _, f := range freq {
		if f == 0 {
			continue
		}
		p := float64(f) / L
		h -= p * math.Log2(p)
	}
	return h
}

func longestLine(s []byte) int {
	maxlen, cur := 0, 0
	for _, c := range s {
		if c == '\n' {
			if cur > maxlen {
				maxlen = cur
			}
			cur = 0
		} else {
			cur++
		}
	}
	if cur > maxlen {
		maxlen = cur
	}
	return maxlen
}

func max64(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// pregEvalModifier matches preg_replace with the /e modifier (the replacement
// is executed as PHP) for the usual delimiters, reading the pattern string
// properly so quotes and letters inside the pattern do not count.
func pregEvalModifier() *regexp.Regexp {
	var alts []string
	for _, d := range []string{"/", "#", "~", "!", "@", "|", "%", "+"} {
		q := regexp.QuoteMeta(d)
		for _, quote := range []string{"'", `"`} {
			alts = append(alts, quote+q+`(?:[^`+quote+`\\`+q+`]|\\.)*`+q+`[a-zA-Z]*e[a-zA-Z]*`+quote)
		}
	}
	return regexp.MustCompile(`(?i:\bpreg_replace)\s*\(\s*(?:` + strings.Join(alts, "|") + `)`)
}

var (
	reEvalArg       = regexp.MustCompile(`(?i)\b(?:eval|assert)\s*\(([^;]{0,300})`)
	reCreateFuncArg = regexp.MustCompile(`(?i)\bcreate_function\s*\(([^;]{0,300})`)
	reMailTo        = regexp.MustCompile(`(?i)\bmail\s*\(([^,;]{0,200})`)
)

// evalOnInput reports eval/assert whose argument contains request data or a
// variable assigned from it.
func evalOnInput(s []byte) bool { return argOnInput(reEvalArg, s) }

// argOnInput reports a call (captured argument text in group 1) that takes
// request data or a variable assigned from it.
func argOnInput(call *regexp.Regexp, s []byte) bool {
	var tainted []string
	for _, m := range reTaintAssign.FindAllSubmatch(s, 20) {
		tainted = append(tainted, string(m[1]))
	}
	for _, m := range call.FindAllSubmatch(s, 50) {
		arg := m[1]
		if reInput.Match(arg) {
			return true
		}
		for _, name := range tainted {
			if regexp.MustCompile(`\$` + regexp.QuoteMeta(name) + `\b`).Match(arg) {
				return true
			}
		}
	}
	return false
}

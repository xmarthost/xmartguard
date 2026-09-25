package scanner

import (
	"math"
	"regexp"
)

// This file implements XMart Guard's own heuristic PHP/JS analyzer. It scores
// several independent signals (obfuscation, decoders, dangerous sinks, input
// flow) and flags a file only when the combination is characteristic of
// malware, keeping false positives on legitimate code low. All patterns are
// our own, written from the behaviour of common backdoor/webshell techniques.

var (
	reEvalSink     = regexp.MustCompile(`(?i)\b(?:eval|assert)\s*\(`)
	reCreateFunc   = regexp.MustCompile(`(?i)\bcreate_function\s*\(`)
	rePregE        = regexp.MustCompile(`(?i)\bpreg_replace(?:_callback)?\s*\(\s*['"][^'"]*['"]?[a-z]*e[a-z]*['"]`)
	reDecoder      = regexp.MustCompile(`(?i)\b(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|hex2bin|convert_uu(?:decode)?|urldecode|rawurldecode|bzdecompress|base_convert|pack)\s*\(`)
	reInput        = regexp.MustCompile(`\$_(?:POST|GET|REQUEST|COOKIE|SERVER|FILES)\b`)
	reSink         = regexp.MustCompile(`(?i)\b(?:system|shell_exec|passthru|proc_open|popen|pcntl_exec)\s*\(`)
	reExecBare     = regexp.MustCompile(`(?i)(?:[^_a-z]|^)exec\s*\(`)
	reVarFunc      = regexp.MustCompile(`\$(?:[a-zA-Z_]\w*|_(?:POST|GET|REQUEST|COOKIE|SERVER)\s*\[[^\]]+\])\s*\(`)
	reCallUserFunc = regexp.MustCompile(`(?i)\bcall_user_func(?:_array)?\s*\(`)
	reUploader     = regexp.MustCompile(`(?i)move_uploaded_file\s*\(`)
	reFilesName    = regexp.MustCompile(`\$_FILES\b`)
	reWriteSink    = regexp.MustCompile(`(?i)\b(?:file_put_contents|fwrite|fputs)\s*\(`)
	reGoto         = regexp.MustCompile(`(?i)\bgoto\s+[a-zA-Z_]\w*\s*;`)
	reHex          = regexp.MustCompile(`\\x[0-9A-Fa-f]{2}`)
	reOct          = regexp.MustCompile(`\\[0-3][0-7]{2}`)
	reChr          = regexp.MustCompile(`(?i)\bchr\s*\(`)
	reConcatChar   = regexp.MustCompile(`['"]\s*\.\s*['"]`)
	reLongB64      = regexp.MustCompile(`['"][A-Za-z0-9+/]{260,}={0,2}['"]`)
	reB64Blob      = regexp.MustCompile(`[A-Za-z0-9+/]{120,}={0,2}`)
	reHalt         = regexp.MustCompile(`(?i)__halt_compiler\s*\(\s*\)\s*;`)
	reGzUncompress = regexp.MustCompile(`(?i)\bgz(?:inflate|uncompress|decode)\s*\(`)
	reDynInclude   = regexp.MustCompile(`(?i)\b(?:include|require)(?:_once)?\s*\(?\s*\$`)
	reMailInput    = regexp.MustCompile(`(?i)\bmail\s*\(`)
	reGlobalsCall  = regexp.MustCompile(`\$GLOBALS\s*\[[^\]]+\]\s*(?:\[[^\]]+\]\s*)*\(`)
	reAssertVar    = regexp.MustCompile(`(?i)\bassert\s*\(\s*(?:@\s*)?\$`)
	reOrdChr       = regexp.MustCompile(`(?i)\b(?:ord|chr|pack|base_convert)\s*\(`)
	reStrReplace   = regexp.MustCompile(`(?i)\bstr_replace\s*\(`)
	reDefineArr    = regexp.MustCompile(`\$\w+\s*=\s*(?:array\s*\(|\[)\s*(?:['"\x60][^'"\x60]{0,4}['"\x60]\s*,\s*){12,}`)
	reEvalGz       = regexp.MustCompile(`(?i)\b(?:eval|assert|include|require|create_function|call_user_func|preg_replace)\b`)
	rePhpOpen      = regexp.MustCompile(`<\?(?:php|=)`)
	reWpNonce      = regexp.MustCompile(`(?i)wp_(?:nonce|verify_nonce|enqueue|register)`)
	// A backtick command substitution on a real code line (assignment, echo,
	// return or print) that embeds attacker input — not a docblock example.
	reBacktickExec = regexp.MustCompile("(?i)(?:=|echo|return|print|exec|system)\\s*`[^`]{0,200}\\$_(?:POST|GET|REQUEST|COOKIE)")
	// move_uploaded_file whose destination is the raw client-supplied filename.
	reUploadRaw = regexp.MustCompile(`(?is)move_uploaded_file\s*\([^;]{0,200}\$_FILES\s*\[[^\]]+\]\s*\[\s*['"]name['"]`)
	// Markers of a legitimate framework/library file.
	reNamespace = regexp.MustCompile(`(?m)^\s*namespace\s+[A-Za-z_\\]`)
	reClassDef  = regexp.MustCompile(`(?m)^\s*(?:abstract\s+|final\s+)?(?:class|interface|trait)\s+\w`)
	reFuncDef   = regexp.MustCompile(`(?i)\bfunction\s+\w+\s*\(`)
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
	s := content
	n := len(s)

	evalOrAssert := reEvalSink.Match(s)
	decoders := countMatches(reDecoder, s)
	hasInput := reInput.Match(s)
	longBlob := reLongB64.Match(s)
	hex := len(reHex.FindAllIndex(s, -1))
	oct := len(reOct.FindAllIndex(s, -1))
	chr := countMatches(reChr, s)
	concat := len(reConcatChar.FindAllIndex(s, -1))
	goto_ := countMatches(reGoto, s)
	varFunc := reVarFunc.Match(s)
	// A file with a namespace, or several functions plus a class/interface, and
	// little obfuscation, is almost certainly a legitimate library. The strong
	// input-flow rules below still apply to it; only the ambiguous
	// obfuscation-density rules consult this guard.
	library := reNamespace.Match(s) ||
		(countMatches(reFuncDef, s) >= 4 && reClassDef.Match(s) && !longBlob && goto_ < 4)

	// 1. preg_replace with the /e modifier (executes its replacement).
	if rePregE.Match(s) {
		return &verdict{CatVirus, "PHP.Backdoor.PregReplaceEval"}
	}
	// 2. create_function with attacker input.
	if reCreateFunc.Match(s) && hasInput {
		return &verdict{CatVirus, "PHP.Backdoor.CreateFunction"}
	}
	// 3. eval/assert of a decoded payload: a long encoded blob, or a decoder
	// chain right next to the executor.
	if evalOrAssert && decoders >= 1 && (longBlob || (decoders >= 2 && near(s, reEvalSink, reDecoder, 200))) && !library {
		return &verdict{CatVirus, "PHP.Obfuscated.EvalDecodedPayload"}
	}
	// 4. eval/assert directly on attacker input.
	if evalOrAssert && hasInput && near(s, reEvalSink, reInput, 120) {
		return &verdict{CatVirus, "PHP.Backdoor.EvalInput"}
	}
	// 5. Command execution driven by attacker input (incl. backticks).
	if (reSink.Match(s) || reExecBare.Match(s)) && hasInput && near(s, orRe(reSink, reExecBare), reInput, 200) {
		return &verdict{CatVirus, "PHP.Backdoor.CommandInjection"}
	}
	if reBacktickExec.Match(s) {
		return &verdict{CatVirus, "PHP.Backdoor.BacktickInput"}
	}
	// 6. Variable-function or call_user_func fed attacker input.
	if (varFunc || reCallUserFunc.Match(s)) && hasInput && near(s, orRe(reVarFunc, reCallUserFunc), reInput, 160) {
		return &verdict{CatVirus, "PHP.Backdoor.DynamicCall"}
	}
	// 7. goto-flattened obfuscation with an execution sink.
	if goto_ >= 8 && (evalOrAssert || decoders >= 1 || reSink.Match(s)) {
		return &verdict{CatVirus, "PHP.Obfuscated.GotoFlow"}
	}
	// 8. Heavy hex/octal/chr obfuscation building code.
	dens := float64(hex*4+oct*4+chr*4) / float64(max64(n, 1))
	if (hex+oct >= 40 || chr >= 40) && dens > 0.10 && (evalOrAssert || decoders >= 1 || varFunc) {
		return &verdict{CatVirus, "PHP.Obfuscated.CharEncoded"}
	}
	// 9. eval/assert after __halt_compiler (payload appended to the file).
	if reHalt.Match(s) && evalOrAssert {
		return &verdict{CatVirus, "PHP.Obfuscated.HaltCompilerPayload"}
	}
	// 10. Compressed payload include (gzinflate blob without eval, still executed).
	if reGzUncompress.Match(s) && longBlob && (evalOrAssert || reDynInclude.Match(s) || varFunc) {
		return &verdict{CatVirus, "PHP.Obfuscated.CompressedPayload"}
	}
	// 11. Uploader that saves the raw client-supplied filename (lets the
	// attacker choose the .php destination).
	if reUploadRaw.Match(s) && !reWpNonce.Match(s) {
		return &verdict{CatVirus, "PHP.Uploader.MoveUploadedFile"}
	}
	// 12. Drop-and-write shell: writes a file from attacker input.
	if reWriteSink.Match(s) && hasInput && (reChr.Match(s) || decoders >= 1) && near(s, reWriteSink, reInput, 200) {
		return &verdict{CatVirus, "PHP.Backdoor.FileDropper"}
	}
	// 13. Spam mailer: mail() fed attacker input, in a small standalone script
	// (not a mail library, which defines classes).
	if reMailInput.Match(s) && hasInput && near(s, reMailInput, reInput, 200) && !library && n < 60000 {
		return &verdict{CatSuspicious, "PHP.Spam.Mailer"}
	}

	// 14. $GLOBALS['x'][y](...) dynamic dispatch (very common in packed shells).
	if reGlobalsCall.Match(s) && (decoders >= 1 || evalOrAssert || hasInput) {
		return &verdict{CatVirus, "PHP.Backdoor.GlobalsDispatch"}
	}
	// 15. assert() on a variable expression built by the file.
	if reAssertVar.Match(s) && !library && (decoders >= 1 || chr >= 10 || concat >= 20 || goto_ >= 4) {
		return &verdict{CatVirus, "PHP.Backdoor.AssertVariable"}
	}
	// 16. Character-array decoder: builds code from ord/chr/pack next to an
	// executor. Excludes crypto/encoding libraries, which use ord/pack heavily.
	ordChr := countMatches(reOrdChr, s)
	if ordChr >= 25 && !library && (evalOrAssert || varFunc || reGlobalsCall.Match(s)) &&
		near(s, reOrdChr, orRe(reEvalSink, reVarFunc, reGlobalsCall), 400) {
		return &verdict{CatVirus, "PHP.Obfuscated.CharArrayDecoder"}
	}
	// 17. Large inline character/string array feeding an executor.
	if reDefineArr.Match(s) && reEvalGz.Match(s) {
		return &verdict{CatVirus, "PHP.Obfuscated.PackedArray"}
	}
	// 18. Minified single-line PHP with an executor (packed one-liner).
	if evalOrAssert && longestLine(s) > 2000 && n < 300000 && (decoders >= 1 || concat >= 15 || varFunc) {
		return &verdict{CatVirus, "PHP.Obfuscated.PackedOneLiner"}
	}
	// ---- weaker signals -> suspicious (report only) ----
	if longBlob && (decoders >= 1 || evalOrAssert) {
		return &verdict{CatSuspicious, "PHP.Suspicious.EncodedPayload"}
	}
	if concat >= 40 && (evalOrAssert || varFunc) {
		return &verdict{CatSuspicious, "PHP.Suspicious.ConcatObfuscation"}
	}
	if entropyOfLongestToken(s) > 5.4 && evalOrAssert && n < 200000 {
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
	if reJSMiner.Match(content) {
		return &verdict{CatVirus, "JS.Miner.Browser"}
	}
	if reJSHexArray.Match(content) && (reJSHexBlob.Match(content) || len(reLongB64.FindIndex(content)) > 0) {
		return &verdict{CatSuspicious, "JS.Obfuscated.EvalPacked"}
	}
	if reJSDocWrite.Match(content) {
		return &verdict{CatSuspicious, "JS.Injection.DocumentWriteUnescape"}
	}
	return nil
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

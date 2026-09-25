package scanner

import (
	"bytes"
	"regexp"
	"strings"
)

// Categories match the portal's scanner settings.
const (
	CatVirus      = "virus"
	CatSuspicious = "suspicious"
	CatBinary     = "binary"
)

// Rule is one content signature. Rules are XMart Guard's own, written from
// publicly documented webshell/backdoor techniques.
type Rule struct {
	ID       string
	Name     string
	Category string
	// Exts limits the rule to these lowercase extensions ("" = any scanned file).
	Exts []string
	re   *regexp.Regexp
	lit  []byte
}

func rx(id, name, cat, pattern string, exts ...string) Rule {
	return Rule{ID: id, Name: name, Category: cat, Exts: exts, re: regexp.MustCompile(pattern)}
}

func lit(id, name, cat, s string, exts ...string) Rule {
	return Rule{ID: id, Name: name, Category: cat, Exts: exts, lit: []byte(s)}
}

var phpExts = []string{".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".php8", ".phar", ".inc", ".pht", ".phps"}

// ScriptExts are files whose content is scanned.
var ScriptExts = map[string]bool{
	".php": true, ".phtml": true, ".php3": true, ".php4": true, ".php5": true, ".php7": true, ".php8": true,
	".phar": true, ".inc": true, ".pht": true, ".phps": true, ".js": true, ".html": true, ".htm": true,
	".pl": true, ".cgi": true, ".py": true, ".sh": true, ".asp": true, ".aspx": true, ".jsp": true,
	".ico": true, ".jpg": true, ".png": true, ".gif": true, ".txt": true, ".htaccess": true, ".suspected": true, "": true,
}

// eicar is the industry-standard antivirus test string.
const eicar = `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`

const input = `\$_(?:POST|GET|REQUEST|COOKIE|SERVER\[['"]HTTP_[A-Z_]+['"]\])`

// Rules is the built-in signature set, evaluated in order (first match wins).
var Rules = []Rule{
	lit("XG-TEST-EICAR", "EICAR-Test-Signature", CatVirus, eicar),

	// Direct execution of attacker-controlled input.
	rx("XG-PHP-EXEC-INPUT", "PHP.Backdoor.ExecInput", CatVirus,
		`(?i)\b(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(\s*(?:@\s*)?(?:stripslashes\s*\(\s*)?`+input, phpExts...),
	rx("XG-PHP-EVAL-INPUT", "PHP.Backdoor.EvalInput", CatVirus,
		`(?i)\b(?:eval|assert)\s*\(\s*(?:@\s*)?(?:stripslashes\s*\(\s*|base64_decode\s*\(\s*|str_rot13\s*\(\s*|urldecode\s*\(\s*)*`+input, phpExts...),
	rx("XG-PHP-VARFUNC-INPUT", "PHP.Backdoor.VariableFunction", CatVirus,
		`(?i)(?:@\s*)?`+input+`\s*\[\s*['"]?[\w-]+['"]?\s*\]\s*\(\s*(?:@\s*)?`+input, phpExts...),
	rx("XG-PHP-CREATEFUNC-INPUT", "PHP.Backdoor.CreateFunction", CatVirus,
		`(?i)create_function\s*\([^;]{0,200}`+input, phpExts...),
	rx("XG-PHP-PREGE", "PHP.Backdoor.PregReplaceEval", CatVirus,
		`(?i)preg_replace\s*\(\s*['"][/#~!|@%].{0,200}?[/#~!|@%][imsxuADSUX]*e[imsxuADSUX]*['"]\s*,[^;]{0,200}`+input, phpExts...),

	// Classic obfuscated loaders.
	rx("XG-PHP-EVAL-B64", "PHP.Obfuscated.EvalBase64", CatVirus,
		`(?i)\beval\s*\(\s*(?:@\s*)?(?:gzinflate|gzuncompress|gzdecode|str_rot13|strrev|base64_decode)\s*\(\s*(?:gzinflate|gzuncompress|gzdecode|str_rot13|strrev|base64_decode)?\s*\(?\s*['"][A-Za-z0-9+/=\s]{200,}`, phpExts...),
	rx("XG-PHP-EVAL-HEXNAME", "PHP.Obfuscated.HexEncodedEval", CatVirus,
		`(?i)(?:\\x65\\x76\\x61\\x6c|\\145\\166\\141\\154|chr\s*\(\s*101\s*\)\s*\.\s*chr\s*\(\s*118\s*\)\s*\.\s*chr\s*\(\s*97\s*\))`, phpExts...),
	rx("XG-PHP-GLOBALS-OBF", "PHP.Obfuscated.GlobalsArrayCall", CatSuspicious,
		`\$GLOBALS\s*\[\s*['"][^'"]{1,40}['"]\s*\]\s*\[\s*\d+\s*\]\s*\(\s*\$GLOBALS`, phpExts...),

	// Known webshell families (markers taken from their public source).
	rx("XG-SHELL-WSO", "PHP.Webshell.WSO", CatVirus, `(?i)(?:WSOsetcookie|wso_version|\$default_action\s*=\s*['"]FilesMan)`, phpExts...),
	rx("XG-SHELL-C99", "PHP.Webshell.C99", CatVirus, `(?i)(?:c99shell|c99_buff_prepare|c99sh_surl)`, phpExts...),
	rx("XG-SHELL-R57", "PHP.Webshell.R57", CatVirus, `(?i)(?:r57shell|r57_version)`, phpExts...),
	rx("XG-SHELL-B374K", "PHP.Webshell.B374k", CatVirus, `(?i)b374k\s*(?:shell|[0-9])`, phpExts...),
	rx("XG-SHELL-INDOXPLOIT", "PHP.Webshell.IndoXploit", CatVirus, `(?i)IndoXploit`, phpExts...),
	rx("XG-SHELL-ALFA", "PHP.Webshell.Alfa", CatVirus, `(?i)(?:ALFA_TEAM|alfacgiapi|AlfaTeam|Alfa_Shell)`, phpExts...),
	rx("XG-SHELL-MARIJUANA", "PHP.Webshell.Marijuana", CatVirus, `(?i)<title>\s*Marijuana`, phpExts...),
	rx("XG-SHELL-TINYUPLOADER", "PHP.Uploader.Minimal", CatVirus,
		`(?is)<\?php.{0,100}if\s*\(\s*isset\s*\(\s*\$_FILES.{0,300}move_uploaded_file\s*\(\s*\$_FILES\s*\[[^\]]+\]\s*\[\s*['"]tmp_name['"]\s*\]\s*,\s*\$_FILES\s*\[[^\]]+\]\s*\[\s*['"]name['"]\s*\]\s*\)`, phpExts...),

	// Mass-mailers and spam scripts.
	rx("XG-PHP-MAILER-INPUT", "PHP.Spam.Mailer", CatSuspicious,
		`(?i)\bmail\s*\(\s*`+input+`[^;]{0,200},\s*`+input, phpExts...),

	// Malicious JavaScript / miners.
	rx("XG-JS-MINER", "JS.Miner.Browser", CatVirus, `(?i)(?:coinhive\.min\.js|CoinHive\.Anonymous|cryptoloot\.pro|coin-hive\.com|webmine\.pro)`),
	rx("XG-JS-INJECT-DOCWRITE", "JS.Injection.UnescapeWrite", CatSuspicious,
		`(?i)document\.write\s*\(\s*unescape\s*\(\s*['"](?:%[0-9a-f]{2}){60,}`),
	rx("XG-JS-FROMCHARCODE-EVAL", "JS.Obfuscated.FromCharCodeEval", CatSuspicious,
		`(?i)eval\s*\(\s*String\.fromCharCode\s*\(\s*(?:\d+\s*,\s*){40,}`),

	// .htaccess abuse.
	rx("XG-HTACCESS-PHPHANDLER", "Htaccess.ExecuteImagesAsPHP", CatSuspicious,
		`(?i)AddType\s+application/x-httpd-php[0-9]*\s+[^\n]*\.(?:jpg|jpeg|png|gif|ico|txt)\b`, ".htaccess"),

	// Suspicious but common in legitimate code: report only.
	rx("XG-PHP-LONGB64", "PHP.Suspicious.LongEncodedPayload", CatSuspicious,
		`(?i)base64_decode\s*\(\s*['"][A-Za-z0-9+/=]{1000}[A-Za-z0-9+/=]{1000}[A-Za-z0-9+/=]{1000}[A-Za-z0-9+/=]{1000}['"]`, phpExts...),
}

// phpInImage flags PHP code hidden in image/text files.
var phpOpen = regexp.MustCompile(`<\?php\s`)

// Match returns the first matching rule for content with the given extension.
func Match(ext string, content []byte) *Rule {
	for i := range Rules {
		r := &Rules[i]
		if len(r.Exts) > 0 && !hasExt(r.Exts, ext) {
			continue
		}
		if r.lit != nil {
			if bytes.Contains(content, r.lit) {
				return r
			}
			continue
		}
		if r.re.Match(content) {
			return r
		}
	}
	switch ext {
	case ".jpg", ".png", ".gif", ".ico":
		if phpOpen.Match(content) {
			return &Rule{ID: "XG-PHP-IN-IMAGE", Name: "PHP.Suspicious.CodeInImage", Category: CatSuspicious}
		}
	}
	return nil
}

func hasExt(list []string, ext string) bool {
	for _, e := range list {
		if e == ext {
			return true
		}
	}
	return false
}

// IsELF reports whether the header is a Linux executable.
func IsELF(head []byte) bool { return len(head) >= 4 && string(head[:4]) == "\x7fELF" }

// extOf returns the lowercase extension; ".htaccess" is treated as its own ext.
func extOf(name string) string {
	base := strings.ToLower(name)
	if base == ".htaccess" {
		return ".htaccess"
	}
	if i := strings.LastIndexByte(base, '.'); i > 0 {
		return base[i:]
	}
	return ""
}

package scanner

import (
	"bytes"
	"path/filepath"
	"regexp"
	"strings"
)

// Data files the signatures misread (AI Learning reports): their content
// quotes attack strings or code, but nothing runs it.

// statsCacheDirs hold the web statistics programs' caches (Analog,
// AWStats, Webalizer): every URL attackers requested is in them.
var statsCacheDirs = []string{"/tmp/analog/", "/tmp/awstats/", "/tmp/webalizer/"}

// phpExt reports a PHP script extension.
func phpExt(ext string) bool {
	return strings.HasPrefix(ext, ".php") || ext == ".phtml" || ext == ".phar" || ext == ".pht" || ext == ".inc"
}

// dataFile reports a statistics cache (not a PHP file) or PsySH's offline
// PHP manual, which are never scanned for code.
func dataFile(path, ext string) bool {
	if !phpExt(ext) {
		for _, d := range statsCacheDirs {
			if strings.Contains(path, d) {
				return true
			}
		}
	}
	base := filepath.Base(path)
	return strings.Contains(path, "/.local/share/psysh/") && (base == "php_manual.php" || base == "php_manual.sqlite")
}

var (
	// WordPress 6.5+ translation files: "<?php return ['domain'=>…];".
	reL10nStart = regexp.MustCompile(`^\s*<\?php\s*(?:(?://|#)[^\n]*\n\s*|/\*[\s\S]*?\*/\s*)*return\s*(?:\[|array\s*\()`)
	reL10nCode  = regexp.MustCompile(`(?i)\b(?:eval|assert|base64_decode|gzinflate|gzuncompress|str_rot13|system|exec|shell_exec|passthru|popen|proc_open|create_function|include|require|file_put_contents|fopen|curl_exec)\s*\(|\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)|\$\w+\s*\(|` + "`")
)

// translationFile reports a WordPress PHP translation file (*.l10n.php in a
// languages folder) that only returns an array of strings.
func translationFile(path string, content []byte) bool {
	if !strings.HasSuffix(path, ".l10n.php") || !strings.Contains(path, "/languages/") || !reL10nStart.Match(content) {
		return false
	}
	t := bytes.TrimSpace(content)
	if !bytes.HasSuffix(t, []byte("];")) && !bytes.HasSuffix(t, []byte(");")) {
		return false
	}
	return bytes.Count(content, []byte("<?")) == 1 && !reL10nCode.Match(content)
}

package scanner

import (
	"bytes"
	"regexp"
	"strings"
)

// analyze runs the heuristic analyzers appropriate for the file extension.
func analyze(ext string, content []byte) *Detection {
	if ext == ".ini" || ext == ".htaccess" {
		if d := configLoader(content); d != nil {
			return d
		}
	}
	if d := markupInImage(ext, content); d != nil {
		if v := analyzePHP(content); v != nil {
			return codeInNonScript(ext, v, content)
		}
		return d
	}
	// A file without an extension is only a PHP script if it starts like one
	// (stats caches such as tmp/analog/cache hold logged attack URLs as text).
	if ext == "" && !startsLikeScript(content) {
		return nil
	}
	if d := phishingKit(ext, content); d != nil {
		return d
	}
	switch {
	case ext == ".js":
		if v := analyzeJS(content); v != nil {
			return &Detection{v.category, v.signature}
		}
	case ext == "", strings.HasPrefix(ext, ".php"), ext == ".phtml", ext == ".pht", ext == ".inc",
		ext == ".phps", ext == ".phar", ext == ".html", ext == ".htm", ext == ".suspected":
		if v := analyzePHP(content); v != nil {
			return &Detection{v.category, v.signature}
		}
	default:
		// Images/text/other extensions that smuggle PHP code.
		if v := analyzePHP(content); v != nil {
			return codeInNonScript(ext, v, content)
		}
		if d := scriptInImage(ext, content); d != nil {
			return d
		}
	}
	return nil
}

// codeInNonScript: PHP inside a non-script file. In an image, code the
// analyzer calls malicious (eval of input, shell commands, droppers) is a
// backdoor waiting to be included, so it is a virus; anything else stays
// suspicious (image polyglots, CTF samples).
func codeInNonScript(ext string, v *verdict, content []byte) *Detection {
	if imageExts[ext] && v.category == CatVirus {
		return &Detection{CatVirus, "Disguised.PHPInImage"}
	}
	// A whole PHP program under a data/style/media name: the analyzer's
	// malicious verdict stands (hidden loaders like crontrol-82.dat).
	if v.category == CatVirus && disguiseExts[ext] && bytes.HasPrefix(bytes.TrimLeft(content[:min(len(content), 256)], " \t\r\n\ufeff"), []byte("<?php")) {
		return &Detection{CatVirus, "Disguised.PHPFile"}
	}
	return &Detection{CatSuspicious, "PHP.Suspicious.CodeInNonScript"}
}

// disguiseExts are names a PHP program has no reason to carry.
var disguiseExts = map[string]bool{".dat": true, ".class": true, ".css": true, ".flv": true, ".haxor": true, ".tmp": true, ".txt": true, ".ico": true}

var reImgScript = regexp.MustCompile(`(?is)<script[^>]*>[^<]{0,1000}?(?:window\.location|document\.location|location\.(?:href|replace)|eval\s*\(|atob\s*\(|fromCharCode|document\.write)`)

// scriptInImage flags a real image that carries a script with a redirect
// or decoder (SEO spam and drive-by redirects appended to images).
func scriptInImage(ext string, content []byte) *Detection {
	if !imageExts[ext] || !bytes.Contains(bytes.ToLower(content), []byte("<script")) {
		return nil
	}
	if reImgScript.Match(content) {
		return &Detection{CatSuspicious, "Disguised.ScriptInImage"}
	}
	return nil
}

// AnalyzeScript runs the heuristic analyzer on content that is not a file
// (for example a database value). kind is "js" or "php".
func AnalyzeScript(kind string, content []byte) *Detection {
	var v *verdict
	if kind == "js" {
		v = analyzeJS(content)
	} else {
		v = analyzePHP(content)
	}
	if v == nil {
		return nil
	}
	return &Detection{v.category, v.signature}
}

func startsLikeScript(content []byte) bool {
	head := bytes.TrimLeft(content[:min(len(content), 256)], " \t\r\n\ufeff")
	return bytes.HasPrefix(head, []byte("<?")) || bytes.HasPrefix(head, []byte("#!"))
}

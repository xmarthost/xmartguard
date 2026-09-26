package scanner

import "strings"

// analyze runs the heuristic analyzers appropriate for the file extension.
func analyze(ext string, content []byte) *Detection {
	if ext == ".ini" || ext == ".htaccess" {
		if d := configLoader(content); d != nil {
			return d
		}
	}
	if d := markupInImage(ext, content); d != nil {
		if v := analyzePHP(content); v != nil {
			return &Detection{CatSuspicious, "PHP.Suspicious.CodeInNonScript"}
		}
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
			return &Detection{CatSuspicious, "PHP.Suspicious.CodeInNonScript"}
		}
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

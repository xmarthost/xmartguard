package scanner

import "strings"

// analyze runs the heuristic analyzers appropriate for the file extension.
func analyze(ext string, content []byte) *Detection {
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

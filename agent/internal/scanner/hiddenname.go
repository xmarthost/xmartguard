package scanner

import (
	"regexp"
	"strconv"
	"strings"
)

// A web shell that hides the name of the function it runs: the name is
// spelled in pieces or escapes ($f = "\x73\x79\x73\x74\x65\x6d" or
// $f = 'sys'.'tem'), then called with the request: $f($_GET['c']). The
// plain forms (system($_GET['c'])) are caught by the command and eval
// rules; these passed (server audit, 2026-11-05). A program that keeps a
// function's name in a variable writes it plainly; spelling it in pieces
// or escapes only hides it.

var (
	// $name = "literal" . 'literal' ...;
	reNameAssign = regexp.MustCompile(`\$([A-Za-z_]\w*)\s*=\s*((?:(?:"(?:[^"\\\n]|\\.)+"|'[^'\\\n]+')\s*\.?\s*)+)\s*;`)
	rePiece      = regexp.MustCompile(`"(?:[^"\\\n]|\\.)*"|'[^'\n]*'`)
	reEscape     = regexp.MustCompile(`\\(?:x[0-9A-Fa-f]{1,2}|[0-7]{1,3}|.)`)
	// Request data among a call's arguments.
	reRequestArg = regexp.MustCompile(`\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER\s*\[\s*['"]HTTP_)`)
)

// hiddenRunners are the functions such a shell hides.
var hiddenRunners = map[string]bool{"system": true, "exec": true, "shell_exec": true, "passthru": true,
	"popen": true, "proc_open": true, "pcntl_exec": true, "assert": true, "create_function": true}

// unescapePHP decodes a double-quoted PHP string's escapes.
func unescapePHP(s string) string {
	return reEscape.ReplaceAllStringFunc(s, func(e string) string {
		switch {
		case e[1] == 'x':
			if v, err := strconv.ParseUint(e[2:], 16, 8); err == nil {
				return string(rune(v))
			}
		case e[1] >= '0' && e[1] <= '7':
			if v, err := strconv.ParseUint(e[1:], 8, 8); err == nil {
				return string(rune(v))
			}
		}
		return e[1:]
	})
}

// disguisedNames are the variables holding a function name spelled in
// pieces or escapes, by variable name.
func disguisedNames(s []byte) map[string]string {
	out := map[string]string{}
	for _, m := range reNameAssign.FindAllSubmatchIndex(s, 50) {
		expr := string(s[m[4]:m[5]])
		if len(expr) > 400 {
			continue
		}
		pieces := rePiece.FindAllString(expr, -1)
		var name strings.Builder
		disguised := len(pieces) > 1
		for _, p := range pieces {
			body := p[1 : len(p)-1]
			if p[0] == '"' {
				if strings.Contains(body, `\`) {
					disguised = true
				}
				body = unescapePHP(body)
			}
			name.WriteString(body)
		}
		if disguised {
			out[string(s[m[2]:m[3]])] = strings.ToLower(strings.TrimSpace(name.String()))
		}
	}
	return out
}

// hiddenNameCall reports a variable holding a disguised command or code
// runner's name that is called with request data.
func hiddenNameCall(s []byte) bool {
	for _, m := range reNameAssign.FindAllSubmatchIndex(s, 50) {
		expr := string(s[m[4]:m[5]])
		if len(expr) > 400 {
			continue
		}
		pieces := rePiece.FindAllString(expr, -1)
		var name strings.Builder
		disguised := len(pieces) > 1
		for _, p := range pieces {
			body := p[1 : len(p)-1]
			if p[0] == '"' {
				if strings.Contains(body, `\`) {
					disguised = true
				}
				body = unescapePHP(body)
			}
			name.WriteString(body)
		}
		if !disguised || !hiddenRunners[strings.ToLower(strings.TrimSpace(name.String()))] {
			continue
		}
		v := regexp.QuoteMeta(string(s[m[2]:m[3]]))
		call := regexp.MustCompile(`\$` + v + `\s*\(([^;]{0,300})`)
		for _, c := range call.FindAllSubmatch(s[m[1]:], 20) {
			if reRequestArg.Match(c[1]) {
				return true
			}
		}
	}
	return false
}

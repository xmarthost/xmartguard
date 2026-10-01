package scanner

import (
	"bytes"
	"regexp"
	"regexp/syntax"
	"strings"
	"sync"
	"unicode/utf8"
)

// Go's regexp engine is slow on large inputs, and most patterns cannot match
// most files. Each pattern's required literals (one of them must occur in any
// match) are derived from its syntax tree; a plain substring search on the
// lowercased file rules the pattern out before the regexp runs. The check
// can only skip patterns that cannot match, so results are unchanged.

var prefilters sync.Map // *regexp.Regexp -> [][]byte (nil: always run)

// minLit is the shortest literal worth checking.
const minLit = 3

// lowerASCII returns a lowercased copy of b (ASCII letters only).
func lowerASCII(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return out
}

// may reports whether re can match the file whose lowercased content is low.
func may(re *regexp.Regexp, low []byte) bool {
	if q := quickChecks[re]; q != nil && !q(low) {
		return false
	}
	lits := literalsOf(re)
	if lits == nil {
		return true
	}
	for _, l := range lits {
		if bytes.Contains(low, l) {
			return true
		}
	}
	return false
}

func literalsOf(re *regexp.Regexp) [][]byte {
	if v, ok := prefilters.Load(re); ok {
		return v.([][]byte)
	}
	var out [][]byte
	if tree, err := syntax.Parse(re.String(), syntax.Perl); err == nil {
		if set, ok := required(tree.Simplify()); ok {
			for _, s := range set {
				out = append(out, []byte(s))
			}
		}
	}
	prefilters.Store(re, out)
	return out
}

// quickChecks are hand-written necessary conditions for patterns without a
// useful literal: a cheap pass over the file that is false only when the
// pattern cannot match.
var quickChecks map[*regexp.Regexp]func(low []byte) bool

func init() {
	quickChecks = map[*regexp.Regexp]func([]byte) bool{
		reLongB64:    func(b []byte) bool { return b64Run(b, 260) },
		reB64Blob:    func(b []byte) bool { return b64Run(b, 120) },
		reFuncTable:  numberedCall,
		reJSHexArray: evalCall,
		reStrPieces:  quotedJoins,
	}
	for i := range Rules {
		if Rules[i].ID == "XG-JS-FROMCHARCODE-EVAL" {
			quickChecks[Rules[i].re] = evalCall
		}
	}
}

// evalCall reports "eval" followed by "(" (spaces allowed).
func evalCall(b []byte) bool {
	for off := 0; ; {
		i := bytes.Index(b[off:], []byte("eval"))
		if i < 0 {
			return false
		}
		k := off + i + 4
		for k < len(b) && isSpace(b[k]) {
			k++
		}
		if k < len(b) && b[k] == '(' {
			return true
		}
		off += i + 4
	}
}

// quotedJoins reports at least two quote-dot-quote joins ('a'.'b'.'c'),
// which reStrPieces needs.
func quotedJoins(b []byte) bool {
	n := 0
	for off := 0; ; {
		i := bytes.IndexByte(b[off:], '.')
		if i < 0 {
			return false
		}
		i += off
		off = i + 1
		j := i - 1
		for j >= 0 && isSpace(b[j]) {
			j--
		}
		k := i + 1
		for k < len(b) && isSpace(b[k]) {
			k++
		}
		if j >= 0 && k < len(b) && (b[j] == '\'' || b[j] == '"') && (b[k] == '\'' || b[k] == '"') {
			if n++; n >= 2 {
				return true
			}
		}
	}
}

// b64Run reports a run of at least n base64 characters.
func b64Run(b []byte, n int) bool {
	run := 0
	for _, c := range b {
		if ('a' <= c && c <= 'z') || ('0' <= c && c <= '9') || c == '+' || c == '/' || ('A' <= c && c <= 'Z') {
			if run++; run >= n {
				return true
			}
		} else {
			run = 0
		}
	}
	return false
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v'
}

// numberedCall reports "( 12 ) (" somewhere: the shape reFuncTable needs
// after its function name.
func numberedCall(b []byte) bool {
	for off := 0; ; {
		i := bytes.IndexByte(b[off:], ')')
		if i < 0 {
			return false
		}
		i += off
		off = i + 1
		k := i + 1
		for k < len(b) && isSpace(b[k]) {
			k++
		}
		if k >= len(b) || b[k] != '(' {
			continue
		}
		j := i - 1
		for j >= 0 && isSpace(b[j]) {
			j--
		}
		d := 0
		for j >= 0 && b[j] >= '0' && b[j] <= '9' {
			j--
			d++
		}
		if d == 0 {
			continue
		}
		for j >= 0 && isSpace(b[j]) {
			j--
		}
		if j >= 0 && b[j] == '(' {
			return true
		}
	}
}

// required returns literals of which every match contains at least one
// (lowercased), or ok=false when no useful set exists.
func required(re *syntax.Regexp) (set []string, ok bool) {
	switch re.Op {
	case syntax.OpLiteral:
		s := string(re.Rune)
		// Non-ASCII case folding (e.g. the Kelvin sign) is not modelled.
		for _, r := range re.Rune {
			if r >= utf8.RuneSelf {
				return nil, false
			}
		}
		if len(s) < minLit {
			return nil, false
		}
		return []string{strings.ToLower(s)}, true
	case syntax.OpCapture, syntax.OpPlus:
		return required(re.Sub[0])
	case syntax.OpRepeat:
		if re.Min >= 1 {
			return required(re.Sub[0])
		}
		return nil, false
	case syntax.OpConcat:
		// Adjacent literals form one longer required literal.
		var best []string
		var run []rune
		consider := func(s []string) {
			if s != nil && score(s) > score(best) {
				best = s
			}
		}
		flush := func() {
			if len(run) >= minLit {
				ascii := true
				for _, r := range run {
					if r >= utf8.RuneSelf {
						ascii = false
					}
				}
				if ascii {
					consider([]string{strings.ToLower(string(run))})
				}
			}
			run = nil
		}
		for _, sub := range re.Sub {
			if sub.Op == syntax.OpLiteral {
				run = append(run, sub.Rune...)
				continue
			}
			// A literal before a choice of literals: "$_" then POST|GET
			// requires "$_post" or "$_get", far rarer than "get" alone.
			if alts := literalAlts(sub); len(run) > 0 && alts != nil {
				joined := make([]string, len(alts))
				for i, a := range alts {
					joined[i] = string(run) + a
				}
				if set, ok := asciiSet(joined); ok {
					consider(set)
				}
			}
			flush()
			if s, ok := required(sub); ok {
				consider(s)
			}
		}
		flush()
		return best, best != nil
	case syntax.OpAlternate:
		var all []string
		for _, sub := range re.Sub {
			s, ok := required(sub)
			if !ok {
				return nil, false
			}
			all = append(all, s...)
		}
		if len(all) > 32 {
			return nil, false
		}
		return all, true
	}
	return nil, false
}

// literalAlts returns the choices of an alternation of plain literals.
func literalAlts(re *syntax.Regexp) []string {
	if re.Op == syntax.OpCapture {
		re = re.Sub[0]
	}
	if re.Op != syntax.OpAlternate || len(re.Sub) > 32 {
		return nil
	}
	out := make([]string, 0, len(re.Sub))
	for _, sub := range re.Sub {
		if sub.Op != syntax.OpLiteral {
			return nil
		}
		out = append(out, string(sub.Rune))
	}
	return out
}

// asciiSet lowercases literals of at least minLit ASCII characters.
func asciiSet(lits []string) ([]string, bool) {
	out := make([]string, len(lits))
	for i, l := range lits {
		if len(l) < minLit {
			return nil, false
		}
		for _, r := range l {
			if r >= utf8.RuneSelf {
				return nil, false
			}
		}
		out[i] = strings.ToLower(l)
	}
	return out, true
}

// score prefers sets whose shortest literal is longest.
func score(set []string) int {
	if len(set) == 0 {
		return 0
	}
	m := len(set[0])
	for _, s := range set[1:] {
		if len(s) < m {
			m = len(s)
		}
	}
	return m*64 - len(set)
}

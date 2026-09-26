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

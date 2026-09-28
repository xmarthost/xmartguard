// Package clamdb reads ClamAV-format signature databases (.cvd/.cld
// archives, .hdb/.hsb hash lists, .ndb body signatures, .ldb logical
// signatures) and matches them inside the agent process. No clamd or
// clamscan process is started: scans stay one process in the server's
// process list.
//
// Supported: the signature features used for scripts and web files
// (targets any/HTML/ASCII, wildcards, nibbles, alternatives, gaps, logical
// expressions with counts, case-insensitive subsignatures, PCRE subsigs that
// Go's regexp accepts). Signatures for executables (PE sections, entry
// points, bytecode) are skipped: the scanner only reads web content.
package clamdb

import (
	"bytes"
	"errors"
	"sort"
	"strconv"
	"strings"
)

// elem is one fixed-length position of a segment.
type elem struct {
	val, mask byte   // literal/nibble/any: b&mask == val
	alts      []byte // single-byte alternatives (nil = use val/mask)
	neg       bool   // !(..): none of alts
}

func (e elem) match(b byte) bool {
	if e.alts != nil {
		hit := bytes.IndexByte(e.alts, b) >= 0
		return hit != e.neg
	}
	return b&e.mask == e.val
}

// segment is a fixed-length run between variable gaps.
type segment struct {
	elems []elem
	// multi-byte alternatives are expanded into several patterns by the
	// compiler, so a segment is always fixed length.
	anchor    []byte // longest literal run
	anchorOff int    // its offset in the segment
}

func (s *segment) at(b []byte, pos int) bool {
	if pos < 0 || pos+len(s.elems) > len(b) {
		return false
	}
	for i, e := range s.elems {
		if !e.match(b[pos+i]) {
			return false
		}
	}
	return true
}

// gap between segments: min..max bytes (max < 0: unbounded).
type gap struct{ min, max int }

// pattern is a compiled hex signature.
type pattern struct {
	segs []segment
	gaps []gap // len(segs)-1
	// Offset: -1 any; >=0 absolute start; eof >0: must start at len-eof.
	off, eof int
	maxShift int
	// key is the segment whose anchor indexes the pattern: the longest
	// literal of the whole signature, so common tokens ("<?php", "eval(")
	// do not wake thousands of signatures on every file.
	key int
}

// anchor returns the indexed literal.
func (p *pattern) anchor() []byte { return p.segs[p.key].anchor }

var errUnsupported = errors.New("unsupported signature feature")

// compileHex parses a ClamAV hex signature. Multi-byte alternatives of
// equal length are expanded (up to a limit) into alternate patterns.
func compileHex(sig string) ([]*pattern, error) {
	sig = strings.TrimSpace(sig)
	if sig == "" || len(sig) > 8192 {
		return nil, errUnsupported
	}
	variants := []string{sig}
	// Expand multi-byte (aa bb|cc dd) groups: "(6162|6364)".
	for n := 0; n < 4; n++ {
		var next []string
		expanded := false
		for _, v := range variants {
			i, j, alts, ok := findMultiAlt(v)
			if !ok {
				next = append(next, v)
				continue
			}
			expanded = true
			for _, a := range alts {
				next = append(next, v[:i]+a+v[j:])
			}
		}
		variants = next
		if !expanded {
			break
		}
		if len(variants) > 16 {
			return nil, errUnsupported
		}
	}
	var out []*pattern
	for _, v := range variants {
		p, err := parseHex(v)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// findMultiAlt finds the first "(..|..)" group whose options are longer than
// one byte; it returns the group's bounds and the options.
func findMultiAlt(s string) (int, int, []string, bool) {
	for i := 0; i < len(s); i++ {
		if s[i] != '(' {
			continue
		}
		if i > 0 && s[i-1] == '!' {
			continue
		}
		j := strings.IndexByte(s[i:], ')')
		if j < 0 {
			return 0, 0, nil, false
		}
		body := s[i+1 : i+j]
		if body == "B" || body == "L" || strings.ContainsAny(body, "{}*[]") {
			continue
		}
		opts := strings.Split(body, "|")
		multi := false
		for _, o := range opts {
			if len(o) > 2 {
				multi = true
			}
		}
		if multi {
			return i, i + j + 1, opts, true
		}
	}
	return 0, 0, nil, false
}

func hexNibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

func parseHex(s string) (*pattern, error) {
	p := &pattern{off: -1}
	cur := segment{}
	flush := func(g gap) error {
		if len(cur.elems) == 0 {
			// A gap at the very start (or two gaps in a row) is merged.
			if len(p.segs) == 0 {
				return nil
			}
			last := &p.gaps[len(p.gaps)-1]
			last.min += g.min
			if last.max >= 0 && g.max >= 0 {
				last.max += g.max
			} else {
				last.max = -1
			}
			return nil
		}
		p.segs = append(p.segs, cur)
		p.gaps = append(p.gaps, g)
		cur = segment{}
		return nil
	}
	i := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == '*':
			_ = flush(gap{0, -1})
			i++
		case c == '{':
			j := strings.IndexByte(s[i:], '}')
			if j < 0 {
				return nil, errUnsupported
			}
			g, err := parseRange(s[i+1 : i+j])
			if err != nil {
				return nil, err
			}
			if g.min == g.max && g.min <= 256 && len(cur.elems) > 0 {
				// Fixed gap inside a segment: wildcards.
				for k := 0; k < g.min; k++ {
					cur.elems = append(cur.elems, elem{mask: 0})
				}
			} else {
				_ = flush(g)
			}
			i += j + 1
		case c == '[':
			j := strings.IndexByte(s[i:], ']')
			if j < 0 {
				return nil, errUnsupported
			}
			g, err := parseRange(s[i+1 : i+j])
			if err != nil || g.max < 0 {
				return nil, errUnsupported
			}
			_ = flush(g)
			i += j + 1
		case c == '(' || (c == '!' && i+1 < len(s) && s[i+1] == '('):
			neg := c == '!'
			if neg {
				i++
			}
			j := strings.IndexByte(s[i:], ')')
			if j < 0 {
				return nil, errUnsupported
			}
			body := s[i+1 : i+j]
			i += j + 1
			if body == "B" || body == "L" {
				continue // word/line boundary markers: not enforced
			}
			var alts []byte
			for _, o := range strings.Split(body, "|") {
				if len(o) != 2 {
					return nil, errUnsupported
				}
				hi, ok1 := hexNibble(o[0])
				lo, ok2 := hexNibble(o[1])
				if !ok1 || !ok2 {
					return nil, errUnsupported
				}
				alts = append(alts, hi<<4|lo)
			}
			cur.elems = append(cur.elems, elem{alts: alts, neg: neg})
		default:
			if i+1 >= len(s) {
				return nil, errUnsupported
			}
			a, b := s[i], s[i+1]
			i += 2
			switch {
			case a == '?' && b == '?':
				cur.elems = append(cur.elems, elem{mask: 0})
			case a == '?':
				lo, ok := hexNibble(b)
				if !ok {
					return nil, errUnsupported
				}
				cur.elems = append(cur.elems, elem{val: lo, mask: 0x0f})
			case b == '?':
				hi, ok := hexNibble(a)
				if !ok {
					return nil, errUnsupported
				}
				cur.elems = append(cur.elems, elem{val: hi << 4, mask: 0xf0})
			default:
				hi, ok1 := hexNibble(a)
				lo, ok2 := hexNibble(b)
				if !ok1 || !ok2 {
					return nil, errUnsupported
				}
				cur.elems = append(cur.elems, elem{val: hi<<4 | lo, mask: 0xff})
			}
		}
	}
	if len(cur.elems) > 0 {
		p.segs = append(p.segs, cur)
	} else if len(p.gaps) > 0 {
		p.gaps = p.gaps[:len(p.gaps)-1] // trailing gap
	}
	if len(p.segs) == 0 {
		return nil, errUnsupported
	}
	p.pickKey()
	if len(p.anchor()) < 2 {
		return nil, errUnsupported // no usable anchor (ClamAV needs 2 static bytes too)
	}
	return p, nil
}

func parseRange(r string) (gap, error) {
	r = strings.TrimSpace(r)
	switch {
	case strings.HasPrefix(r, "-"):
		n, err := strconv.Atoi(r[1:])
		return gap{0, n}, err
	case strings.HasSuffix(r, "-"):
		n, err := strconv.Atoi(r[:len(r)-1])
		return gap{n, -1}, err
	case strings.Contains(r, "-"):
		a, b, _ := strings.Cut(r, "-")
		x, err1 := strconv.Atoi(a)
		y, err2 := strconv.Atoi(b)
		if err1 != nil || err2 != nil || y < x {
			return gap{}, errUnsupported
		}
		return gap{x, y}, nil
	default:
		n, err := strconv.Atoi(r)
		return gap{n, n}, err
	}
}

// pickKey sets every segment's anchor and chooses the indexed segment.
func (p *pattern) pickKey() {
	p.key = 0
	for k := range p.segs {
		setAnchor(&p.segs[k])
		if len(p.segs[k].anchor) > len(p.segs[p.key].anchor) {
			p.key = k
		}
	}
}

// setAnchor picks the longest literal run of a segment.
func setAnchor(s *segment) {
	best, bestOff, run, runOff := 0, 0, 0, 0
	for i, e := range s.elems {
		if e.alts == nil && e.mask == 0xff {
			if run == 0 {
				runOff = i
			}
			run++
			if run > best {
				best, bestOff = run, runOff
			}
		} else {
			run = 0
		}
	}
	s.anchor = make([]byte, best)
	for k := 0; k < best; k++ {
		s.anchor[k] = s.elems[bestOff+k].val
	}
	s.anchorOff = bestOff
}

// budget bounds the work one pattern may do on one file.
const budget = 20000

// occFunc returns the sorted start positions of segment k in the content
// (only for segments with an anchor; nil otherwise).
type occFunc func(k int) []int

// maxWindow bounds scanning of a gap in front of a segment without anchor.
const maxWindow = 4096

// fwd checks the segments after k (segment k verified at pos).
func (p *pattern) fwd(b []byte, occ occFunc, k, pos int, steps *int) bool {
	*steps++
	if *steps > budget {
		return false
	}
	if k == len(p.segs)-1 {
		return true
	}
	g := p.gaps[k]
	next := &p.segs[k+1]
	lo := pos + len(p.segs[k].elems) + g.min
	hi := len(b) - len(next.elems)
	if g.max >= 0 && pos+len(p.segs[k].elems)+g.max < hi {
		hi = pos + len(p.segs[k].elems) + g.max
	}
	if lo > hi {
		return false
	}
	if list := occ(k + 1); list != nil || len(next.anchor) >= 2 {
		for i := sort.SearchInts(list, lo); i < len(list) && list[i] <= hi; i++ {
			if p.fwd(b, occ, k+1, list[i], steps) {
				return true
			}
			if *steps > budget {
				return false
			}
		}
		return false
	}
	if hi-lo > maxWindow {
		hi = lo + maxWindow
	}
	for q := lo; q <= hi; q++ {
		if next.at(b, q) && p.fwd(b, occ, k+1, q, steps) {
			return true
		}
		if *steps > budget {
			return false
		}
	}
	return false
}

// startOK checks the offset rules on the match start.
func (p *pattern) startOK(b []byte, start int) bool {
	if p.off >= 0 && (start < p.off || start > p.off+p.maxShift) {
		return false
	}
	if p.eof > 0 && start != len(b)-p.eof {
		return false
	}
	return true
}

// back checks segments j..0 before nextStart (segment j+1 starts there).
func (p *pattern) back(b []byte, occ occFunc, j, nextStart int, steps *int) bool {
	*steps++
	if *steps > budget {
		return false
	}
	if j < 0 {
		return p.startOK(b, nextStart)
	}
	seg := &p.segs[j]
	g := p.gaps[j]
	n := len(seg.elems)
	hi := nextStart - g.min - n // latest start
	lo := 0
	if g.max >= 0 {
		lo = nextStart - g.max - n
	}
	if lo < 0 {
		lo = 0
	}
	if hi < lo {
		return false
	}
	if list := occ(j); list != nil || len(seg.anchor) >= 2 {
		for i := sort.SearchInts(list, hi+1) - 1; i >= 0 && list[i] >= lo; i-- {
			if p.back(b, occ, j-1, list[i], steps) {
				return true
			}
			if *steps > budget {
				return false
			}
		}
		return false
	}
	if hi-lo > maxWindow {
		lo = hi - maxWindow
	}
	for q := hi; q >= lo; q-- {
		if seg.at(b, q) && p.back(b, occ, j-1, q, steps) {
			return true
		}
		if *steps > budget {
			return false
		}
	}
	return false
}

// matches counts matches (by start of the segment with fewest
// occurrences, capped at limit).
func (p *pattern) matches(b []byte, occ occFunc, limit int) int {
	k, best := -1, -1
	for i := range p.segs {
		if len(p.segs[i].anchor) < 2 {
			continue
		}
		if n := len(occ(i)); best < 0 || n < best {
			k, best = i, n
		}
	}
	if k < 0 || best == 0 {
		return 0
	}
	n, steps := 0, 0
	for _, pos := range occ(k) {
		if k == 0 && !p.startOK(b, pos) {
			continue
		}
		if p.fwd(b, occ, k, pos, &steps) && (k == 0 || p.back(b, occ, k-1, pos, &steps)) {
			n++
			if n >= limit {
				break
			}
		}
		if steps > budget {
			break
		}
		steps = 0
	}
	return n
}

// segOcc finds where a segment occurs (starts), capped.
func segOcc(b []byte, s *segment, limit int) []int {
	var out []int
	if len(s.anchor) < 2 {
		return nil
	}
	for from := 0; from < len(b) && len(out) < limit; {
		i := bytes.Index(b[from:], s.anchor)
		if i < 0 {
			break
		}
		st := from + i - s.anchorOff
		if s.at(b, st) {
			out = append(out, st)
		}
		from += i + 1
	}
	return out
}

// count matches the pattern on its own (tests and small uses).
func (p *pattern) count(b []byte, limit int) int {
	cache := map[int][]int{}
	occ := func(k int) []int {
		if v, ok := cache[k]; ok {
			return v
		}
		v := segOcc(b, &p.segs[k], 4096)
		if v == nil && len(p.segs[k].anchor) >= 2 {
			v = []int{}
		}
		cache[k] = v
		return v
	}
	return p.matches(b, occ, limit)
}

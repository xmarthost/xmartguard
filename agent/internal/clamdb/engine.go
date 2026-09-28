package clamdb

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"regexp"
	"strconv"
	"strings"
)

// Content views signatures run on.
const (
	viewRaw   = 0 // file bytes (target 0)
	viewLower = 1 // lowercased (case-insensitive subsignatures)
	viewNorm  = 2 // lowercased, whitespace collapsed (targets 3 HTML and 7 ASCII)
	nViews    = 3
)

// upat is one unique compiled pattern with everything that uses it:
// signatures sharing a subsignature (e.g. "eval(") match it once per file.
type upat struct {
	p      *pattern
	view   int
	segIDs []int // unique segment id per segment (-1: no anchor)
	ndbs   []int // body signatures (first hit wins)
	uses   []use // logical signature subsigs (counted)
}

type use struct{ ldb, sub int }

// useg is a unique anchored segment; its occurrences are found once per
// file and shared by every pattern containing it.
type useg struct {
	seg  *segment
	pats []int // upat ids
}

// index finds segment occurrences by the first bytes of their anchor.
type index struct {
	long  map[uint32][]int // anchors of 4+ bytes (key: first 4) -> useg ids
	short map[uint16][]int // anchors of 2-3 bytes
	bloom []uint64         // quick filter over long keys
}

func newIndex() *index {
	return &index{long: map[uint32][]int{}, short: map[uint16][]int{}, bloom: make([]uint64, 1<<14)}
}

func bloomBit(k uint32) (int, uint64) {
	h := k * 2654435761
	h >>= 12 // 20 bits
	return int(h >> 6), 1 << (h & 63)
}

func (x *index) add(id int, a []byte) {
	if len(a) >= 4 {
		k := binary.LittleEndian.Uint32(a)
		x.long[k] = append(x.long[k], id)
		w, bit := bloomBit(k)
		x.bloom[w] |= bit
		return
	}
	k := uint16(a[0]) | uint16(a[1])<<8
	x.short[k] = append(x.short[k], id)
}

func (x *index) empty() bool { return len(x.long) == 0 && len(x.short) == 0 }

type ndbSig struct {
	name string
}

// ldbSig is a logical signature.
type ldbSig struct {
	name  string
	expr  *node
	nsubs int
	subs  [][]int   // unique pattern ids per hex subsig
	pcre  []pcreSub // PCRE subsigs
}

type pcreSub struct {
	idx     int
	re      *regexp.Regexp
	trigger *node
}

// Engine holds loaded signatures.
type Engine struct {
	idx    [nViews]*index
	upats  []*upat
	usegs  []*useg
	reg    map[string][]int // view|offset|hex -> unique pattern ids
	segReg map[string]int   // view|segment bytes -> unique segment id
	ndb    []ndbSig
	ldb    []ldbSig
	hash   map[string]string // "md5:<hex>" / "sha1:" / "sha256:" -> name
	// sizes having hash signatures (-1 = any size)
	sizes map[int64]bool
	fp    map[string]bool // known-good hashes (.fp/.sfp)
	ign   map[string]bool // ignored signature names (.ign/.ign2)

	Stats Stats
}

// Stats describes what was loaded.
type Stats struct {
	Hashes    int      `json:"hashes"`
	Body      int      `json:"body"`
	Logical   int      `json:"logical"`
	Skipped   int      `json:"skipped"`
	Databases []string `json:"databases"`
}

func newEngine() *Engine {
	e := &Engine{hash: map[string]string{}, sizes: map[int64]bool{}, fp: map[string]bool{}, ign: map[string]bool{}, reg: map[string][]int{}, segReg: map[string]int{}}
	for i := range e.idx {
		e.idx[i] = newIndex()
	}
	return e
}

// Empty reports an engine without signatures.
func (e *Engine) Empty() bool {
	return e == nil || (len(e.hash) == 0 && len(e.ndb) == 0 && len(e.ldb) == 0)
}

// ---- logical expressions

type node struct {
	op   byte // 'l' leaf, '&', '|'
	leaf int
	kids []*node
	mod  byte // 0, '=', '>', '<'
	x, y int
	hasY bool
}

type exprParser struct {
	s   string
	pos int
	max int
}

func parseExpr(s string, nsubs int) (*node, error) {
	p := &exprParser{s: strings.ReplaceAll(s, " ", ""), max: nsubs}
	n, err := p.or()
	if err != nil {
		return nil, err
	}
	if p.pos != len(p.s) {
		return nil, errUnsupported
	}
	return n, nil
}

func (p *exprParser) or() (*node, error) {
	l, err := p.and()
	if err != nil {
		return nil, err
	}
	kids := []*node{l}
	for p.pos < len(p.s) && p.s[p.pos] == '|' {
		p.pos++
		r, err := p.and()
		if err != nil {
			return nil, err
		}
		kids = append(kids, r)
	}
	if len(kids) == 1 {
		return l, nil
	}
	return &node{op: '|', kids: kids}, nil
}

func (p *exprParser) and() (*node, error) {
	l, err := p.term()
	if err != nil {
		return nil, err
	}
	kids := []*node{l}
	for p.pos < len(p.s) && p.s[p.pos] == '&' {
		p.pos++
		r, err := p.term()
		if err != nil {
			return nil, err
		}
		kids = append(kids, r)
	}
	if len(kids) == 1 {
		return l, nil
	}
	return &node{op: '&', kids: kids}, nil
}

func (p *exprParser) num() (int, bool) {
	st := p.pos
	for p.pos < len(p.s) && p.s[p.pos] >= '0' && p.s[p.pos] <= '9' {
		p.pos++
	}
	if st == p.pos {
		return 0, false
	}
	n, err := strconv.Atoi(p.s[st:p.pos])
	return n, err == nil
}

func (p *exprParser) term() (*node, error) {
	var n *node
	if p.pos < len(p.s) && p.s[p.pos] == '(' {
		p.pos++
		inner, err := p.or()
		if err != nil {
			return nil, err
		}
		if p.pos >= len(p.s) || p.s[p.pos] != ')' {
			return nil, errUnsupported
		}
		p.pos++
		// Wrap so a modifier applies to the group, not its last child.
		n = &node{op: '|', kids: []*node{inner}}
		if inner.op == '|' {
			n = inner
		}
	} else {
		v, ok := p.num()
		if !ok || v >= p.max {
			return nil, errUnsupported
		}
		n = &node{op: 'l', leaf: v}
	}
	if p.pos < len(p.s) && strings.IndexByte("=><", p.s[p.pos]) >= 0 {
		n.mod = p.s[p.pos]
		p.pos++
		x, ok := p.num()
		if !ok {
			return nil, errUnsupported
		}
		n.x = x
		if p.pos < len(p.s) && p.s[p.pos] == ',' {
			p.pos++
			y, ok := p.num()
			if !ok {
				return nil, errUnsupported
			}
			n.y, n.hasY = y, true
		}
	}
	return n, nil
}

// eval returns (count, unique subsigs matched).
func (n *node) eval(counts []int) (int, int) {
	var v, u int
	switch n.op {
	case 'l':
		v = counts[n.leaf]
		if v > 0 {
			u = 1
		}
	case '|':
		for _, k := range n.kids {
			a, b := k.eval(counts)
			v += a
			u += b
		}
	case '&':
		v = 1
		for _, k := range n.kids {
			a, b := k.eval(counts)
			if a == 0 {
				v = 0
			}
			u += b
		}
	}
	if n.mod == 0 {
		return v, u
	}
	ok := false
	switch n.mod {
	case '=':
		ok = v == n.x
	case '>':
		ok = v > n.x
	case '<':
		ok = v > 0 && v < n.x
	}
	if ok && n.hasY {
		ok = u >= n.y
	}
	if ok {
		return 1, 1
	}
	return 0, 0
}

// ---- scanning

func normalize(b []byte) []byte {
	out := make([]byte, 0, len(b))
	space := false
	for _, c := range b {
		switch c {
		case ' ', '\t', '\r', '\n', '\f', '\v':
			if !space {
				out = append(out, ' ')
			}
			space = true
			continue
		}
		space = false
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		out = append(out, c)
	}
	return out
}

func lower(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		out[i] = c
	}
	return out
}

// hashHit checks the hash signatures (and the known-good list).
func (e *Engine) hashHit(b []byte) (name string, knownGood bool) {
	size := int64(len(b))
	if !e.sizes[size] && !e.sizes[-1] && len(e.fp) == 0 {
		return "", false
	}
	m, s1, s2 := md5.Sum(b), sha1.Sum(b), sha256.Sum256(b)
	keys := []string{"md5:" + hex.EncodeToString(m[:]), "sha1:" + hex.EncodeToString(s1[:]), "sha256:" + hex.EncodeToString(s2[:])}
	for _, k := range keys {
		if e.fp[k] {
			return "", true
		}
	}
	for _, k := range keys {
		for _, sz := range []string{strconv.FormatInt(size, 10), "*"} {
			if n, ok := e.hash[k+":"+sz]; ok {
				return n, false
			}
		}
	}
	return "", false
}

// register returns the unique pattern ids for a compiled subsignature.
func (e *Engine) register(key string, view int, pats []*pattern) []int {
	if ids, ok := e.reg[key]; ok {
		return ids
	}
	ids := make([]int, 0, len(pats))
	for _, p := range pats {
		id := len(e.upats)
		u := &upat{p: p, view: view, segIDs: make([]int, len(p.segs))}
		for k := range p.segs {
			u.segIDs[k] = e.segID(view, &p.segs[k], id)
		}
		e.upats = append(e.upats, u)
		ids = append(ids, id)
	}
	e.reg[key] = ids
	return ids
}

func segKey(view int, s *segment) string {
	var sb strings.Builder
	sb.WriteByte(byte('0' + view))
	for _, e := range s.elems {
		if e.alts != nil {
			sb.WriteByte('(')
			if e.neg {
				sb.WriteByte('!')
			}
			sb.Write(e.alts)
			sb.WriteByte(')')
			continue
		}
		sb.WriteByte(e.val)
		sb.WriteByte(e.mask)
	}
	return sb.String()
}

// segID registers an anchored segment (-1 when it has no anchor).
func (e *Engine) segID(view int, s *segment, patID int) int {
	if len(s.anchor) < 2 {
		return -1
	}
	k := segKey(view, s)
	id, ok := e.segReg[k]
	if !ok {
		id = len(e.usegs)
		e.usegs = append(e.usegs, &useg{seg: s})
		e.segReg[k] = id
		e.idx[view].add(id, s.anchor)
	}
	u := e.usegs[id]
	if n := len(u.pats); n == 0 || u.pats[n-1] != patID {
		u.pats = append(u.pats, patID)
	}
	return id
}

// Scan returns the name of the first signature matching the content ("" = clean).
func (e *Engine) Scan(b []byte) string {
	if e.Empty() || len(b) == 0 {
		return ""
	}
	name, good := e.hashHit(b)
	if good {
		return ""
	}
	if name != "" {
		return name
	}
	counts := map[int]int{} // unique pattern id -> matches
	views := [nViews][]byte{b, nil, nil}
	for v := 0; v < nViews; v++ {
		x := e.idx[v]
		if x.empty() {
			continue
		}
		if views[v] == nil {
			if v == viewLower {
				views[v] = lower(b)
			} else {
				views[v] = normalize(b)
			}
		}
		if hit := e.scanView(x, views[v], counts); hit != "" {
			return hit
		}
	}
	if len(counts) == 0 {
		return ""
	}
	// Logical signatures with at least one subsig hit.
	touched := map[int]bool{}
	for u := range counts {
		for _, us := range e.upats[u].uses {
			touched[us.ldb] = true
		}
	}
	for li := range touched {
		l := &e.ldb[li]
		c := make([]int, l.nsubs)
		for i, ids := range l.subs {
			for _, id := range ids {
				c[i] += counts[id]
			}
		}
		for _, pc := range l.pcre {
			if pc.trigger != nil {
				if v, _ := pc.trigger.eval(c); v == 0 {
					continue
				}
			}
			c[pc.idx] = len(pc.re.FindAllIndex(b, 64))
		}
		if v, _ := l.expr.eval(c); v > 0 {
			return l.name
		}
	}
	return ""
}

// scanView finds segment occurrences, then checks the patterns whose
// anchored segments all occur.
func (e *Engine) scanView(x *index, b []byte, counts map[int]int) string {
	const occCap = 4096
	occ := map[int][]int{}
	record := func(id, pos int) {
		sg := e.usegs[id].seg
		a := sg.anchor
		if pos+len(a) > len(b) || !bytes.Equal(b[pos:pos+len(a)], a) {
			return
		}
		st := pos - sg.anchorOff
		if st < 0 || !sg.at(b, st) {
			return
		}
		l := occ[id]
		if len(l) < occCap && (len(l) == 0 || l[len(l)-1] != st) {
			occ[id] = append(l, st)
		}
	}
	hasShort := len(x.short) > 0
	for i := 0; i+1 < len(b); i++ {
		if i+3 < len(b) {
			k := binary.LittleEndian.Uint32(b[i:])
			w, bit := bloomBit(k)
			if x.bloom[w]&bit != 0 {
				for _, id := range x.long[k] {
					record(id, i)
				}
			}
		}
		if hasShort {
			for _, id := range x.short[uint16(b[i])|uint16(b[i+1])<<8] {
				record(id, i)
			}
		}
	}
	if len(occ) == 0 {
		return ""
	}
	tried := map[int]bool{}
	for sid := range occ {
		for _, pid := range e.usegs[sid].pats {
			if tried[pid] {
				continue
			}
			tried[pid] = true
			u := e.upats[pid]
			complete := true
			for _, id := range u.segIDs {
				if id >= 0 && len(occ[id]) == 0 {
					complete = false
					break
				}
			}
			if !complete {
				continue
			}
			of := func(k int) []int {
				if id := u.segIDs[k]; id >= 0 {
					return occ[id]
				}
				return nil
			}
			if len(u.ndbs) > 0 {
				if u.p.matches(b, of, 1) > 0 {
					return e.ndb[u.ndbs[0]].name
				}
				continue
			}
			if n := u.p.matches(b, of, 1000); n > 0 {
				counts[pid] += n
			}
		}
	}
	return ""
}

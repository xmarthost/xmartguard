package clamdb

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// LocalDirs are where ClamAV keeps its databases (cPanel's ClamAV plugin,
// distribution packages). Databases found there are used as they are:
// freshclam keeps them current.
var LocalDirs = []string{
	"/var/lib/clamav",
	"/usr/local/cpanel/3rdparty/share/clamav",
	"/usr/share/clamav",
	"/var/clamav",
}

// webPrefixes limit the official ClamAV databases (main/daily) to
// signatures for scripts and web content; the rest target Windows
// executables, documents and mail, which the scanner never reads.
var webPrefixes = []string{"php.", "html.", "js.", "txt.", "unix.", "multios.", "perl.", "python.", "py.", "asp.",
	"java.", "vbs.", "win.exploit.cve", "heuristics.phishing"}

// MaxSignatures caps memory use.
var MaxSignatures = 400000

func official(base string) bool {
	b := strings.ToLower(base)
	return strings.HasPrefix(b, "main.") || strings.HasPrefix(b, "daily.") || strings.HasPrefix(b, "bytecode.")
}

func webName(name string) bool {
	n := strings.ToLower(name)
	for _, p := range webPrefixes {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	return false
}

type loader struct {
	e *Engine
	// unofficial adds ".UNOFFICIAL" to names like ClamAV does for
	// third-party databases.
	unofficial bool
	filter     bool
	full       bool
}

func (l *loader) name(n string) string {
	if l.unofficial && !strings.HasSuffix(n, ".UNOFFICIAL") {
		return n + ".UNOFFICIAL"
	}
	return n
}

func (l *loader) count() int { return l.e.Stats.Hashes + l.e.Stats.Body + l.e.Stats.Logical }

func (l *loader) keep(name string) bool {
	if l.count() >= MaxSignatures {
		l.full = true
		return false
	}
	if l.e.ign[name] {
		return false
	}
	return !l.filter || webName(name)
}

// line loads one signature line of a database with the given extension.
func (l *loader) line(ext, s string) {
	s = strings.TrimRight(s, "\r")
	if s == "" || s[0] == '#' {
		return
	}
	switch ext {
	case ".hdb", ".hsb", ".fp", ".sfp":
		f := strings.Split(s, ":")
		if len(f) < 3 {
			return
		}
		h := strings.ToLower(f[0])
		kind := map[int]string{32: "md5", 40: "sha1", 64: "sha256"}[len(h)]
		if kind == "" {
			return
		}
		if _, err := strconv.ParseInt(f[1], 10, 64); err != nil && f[1] != "*" {
			return
		}
		if ext == ".fp" || ext == ".sfp" {
			l.e.fp[kind+":"+h] = true
			return
		}
		if !l.keep(f[2]) {
			return
		}
		l.e.hash[kind+":"+h+":"+f[1]] = l.name(f[2])
		if f[1] == "*" {
			l.e.sizes[-1] = true
		} else {
			n, _ := strconv.ParseInt(f[1], 10, 64)
			l.e.sizes[n] = true
		}
		l.e.Stats.Hashes++
	case ".ign", ".ign2":
		f := strings.Split(s, ":")
		n := f[0]
		if ext == ".ign" && len(f) >= 3 {
			n = f[2]
		}
		l.e.ign[strings.TrimSpace(n)] = true
	case ".ndb":
		l.ndb(s)
	case ".ldb":
		l.ldb(s)
	}
}

func targetView(t string) (int, bool) {
	switch strings.TrimSpace(t) {
	case "0", "":
		return viewRaw, true
	case "3", "7":
		return viewNorm, true
	}
	return 0, false
}

// parseOffset handles "*", "n", "n,shift" and "EOF-n".
func parseOffset(p *pattern, off string) bool {
	off = strings.TrimSpace(off)
	switch {
	case off == "*" || off == "":
		return true
	case strings.HasPrefix(off, "EOF-"):
		n, err := strconv.Atoi(off[4:])
		if err != nil || n <= 0 {
			return false
		}
		p.eof = n
		return true
	default:
		a, b, hasShift := strings.Cut(off, ",")
		n, err := strconv.Atoi(a)
		if err != nil {
			return false // EP+, Sx+, SE, VI: executables only
		}
		p.off = n
		if hasShift {
			m, err := strconv.Atoi(b)
			if err != nil {
				return false
			}
			p.maxShift = m
		}
		return true
	}
}

func (l *loader) ndb(s string) {
	f := strings.Split(s, ":")
	if len(f) < 4 {
		return
	}
	name, target, off, sig := f[0], f[1], f[2], f[3]
	view, ok := targetView(target)
	if !ok || !l.keep(name) {
		return
	}
	pats, err := compileHex(sig)
	if err != nil {
		l.e.Stats.Skipped++
		return
	}
	for _, p := range pats {
		if !parseOffset(p, off) {
			l.e.Stats.Skipped++
			return
		}
	}
	if view == viewNorm {
		lowerPatterns(pats)
	}
	id := len(l.e.ndb)
	l.e.ndb = append(l.e.ndb, ndbSig{name: l.name(name)})
	for _, u := range l.e.register(strconv.Itoa(view)+"|"+off+"|"+sig, view, pats) {
		l.e.upats[u].ndbs = append(l.e.upats[u].ndbs, id)
	}
	l.e.Stats.Body++
}

// lowerPatterns lowercases literal letters (views that are lowercased).
func lowerPatterns(pats []*pattern) {
	for _, p := range pats {
		for k := range p.segs {
			for i, e := range p.segs[k].elems {
				if e.alts == nil && e.mask == 0xff && e.val >= 'A' && e.val <= 'Z' {
					p.segs[k].elems[i].val += 32
				}
				for j, a := range e.alts {
					if a >= 'A' && a <= 'Z' {
						p.segs[k].elems[i].alts[j] = a + 32
					}
				}
			}
		}
		p.pickKey()
	}
}

func (l *loader) ldb(s string) {
	f := strings.Split(s, ";")
	if len(f) < 4 {
		return
	}
	name, tdb, logic, subs := f[0], f[1], f[2], f[3:]
	if !l.keep(name) {
		return
	}
	view := viewRaw
	for _, kv := range strings.Split(tdb, ",") {
		k, v, _ := strings.Cut(kv, ":")
		switch k {
		case "Target":
			vv, ok := targetView(v)
			if !ok {
				return
			}
			view = vv
		case "Container", "IconGroup1", "IconGroup2", "NumberOfSections", "HandlerType", "Intermediates":
			return // executables and archives only
		}
	}
	expr, err := parseExpr(logic, len(subs))
	if err != nil {
		l.e.Stats.Skipped++
		return
	}
	sig := ldbSig{name: l.name(name), expr: expr, nsubs: len(subs), pcre: make([]pcreSub, 0)}
	type pending struct {
		key  string
		pats []*pattern
		view int
		sub  int
	}
	var refs []pending
	anyHex := false
	for i, sub := range subs {
		if strings.Contains(sub, "/") {
			pc, ok := parsePCRE(sub, len(subs))
			if !ok {
				l.e.Stats.Skipped++
				return
			}
			pc.idx = i
			sig.pcre = append(sig.pcre, pc)
			continue
		}
		mods := ""
		if a, b, ok := strings.Cut(sub, "::"); ok {
			sub, mods = a, b
		}
		if strings.Contains(mods, "w") || strings.HasPrefix(sub, "${") || strings.Contains(sub, "(>>") || strings.Contains(sub, "(<<") {
			l.e.Stats.Skipped++
			return
		}
		off := "*"
		if a, b, ok := strings.Cut(sub, ":"); ok {
			off, sub = a, b
		}
		pats, err := compileHex(sub)
		if err != nil {
			l.e.Stats.Skipped++
			return
		}
		v := view
		if strings.Contains(mods, "i") && v == viewRaw {
			v = viewLower
		}
		if v != viewRaw {
			lowerPatterns(pats)
		}
		for _, p := range pats {
			if !parseOffset(p, off) {
				l.e.Stats.Skipped++
				return
			}
		}
		refs = append(refs, pending{strconv.Itoa(v) + "|" + off + "|" + sub, pats, v, i})
		anyHex = true
	}
	if !anyHex {
		// A logical signature needs a static anchor to be looked at
		// (PCRE-only signatures would run on every file).
		l.e.Stats.Skipped++
		return
	}
	id := len(l.e.ldb)
	sig.subs = make([][]int, len(subs))
	for _, r := range refs {
		ids := l.e.register(r.key, r.view, r.pats)
		sig.subs[r.sub] = ids
		for _, u := range ids {
			l.e.upats[u].uses = append(l.e.upats[u].uses, use{ldb: id, sub: r.sub})
		}
	}
	l.e.ldb = append(l.e.ldb, sig)
	l.e.Stats.Logical++
}

// parsePCRE reads "[Offset:]Trigger/regex/flags".
func parsePCRE(sub string, nsubs int) (pcreSub, bool) {
	first := strings.IndexByte(sub, '/')
	last := strings.LastIndexByte(sub, '/')
	if first < 0 || last <= first {
		return pcreSub{}, false
	}
	trig, re, flags := sub[:first], sub[first+1:last], sub[last+1:]
	if i := strings.LastIndexByte(trig, ':'); i >= 0 {
		trig = trig[i+1:] // offsets on PCRE subsigs are not enforced
	}
	var t *node
	if trig != "" {
		n, err := parseExpr(trig, nsubs)
		if err != nil {
			return pcreSub{}, false
		}
		t = n
	}
	pre := "(?s)"
	for _, f := range flags {
		switch f {
		case 'i':
			pre += "(?i)"
		case 'm':
			pre += "(?m)"
		case 's', 'x', 'g', 'r', 'e', 'E', 'U', 'A':
		default:
			return pcreSub{}, false
		}
	}
	r, err := regexp.Compile(pre + re)
	if err != nil {
		return pcreSub{}, false // back-references and look-arounds are not supported by RE2
	}
	return pcreSub{re: r, trigger: t}, true
}

// readDB loads a plain database file (.hdb, .ndb, .ldb, ...).
func (l *loader) readDB(ext string, r io.Reader) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 4<<20)
	for sc.Scan() {
		l.line(ext, sc.Text())
		if l.full {
			return
		}
	}
}

var dbExts = map[string]bool{".hdb": true, ".hsb": true, ".ndb": true, ".ldb": true, ".fp": true, ".sfp": true, ".ign": true, ".ign2": true}

// readArchive loads a .cvd/.cld: a 512-byte header, then a (gzipped) tar.
func (l *loader) readArchive(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	head := make([]byte, 512)
	if _, err := io.ReadFull(f, head); err != nil {
		return err
	}
	if !bytes.HasPrefix(head, []byte("ClamAV-VDB")) {
		return errors.New("not a ClamAV database")
	}
	br := bufio.NewReader(f)
	var r io.Reader = br
	if m, _ := br.Peek(2); len(m) == 2 && m[0] == 0x1f && m[1] == 0x8b {
		gz, err := gzip.NewReader(br)
		if err != nil {
			return err
		}
		defer gz.Close()
		r = gz
	}
	tr := tar.NewReader(r)
	// Ignore lists first would be nicer, but the archive order is fixed;
	// names ignored later are removed after loading (see prune).
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		ext := strings.ToLower(filepath.Ext(h.Name))
		if dbExts[ext] {
			l.readDB(ext, tr)
		}
		if l.full {
			return nil
		}
	}
}

// Source is one database to load.
type Source struct {
	Path string
	// Unofficial databases (third-party subscriptions) are not filtered and
	// get ".UNOFFICIAL" appended to their names.
	Unofficial bool
}

// FindLocal lists the ClamAV databases installed on the server.
func FindLocal(dirs []string) []Source {
	var out []Source
	for _, d := range dirs {
		ents, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		names := map[string]bool{}
		for _, e := range ents {
			names[e.Name()] = true
		}
		for _, e := range ents {
			n := e.Name()
			ext := strings.ToLower(filepath.Ext(n))
			base := strings.TrimSuffix(n, filepath.Ext(n))
			switch {
			case ext == ".cvd" && names[base+".cld"]:
				continue // the .cld is the current one
			case ext == ".cvd" || ext == ".cld" || dbExts[ext]:
				out = append(out, Source{Path: filepath.Join(d, n), Unofficial: !official(n)})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// Load builds an engine from the given databases.
func Load(srcs []Source) *Engine {
	e := newEngine()
	// Ignore lists and known-good lists first so they apply to every file.
	sorted := append([]Source(nil), srcs...)
	sort.SliceStable(sorted, func(i, j int) bool {
		pi := strings.HasSuffix(sorted[i].Path, ".ign2") || strings.HasSuffix(sorted[i].Path, ".ign") || strings.HasSuffix(sorted[i].Path, ".fp")
		pj := strings.HasSuffix(sorted[j].Path, ".ign2") || strings.HasSuffix(sorted[j].Path, ".ign") || strings.HasSuffix(sorted[j].Path, ".fp")
		return pi && !pj
	})
	for _, s := range sorted {
		l := &loader{e: e, unofficial: s.Unofficial, filter: !s.Unofficial && official(filepath.Base(s.Path))}
		ext := strings.ToLower(filepath.Ext(s.Path))
		switch {
		case ext == ".cvd" || ext == ".cld":
			if err := l.readArchive(s.Path); err != nil {
				continue
			}
		case dbExts[ext]:
			f, err := os.Open(s.Path)
			if err != nil {
				continue
			}
			l.readDB(ext, f)
			f.Close()
		default:
			continue
		}
		e.Stats.Databases = append(e.Stats.Databases, s.Path)
		if l.full {
			break
		}
	}
	return e
}

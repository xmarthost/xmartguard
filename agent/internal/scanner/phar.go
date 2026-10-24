package scanner

import (
	"bytes"
	"compress/bzip2"
	"compress/flate"
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"path"
)

// PHP archives (.phar: Composer, WP-CLI, PHPUnit) bundle whole libraries
// behind a small stub. Judged as one file, the libraries' own eval and
// exec matched heuristics (composer.phar in a home folder: "PHP.
// Obfuscated.HaltCompilerPayload"). A well-formed phar is judged like a
// zip: its stub (the only part PHP runs on its own) and every script in it,
// each on its own. One that does not parse is judged as before.

// pharMember is a script stored in a phar (or its stub, name "").
type pharMember struct {
	name    string
	content []byte
}

// pharMembers parses a phar in the PHP format and returns its stub and its
// scripts; ok is false when content is not a well-formed phar.
func pharMembers(content []byte) (members []pharMember, ok bool) {
	lower := bytes.ToLower(content)
	i := bytes.Index(lower, []byte("__halt_compiler();"))
	if i < 0 {
		return nil, false
	}
	stub := content[:i]
	p := i + len("__halt_compiler();")
	if bytes.HasPrefix(content[p:], []byte(" ?>")) {
		p += 3
	}
	if bytes.HasPrefix(content[p:], []byte("\r\n")) {
		p += 2
	} else if bytes.HasPrefix(content[p:], []byte("\n")) {
		p++
	}
	r := &pharReader{b: content, p: p}
	manifestLen := int(r.u32())
	start := r.p
	count := int(r.u32())
	r.skip(2)            // API version
	r.skip(4)            // global flags
	r.skip(int(r.u32())) // alias
	r.skip(int(r.u32())) // metadata
	if r.bad || count > maxZipEntries || start+manifestLen > len(content) {
		return nil, false
	}
	type entry struct {
		name             string
		size, compressed int
		flags            uint32
	}
	entries := make([]entry, 0, count)
	for range count {
		var e entry
		e.name = string(r.bytes(int(r.u32())))
		e.size = int(r.u32())
		r.skip(4) // timestamp
		e.compressed = int(r.u32())
		r.skip(4) // CRC32
		e.flags = r.u32()
		r.skip(int(r.u32())) // metadata
		if r.bad {
			return nil, false
		}
		entries = append(entries, e)
	}
	if r.p != start+manifestLen {
		return nil, false
	}
	members = []pharMember{{"", stub}}
	data, total := r.p, 0
	for _, e := range entries {
		if e.compressed < 0 || data+e.compressed > len(content) {
			return nil, false
		}
		raw := content[data : data+e.compressed]
		data += e.compressed
		if !ScriptExts[extOf(path.Base(e.name))] || e.size == 0 || e.size > maxZipMember || total >= maxZipTotal {
			continue
		}
		var src io.Reader
		switch {
		case e.flags&0x1000 != 0:
			src = flate.NewReader(bytes.NewReader(raw))
		case e.flags&0x2000 != 0:
			src = bzip2.NewReader(bytes.NewReader(raw))
		default:
			src = bytes.NewReader(raw)
		}
		b, err := io.ReadAll(io.LimitReader(src, maxZipMember+1))
		if err != nil || len(b) != e.size {
			return nil, false
		}
		total += len(b)
		members = append(members, pharMember{e.name, b})
	}
	return members, true
}

// scanPhar judges a well-formed phar by its stub and scripts (handled =
// false: not one, judge the file as a whole).
func scanPhar(content []byte) (d *Detection, handled bool) {
	members, ok := pharMembers(content)
	if !ok {
		return nil, false
	}
	for _, m := range members {
		ext := extOf(path.Base(m.name))
		if m.name == "" {
			ext = ".php"
		}
		if hdb := activeHashDB(); hdb.SizeKnown(int64(len(m.content))) {
			if label := hdb.LookupSums(int64(len(m.content)), func() (string, string) { return sumsOf(m.content) }); label != "" {
				return &Detection{CatVirus, "Archive." + label}, true
			}
		}
		if inTestsDir(m.name) {
			continue
		}
		if d := analyze(ext, m.content); d != nil && d.Category == CatVirus {
			return &Detection{CatVirus, "Archive." + d.Signature}, true
		}
		if r := Match(ext, m.content); r != nil && r.Category == CatVirus {
			return &Detection{CatVirus, "Archive." + r.Name}, true
		}
		if d := clamCheck(m.content); d != nil && d.Category == CatVirus {
			return &Detection{CatVirus, "Archive." + d.Signature}, true
		}
	}
	return nil, true
}

type pharReader struct {
	b   []byte
	p   int
	bad bool
}

func (r *pharReader) bytes(n int) []byte {
	if r.bad || n < 0 || r.p+n > len(r.b) {
		r.bad = true
		return nil
	}
	out := r.b[r.p : r.p+n]
	r.p += n
	return out
}

func (r *pharReader) skip(n int) { r.bytes(n) }

func (r *pharReader) u32() uint32 {
	b := r.bytes(4)
	if b == nil {
		return 0
	}
	return binary.LittleEndian.Uint32(b)
}

func sumsOf(b []byte) (string, string) {
	h, m := sha256.Sum256(b), md5.Sum(b)
	return hex.EncodeToString(h[:]), hex.EncodeToString(m[:])
}

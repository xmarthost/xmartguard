package wpcore

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"
)

// The official checksums of many plugin versions stay small in memory (a
// hosting server checks thousands of plugin versions; the map of maps took
// gigabytes), and still tell an official file from a changed one.
func TestPluginChecksumsCompact(t *testing.T) {
	const files = 3000
	var b strings.Builder
	b.WriteString(`{"files":{`)
	for i := 0; i < files; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		s := md5.Sum([]byte(fmt.Sprint("file", i)))
		fmt.Fprintf(&b, `"includes/module-%d/class-feature-%d.php":{"md5":"%s"}`, i, i, hex.EncodeToString(s[:]))
	}
	b.WriteString(`,"readme.txt":{"md5":["` + strings.Repeat("a", 32) + `","` + strings.Repeat("B", 32) + `"]}}}`)
	doc := []byte(b.String())

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	p := &Plugins{}
	for v := 0; v < 200; v++ {
		f, err := parsePluginChecksums(doc)
		if err != nil {
			t.Fatal(err)
		}
		p.store(fmt.Sprintf("big@1.%d", v), f, time.Time{})
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	// 200 versions x 3002 files: about 5 MB as hashes (the old maps: ~200 MB).
	if grown := int64(after.HeapAlloc) - int64(before.HeapAlloc); grown > 20<<20 {
		t.Errorf("200 plugin versions hold %d MB", grown>>20)
	}
	f := p.sums["big@1.7"].files
	ok := md5.Sum([]byte("file42"))
	var a, bb [16]byte
	hex.Decode(a[:], []byte(strings.Repeat("a", 32)))
	hex.Decode(bb[:], []byte(strings.Repeat("b", 32)))
	if !f.has("includes/module-42/class-feature-42.php", ok) || !f.has("readme.txt", a) || !f.has("readme.txt", bb) {
		t.Fatal("official file not recognised")
	}
	if f.has("includes/module-43/class-feature-43.php", ok) || f.has("includes/module-42/class-feature-42.php", a) {
		t.Fatal("changed or moved file taken as official")
	}
	// The budget: past it the cache starts again.
	if p.entries > maxSumEntries {
		t.Fatalf("%d entries held", p.entries)
	}
}

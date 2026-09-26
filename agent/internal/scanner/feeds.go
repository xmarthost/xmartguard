package scanner

import (
	"bufio"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	"github.com/xmarthost/xmartguard/agent/internal/config"
	"github.com/xmarthost/xmartguard/agent/internal/store"
)

// Public malware signatures (Linux Malware Detect hex patterns, YARA rule
// files) received from the portal. MD5 signatures go into the hash DB.

// FeedHexPath holds LMD hex patterns ("hex name" per line).
func FeedHexPath() string { return store.StateDir() + "/sigs/feed-hex.txt" }

// FeedYARADir holds YARA rule files from public feeds.
func FeedYARADir() string { return filepath.Join(config.Dir(), "yara", "feeds") }

// matcher finds any of many byte patterns in one pass (Aho-Corasick).
type matcher struct {
	next  []map[byte]int32
	fail  []int32
	out   []int32 // pattern index ending here (-1 = none), via fail links
	names []string
}

func newMatcher(patterns [][]byte, names []string) *matcher {
	m := &matcher{next: []map[byte]int32{{}}, fail: []int32{0}, out: []int32{-1}, names: names}
	for pi, p := range patterns {
		if len(p) == 0 {
			continue
		}
		cur := int32(0)
		for _, c := range p {
			nx, ok := m.next[cur][c]
			if !ok {
				nx = int32(len(m.next))
				m.next = append(m.next, map[byte]int32{})
				m.fail = append(m.fail, 0)
				m.out = append(m.out, -1)
				m.next[cur][c] = nx
			}
			cur = nx
		}
		if m.out[cur] < 0 {
			m.out[cur] = int32(pi)
		}
	}
	queue := []int32{}
	for _, s := range m.next[0] {
		queue = append(queue, s)
	}
	for len(queue) > 0 {
		r := queue[0]
		queue = queue[1:]
		for c, s := range m.next[r] {
			queue = append(queue, s)
			f := m.fail[r]
			for {
				if t, ok := m.next[f][c]; ok && t != s {
					m.fail[s] = t
					break
				}
				if f == 0 {
					m.fail[s] = 0
					break
				}
				f = m.fail[f]
			}
			if m.out[s] < 0 {
				m.out[s] = m.out[m.fail[s]]
			}
		}
	}
	return m
}

// Match returns the name of the first pattern found in b, or "".
func (m *matcher) Match(b []byte) string {
	if m == nil || len(m.next) <= 1 {
		return ""
	}
	cur := int32(0)
	for _, c := range b {
		for {
			if nx, ok := m.next[cur][c]; ok {
				cur = nx
				break
			}
			if cur == 0 {
				break
			}
			cur = m.fail[cur]
		}
		if o := m.out[cur]; o >= 0 {
			return m.names[o]
		}
	}
	return ""
}

type feedMatcher struct{ p atomic.Pointer[matcher] }

func (f *feedMatcher) Match(b []byte) string { return f.p.Load().Match(b) }

var feedPatterns = func() *feedMatcher {
	f := &feedMatcher{}
	f.p.Store(loadFeedHex())
	return f
}()

func loadFeedHex() *matcher {
	fh, err := os.Open(FeedHexPath())
	if err != nil {
		return nil
	}
	defer fh.Close()
	var pats [][]byte
	var names []string
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		h, name, ok := strings.Cut(strings.TrimSpace(sc.Text()), " ")
		if !ok {
			continue
		}
		b, err := hex.DecodeString(h)
		if err != nil || len(b) < 16 {
			continue
		}
		pats = append(pats, b)
		names = append(names, name)
	}
	return newMatcher(pats, names)
}

// ReloadFeeds re-reads feed hashes and patterns after an update.
func ReloadFeeds() {
	feedPatterns.p.Store(loadFeedHex())
	ReloadHashDB()
}

// FeedCounts reports loaded feed signatures (patterns).
func FeedCounts() int {
	m := feedPatterns.p.Load()
	if m == nil {
		return 0
	}
	return len(m.names)
}

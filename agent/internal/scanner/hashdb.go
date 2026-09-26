package scanner

import (
	"bufio"
	_ "embed"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/xmarthost/xmartguard/agent/internal/store"
)

// baselineHashes is XMart Guard's own SHA-256 blocklist of known-malicious
// files, shipped with the agent. It is our own data, keyed by file size so a
// scan only hashes a file whose size matches a known-bad entry.
//
//go:embed sigdata/hashes.txt
var baselineHashes string

type hashEntry struct {
	sha, label string
}

// HashDB is a size-indexed known-bad hash set.
type HashDB struct {
	mu     sync.RWMutex
	bySize map[int64][]hashEntry
	count  int
}

// current is swapped atomically when signatures are updated during scans.
var current atomic.Pointer[HashDB]

func init() { current.Store(loadHashDB()) }

func activeHashDB() *HashDB { return current.Load() }

// HashDBPath is where the portal can push signature updates.
func HashDBPath() string { return store.StateDir() + "/sigs/hashes.txt" }

// LearnedHashPath lists files the AI scanner of any linked server found
// malicious (the fleet's shared knowledge, synced from the portal).
func LearnedHashPath() string { return store.StateDir() + "/sigs/learned.txt" }

// LearnedLabel is the signature name of fleet-learned detections.
const LearnedLabel = "XG.AI.Learned"

func loadHashDB() *HashDB {
	db := &HashDB{bySize: map[int64][]hashEntry{}}
	db.merge(baselineHashes)
	if raw, err := os.ReadFile(HashDBPath()); err == nil {
		db.merge(string(raw))
	}
	if raw, err := os.ReadFile(LearnedHashPath()); err == nil {
		db.merge(string(raw))
	}
	if raw, err := os.ReadFile(FeedHashPath()); err == nil {
		db.merge(string(raw))
	}
	return db
}

// FeedHashPath holds MD5 signatures from public feeds (Linux Malware Detect).
func FeedHashPath() string { return store.StateDir() + "/sigs/feed-md5.txt" }

func (db *HashDB) merge(text string) {
	db.mu.Lock()
	defer db.mu.Unlock()
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		size, err := strconv.ParseInt(f[0], 10, 64)
		if err != nil {
			continue
		}
		label := "XMartGuard.KnownMalware"
		if len(f) >= 3 {
			label = f[2]
		}
		sha := strings.ToLower(f[1])
		if len(sha) != 64 && len(sha) != 32 {
			continue
		}
		for _, e := range db.bySize[size] {
			if e.sha == sha {
				sha = ""
				break
			}
		}
		if sha != "" {
			db.bySize[size] = append(db.bySize[size], hashEntry{sha, label})
			db.count++
		}
	}
}

// SizeKnown reports whether any known-bad file has this exact size (cheap
// pre-filter so we only hash candidates).
func (db *HashDB) SizeKnown(size int64) bool {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return len(db.bySize[size]) > 0
}

// Lookup returns the label for a size + SHA-256 (or MD5) match, or "".
// sums is called only when an entry has this size.
func (db *HashDB) Lookup(size int64, sha string) string {
	return db.LookupSums(size, func() (string, string) { return sha, "" })
}

// LookupSums matches SHA-256 entries and MD5 entries (public feeds).
func (db *HashDB) LookupSums(size int64, sums func() (sha256, md5 string)) string {
	db.mu.RLock()
	entries := db.bySize[size]
	db.mu.RUnlock()
	if len(entries) == 0 {
		return ""
	}
	sha, md := sums()
	for _, e := range entries {
		if (len(e.sha) == 64 && e.sha == sha) || (len(e.sha) == 32 && md != "" && e.sha == md) {
			return e.label
		}
	}
	return ""
}

// Count returns the number of loaded signatures.
func (db *HashDB) Count() int {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return db.count
}

// ReloadHashDB re-reads the runtime signature file (after a portal update).
func ReloadHashDB() int {
	db := loadHashDB()
	current.Store(db)
	return db.Count()
}

// SignatureCount is exposed for the About/stats views.
func SignatureCount() int { return activeHashDB().Count() + len(Rules) }

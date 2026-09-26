package scanner

import (
	"bufio"
	_ "embed"
	"os"
	"strconv"
	"strings"
	"sync"

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

var hashDB = loadHashDB()

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
	return db
}

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

// Lookup returns the label for a size+sha256 match, or "".
func (db *HashDB) Lookup(size int64, sha string) string {
	db.mu.RLock()
	defer db.mu.RUnlock()
	for _, e := range db.bySize[size] {
		if e.sha == sha {
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
	hashDB = db
	return db.Count()
}

// SignatureCount is exposed for the About/stats views.
func SignatureCount() int { return hashDB.Count() + len(Rules) }

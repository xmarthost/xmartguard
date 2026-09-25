// Package store is the agent's local SQLite database. Detailed security data
// (scans, findings, firewall rules and events) stays on the server; the portal
// fetches it on demand.
package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// Install layout (mirrors /etc/<product> + /opt/<product>):
//
//	/etc/xmartguard            agent.json, identity.key, settings.json
//	/opt/xmartguard/bin        the agent binary
//	/opt/xmartguard/data       local database, signatures, IPDB list, quarantine
//	/opt/xmartguard/logs       agent and install logs
//
// DefaultStateDir can be overridden with XG_STATE_DIR (tests).
const (
	HomeDir         = "/opt/xmartguard"
	DefaultStateDir = HomeDir + "/data"
	// LegacyStateDir is where agents before 0.3.0 kept their data.
	LegacyStateDir = "/var/lib/xmartguard"
)

// StateDir returns the agent state directory.
func StateDir() string {
	if d := os.Getenv("XG_STATE_DIR"); d != "" {
		return d
	}
	if stateOverride != "" {
		return stateOverride
	}
	return DefaultStateDir
}

// stateOverride keeps a legacy install on /var/lib/xmartguard when its data
// cannot be moved (e.g. /opt is a different filesystem).
var stateOverride string

const schema = `
CREATE TABLE IF NOT EXISTS scans (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  kind        TEXT NOT NULL,           -- full | quick | path | daily | weekly
  target      TEXT NOT NULL,
  status      TEXT NOT NULL,           -- queued | running | completed | failed | stopped
  files       INTEGER NOT NULL DEFAULT 0,
  infected    INTEGER NOT NULL DEFAULT 0,
  initiator   TEXT NOT NULL DEFAULT '',
  started_at  INTEGER NOT NULL,
  finished_at INTEGER NOT NULL DEFAULT 0,
  error       TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS findings (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id     INTEGER NOT NULL DEFAULT 0,
  source      TEXT NOT NULL,           -- manual | scheduled | realtime
  path        TEXT NOT NULL,
  owner       TEXT NOT NULL DEFAULT '',
  category    TEXT NOT NULL,           -- virus | suspicious | binary
  signature   TEXT NOT NULL,
  sha256      TEXT NOT NULL DEFAULT '',
  size        INTEGER NOT NULL DEFAULT 0,
  status      TEXT NOT NULL,           -- detected | quarantined | disabled | restored | deleted | ignored
  created_at  INTEGER NOT NULL,
  updated_at  INTEGER NOT NULL,
  qpath       TEXT NOT NULL DEFAULT '',
  orig_mode   INTEGER NOT NULL DEFAULT 0,
  orig_uid    INTEGER NOT NULL DEFAULT -1,
  orig_gid    INTEGER NOT NULL DEFAULT -1
);
CREATE INDEX IF NOT EXISTS findings_created ON findings(created_at);
CREATE INDEX IF NOT EXISTS findings_path ON findings(path);
CREATE TABLE IF NOT EXISTS fw_rules (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  kind        TEXT NOT NULL,           -- allow | deny | tempban | tempallow | ignore
  cidr        TEXT NOT NULL,
  comment     TEXT NOT NULL DEFAULT '',
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL DEFAULT 0,
  UNIQUE(kind, cidr)
);
CREATE TABLE IF NOT EXISTS fw_events (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  ip          TEXT NOT NULL,
  reason      TEXT NOT NULL,
  source      TEXT NOT NULL,           -- bruteforce | dos | manual
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL DEFAULT 0,
  status      TEXT NOT NULL            -- blocked | unblocked | expired
);
CREATE INDEX IF NOT EXISTS fw_events_created ON fw_events(created_at);
CREATE TABLE IF NOT EXISTS ipdb_hits (
  entry       TEXT PRIMARY KEY,        -- IPDB list entry (IP or CIDR) that matched
  country     TEXT NOT NULL DEFAULT '',
  hits        INTEGER NOT NULL DEFAULT 0,
  pending     INTEGER NOT NULL DEFAULT 0, -- not yet sent to the portal
  first_seen  INTEGER NOT NULL,
  last_seen   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS ipdb_hits_last ON ipdb_hits(last_seen);
CREATE TABLE IF NOT EXISTS ipdb_country (
  day      TEXT NOT NULL,
  country  TEXT NOT NULL,
  hits     INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (day, country)
);
CREATE TABLE IF NOT EXISTS kv (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
`

// Open opens (and migrates) the database at <state>/agent.db.
func Open() (*sql.DB, error) {
	dir := StateDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	moved := false
	if dir == DefaultStateDir {
		var ok bool
		if moved, ok = migrateLegacy(dir); !ok {
			stateOverride, dir = LegacyStateDir, LegacyStateDir
		}
	}
	db, err := OpenPath(filepath.Join(dir, "agent.db"))
	if err == nil && moved {
		// Quarantined files keep their records: point them at the new location.
		_, _ = db.Exec(`UPDATE findings SET qpath = ? || substr(qpath, ?) WHERE qpath LIKE ?`,
			dir, len(LegacyStateDir)+1, LegacyStateDir+"/%")
	}
	return db, err
}

// migrateLegacy moves data from the pre-0.3.0 location (/var/lib/xmartguard)
// into /opt/xmartguard/data once. The install manifest stays where it is so
// the uninstaller that shipped with that install still works.
func migrateLegacy(dir string) (moved, ok bool) {
	if _, err := os.Stat(filepath.Join(dir, "agent.db")); err == nil {
		return false, true
	}
	if _, err := os.Stat(filepath.Join(LegacyStateDir, "agent.db")); err != nil {
		return false, true
	}
	for _, name := range []string{"agent.db", "agent.db-wal", "agent.db-shm", "quarantine", "sigs", "geo"} {
		src := filepath.Join(LegacyStateDir, name)
		if _, err := os.Lstat(src); err != nil {
			continue
		}
		if err := os.Rename(src, filepath.Join(dir, name)); err != nil && name == "agent.db" {
			return false, false
		}
	}
	return true, true
}

// OpenPath opens a database file directly.
func OpenPath(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // SQLite: serialize writers
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: migrate: %w", err)
	}
	_ = os.Chmod(path, 0o600)
	return db, nil
}

// Now is the clock used for timestamps (overridable in tests).
var Now = func() int64 { return time.Now().Unix() }

// GetKV reads a key; missing keys return "".
func GetKV(db *sql.DB, key string) string {
	var v string
	_ = db.QueryRow(`SELECT value FROM kv WHERE key = ?`, key).Scan(&v)
	return v
}

// SetKV upserts a key.
func SetKV(db *sql.DB, key, value string) error {
	_, err := db.Exec(`INSERT INTO kv(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

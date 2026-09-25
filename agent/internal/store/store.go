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

// DefaultStateDir can be overridden with XG_STATE_DIR (tests).
const DefaultStateDir = "/var/lib/xmartguard"

// StateDir returns the agent state directory.
func StateDir() string {
	if d := os.Getenv("XG_STATE_DIR"); d != "" {
		return d
	}
	return DefaultStateDir
}

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
	return OpenPath(filepath.Join(dir, "agent.db"))
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

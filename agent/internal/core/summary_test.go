package core

import (
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/store"
)

// Audit A1 F15: retention also prunes old IPDB hits, cleared findings, DB
// clean backups and unreferenced AI verdicts; keeps the WAF log 32 days for
// the monthly report, and keeps admin and fleet verdicts.
func TestPruneOldGrowingTables(t *testing.T) {
	a := newTestAgent(t, `{"firewall":{"enabled":false},"scanner":{"keep_days":7}}`)
	now := store.Now()
	old, recent := now-10*86400, now-20*86400 // recent: inside 32 days
	a.DB.Exec(`INSERT INTO ipdb_hits (entry, hits, pending, first_seen, last_seen) VALUES ('192.0.2.1',1,0,?,?), ('192.0.2.2',1,3,?,?)`, old, old, old, old)
	a.DB.Exec(`INSERT INTO findings (source, path, owner, category, signature, status, sha256, created_at, updated_at) VALUES ('manual','/home/u/a.php','u','virus','X','cleared','',?,?)`, old, old)
	a.DB.Exec(`INSERT INTO findings (source, path, owner, category, signature, status, sha256, created_at, updated_at) VALUES ('manual','/home/u/b.php','u','virus','X','detected','kept',?,?)`, old, old)
	a.DB.Exec(`INSERT INTO db_clean_backup (finding_id, at, site_path, db_name, tbl, key_col, key_val, col, old_value) VALUES (1,?,'/s','d','t','k','1','c','v')`, old)
	ancient := now - 200*86400
	for _, v := range [][2]string{{"gone", "ai"}, {"kept", "ai"}, {"adm", "admin"}, {"flt", "fleet"}} {
		a.DB.Exec(`INSERT INTO ai_verdicts (sha256, verdict, confidence, model, at, source) VALUES (?, 'clean', 95, 'm', ?, ?)`, v[0], ancient, v[1])
	}
	a.DB.Exec(`INSERT INTO waf_events (at, ip, category, action) VALUES (?, '192.0.2.9', 'waf', 'Access denied')`, recent)
	a.pruneOld()
	count := func(q string) (n int) { a.DB.QueryRow(q).Scan(&n); return }
	if n := count(`SELECT count(*) FROM ipdb_hits`); n != 1 {
		t.Errorf("ipdb_hits %d, want the unsent one", n)
	}
	if n := count(`SELECT count(*) FROM findings WHERE status = 'cleared'`); n != 0 {
		t.Error("old cleared finding kept")
	}
	if n := count(`SELECT count(*) FROM db_clean_backup`); n != 0 {
		t.Error("old DB clean backup kept")
	}
	var shas string
	a.DB.QueryRow(`SELECT group_concat(sha256) FROM (SELECT sha256 FROM ai_verdicts ORDER BY sha256)`).Scan(&shas)
	if shas != "adm,flt,kept" {
		t.Errorf("ai_verdicts left: %s", shas)
	}
	if n := count(`SELECT count(*) FROM waf_events`); n != 1 {
		t.Error("WAF events of the last 32 days pruned")
	}
}

// Audit A1 F10: the table counts behind the metrics summary run once per
// summaryEvery, not on every (5-second) sample, and are refreshed in the
// background when stale.
func TestSummaryCountsCached(t *testing.T) {
	var c summaryCache
	var runs atomic.Int32
	compute := func() heavySummary { runs.Add(1); return heavySummary{listed: int(runs.Load())} }
	for i := 0; i < 20; i++ {
		if v := c.get(compute); v.listed != 1 {
			t.Fatalf("sample %d: %+v", i, v)
		}
	}
	if runs.Load() != 1 {
		t.Fatalf("%d computations for 20 samples", runs.Load())
	}
	c.mu.Lock()
	c.at = time.Now().Add(-summaryEvery - time.Second)
	c.mu.Unlock()
	if v := c.get(compute); v.listed != 1 {
		t.Fatal("stale value not served while refreshing")
	}
	for i := 0; i < 100 && c.get(compute).listed != 2; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if runs.Load() != 2 {
		t.Fatalf("refresh: %d computations", runs.Load())
	}
	// The real summary still answers.
	a := newTestAgent(t, `{"firewall":{"enabled":false}}`)
	if m, ok := a.SecuritySummary().(map[string]any); !ok || m["card"] == nil {
		t.Fatalf("summary %v", a.SecuritySummary())
	}
}

// Quarantined files are kept a week by default (the owner's choice), apart
// from the logs (2 months): one restored in time comes back, older ones
// are deleted for good.
func TestQuarantineKeptAWeek(t *testing.T) {
	a := newTestAgent(t, `{"firewall":{"enabled":false}}`)
	if st := a.Settings.Get().Scanner; st.QuarantineDays != 7 || st.KeepDays != 60 {
		t.Fatalf("defaults: quarantine %d, logs %d", st.QuarantineDays, st.KeepDays)
	}
	now := store.Now()
	dir := t.TempDir()
	add := func(name string, age int64) int64 {
		q := filepath.Join(dir, name)
		os.WriteFile(q, []byte("x"), 0o600)
		res, _ := a.DB.Exec(`INSERT INTO findings (source, path, owner, category, signature, status, qpath, created_at, updated_at)
			VALUES ('manual', ?, 'u', 'virus', 'X', 'quarantined', ?, ?, ?)`, "/home/u/"+name, q, now-age*86400, now-age*86400)
		id, _ := res.LastInsertId()
		return id
	}
	old, recent := add("old.php", 8), add("recent.php", 3)
	// The first week after the update: nothing is deleted yet.
	a.pruneOld()
	var st string
	a.DB.QueryRow(`SELECT status FROM findings WHERE id = ?`, old).Scan(&st)
	if st != "quarantined" {
		t.Fatalf("deleted in the first week: %s", st)
	}
	store.SetKV(a.DB, kvQuarantineWeek, strconv.FormatInt(now-8*86400, 10))
	a.pruneOld()
	status := func(id int64) (s string) {
		a.DB.QueryRow(`SELECT status FROM findings WHERE id = ?`, id).Scan(&s)
		return
	}
	if status(old) != "deleted" || status(recent) != "quarantined" {
		t.Fatalf("old %s, recent %s", status(old), status(recent))
	}
	if _, err := os.Stat(filepath.Join(dir, "old.php")); !os.IsNotExist(err) {
		t.Fatal("old quarantined file kept")
	}
}

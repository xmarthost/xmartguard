package core

import (
	"strings"
	"testing"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/store"
)

// Audit A1 F16: on the 29th-31st "last month" is still the month before.
func TestLastMonth(t *testing.T) {
	for now, want := range map[string]string{"2026-03-31": "2026-02", "2026-03-01": "2026-02", "2026-01-30": "2025-12", "2026-10-20": "2026-09"} {
		d, _ := time.ParseInLocation("2006-01-02", now, time.Local)
		if got := lastMonth(d.Add(23 * time.Hour)).Format("2006-01"); got != want {
			t.Errorf("%s: %s, want %s", now, got, want)
		}
	}
}

func TestMonthReport(t *testing.T) {
	a := newTestAgent(t, "")
	now := store.Now()
	a.DB.Exec(`INSERT INTO cms_sites (type, path, user, domain, version, latest) VALUES ('WordPress','/home/u1/public_html','u1','one.example','6.8','6.8')`)
	for i := 0; i < 3; i++ {
		a.DB.Exec(`INSERT INTO waf_events (at, ip, method, host, uri, rule_id, msg, category, action, user, detail) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
			now, "198.51.100.1", "GET", "one.example", "/x", 7700100, "x", "waf", "Access denied with code 403", "u1", "")
	}
	a.DB.Exec(`INSERT INTO findings (scan_id, source, path, owner, category, signature, sha256, size, status, created_at, updated_at) VALUES (0,'realtime','/home/u1/public_html/a.php','u1','virus','PHP.Test','x',1,'quarantined',?,?)`, now, now)
	r := a.monthReport("u1", time.Now())
	if r.Attacks != 3 || r.Malware != 1 || r.Removed != 1 || len(r.Sites) != 1 {
		t.Fatalf("report %+v", r)
	}
	txt := r.Text()
	for _, want := range []string{"Web attacks blocked:      3", "one.example: A (90/100)", "change the WordPress", "Security report for"} {
		if !strings.Contains(txt, want) {
			t.Errorf("missing %q in:\n%s", want, txt)
		}
	}
	if other := a.monthReport("u2", time.Now()); other.Attacks != 0 || len(other.Sites) != 0 {
		t.Fatalf("other user sees %+v", other)
	}
}

package core

import (
	"strings"
	"testing"

	"github.com/xmarthost/xmartguard/agent/internal/store"
)

// Audit A1 F11: the per-website finding counts use the path index, and
// count only files inside the website's folder.
func TestSiteScoresUsePathIndex(t *testing.T) {
	a := newTestAgent(t, `{"firewall":{"enabled":false}}`)
	now := store.Now()
	a.DB.Exec(`INSERT INTO cms_sites (type, path, user, domain) VALUES ('wordpress', '/home/u/public_html', 'u', 'a.example')`)
	for _, p := range []string{"/home/u/public_html/x.php", "/home/u/public_html2/y.php", "/home/u/public_html.php"} {
		a.DB.Exec(`INSERT INTO findings (source, path, owner, category, signature, status, created_at, updated_at) VALUES ('manual',?,'u','virus','X','detected',?,?)`, p, now, now)
	}
	s := a.siteScores("")
	if len(s) != 1 || len(s[0].ToDo) == 0 || !strings.Contains(s[0].ToDo[0], "1 infected") {
		t.Fatalf("scores %+v", s)
	}
	rows, err := a.DB.Query(`EXPLAIN QUERY PLAN SELECT count(*) FROM findings WHERE path >= ? AND path < ? AND status = 'detected' AND category != 'symlink'`, "/a/", "/a0")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	plan := ""
	for rows.Next() {
		var id, parent, nu int
		var detail string
		rows.Scan(&id, &parent, &nu, &detail)
		plan += detail + ";"
	}
	if !strings.Contains(plan, "findings_path") {
		t.Fatalf("plan %q", plan)
	}
}

package core

import (
	"testing"

	"github.com/xmarthost/xmartguard/agent/internal/store"
)

func TestSiteScores(t *testing.T) {
	a := newTestAgent(t, "")
	ins := `INSERT INTO cms_sites (type, path, user, domain, version, latest, risk, outdated_plugins, outdated_themes, core_issues, db_issues) VALUES (?,?,?,?,?,?,?,?,?,?,?)`
	a.DB.Exec(ins, "WordPress", "/home/good/public_html", "good", "good.example", "6.8", "6.8", "ok", 0, 0, 0, 0)
	a.DB.Exec(ins, "WordPress", "/home/bad/public_html", "bad", "bad.example", "6.1", "6.8", "critical", 6, 1, 3, 1)
	a.DB.Exec(`INSERT INTO findings (scan_id, source, path, owner, category, signature, sha256, size, status, created_at, updated_at) VALUES (0,'realtime',?, 'bad','virus','PHP.Test','x',1,'detected',?,?)`,
		"/home/bad/public_html/wp-content/x.php", store.Now(), store.Now())
	got := a.siteScores("")
	if len(got) != 2 || got[0].Domain != "bad.example" || got[0].Grade != "F" || len(got[0].ToDo) < 5 {
		t.Fatalf("scores %+v", got)
	}
	if got[1].Grade != "A" || got[1].Score != 100 || len(got[1].ToDo) != 0 {
		t.Fatalf("good site %+v", got[1])
	}
	if mine := a.siteScores("good"); len(mine) != 1 || mine[0].Owner != "good" {
		t.Fatalf("user filter %+v", mine)
	}
}

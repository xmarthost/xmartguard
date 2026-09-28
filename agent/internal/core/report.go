package core

import (
	"strings"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/cms"
	"github.com/xmarthost/xmartguard/agent/internal/scanner"
)

// scanReport summarises a scan: what was checked and found, and the state
// of the CMS installations and databases inside its target.
func (a *Agent) scanReport(sc scanner.Scan) map[string]any {
	// Sites inside the scanned path (a full scan covers every site).
	where, args := "1=1", []any{}
	if strings.HasPrefix(sc.Target, "/") {
		t := strings.TrimRight(sc.Target, "/")
		where, args = "(path = ? OR substr(path, 1, ?) = ?)", []any{t, len(t) + 1, t + "/"}
	}
	count := func(q string, extra ...any) int {
		var n int
		_ = a.DB.QueryRow(q, append(append([]any{}, args...), extra...)...).Scan(&n)
		return n
	}
	inTarget := func(path string) bool {
		if !strings.HasPrefix(sc.Target, "/") {
			return true
		}
		t := strings.TrimRight(sc.Target, "/")
		return path == t || strings.HasPrefix(path, t+"/")
	}
	cmsThreats, outdated, sites, dbScanned := 0, 0, 0, 0
	dbScan := a.Settings.Get().CMS.DBScan
	for off := 0; ; off += 500 {
		list, _, err := a.CMS.Sites(cms.SiteFilter{Limit: 500, Offset: off})
		if err != nil || len(list) == 0 {
			break
		}
		for _, st := range list {
			if !inTarget(st.Path) {
				continue
			}
			sites++
			cmsThreats += st.CoreIssues + st.DBIssues + st.Vulnerable
			if st.OutdatedPlugins+st.OutdatedThemes > 0 || (st.Latest != "" && st.Version != st.Latest) {
				outdated++
			}
			if dbScan && st.Type == "wordpress" {
				dbScanned++
			}
		}
		if len(list) < 500 {
			break
		}
	}
	dbWhere := strings.ReplaceAll(where, "path", "site_path")
	dbInfected := count(`SELECT count(*) FROM db_findings WHERE ` + dbWhere + ` AND status = 'detected'`)
	end := sc.FinishedAt
	if end == 0 {
		end = time.Now().Unix()
	}
	var found, byCat = 0, map[string]int{}
	rows, err := a.DB.Query(`SELECT category, count(*) FROM findings WHERE scan_id = ? GROUP BY category`, sc.ID)
	if err == nil {
		for rows.Next() {
			var c string
			var n int
			if rows.Scan(&c, &n) == nil {
				byCat[c] = n
				found += n
			}
		}
		rows.Close()
	}
	return map[string]any{
		"scan":         sc,
		"duration":     end - sc.StartedAt,
		"findings":     found,
		"categories":   byCat,
		"cms_sites":    sites,
		"cms_threats":  cmsThreats,
		"outdated_cms": outdated,
		"db_infected":  dbInfected,
		"db_scanned":   dbScanned,
	}
}

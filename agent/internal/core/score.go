package core

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/xmarthost/xmartguard/agent/internal/client"
	"github.com/xmarthost/xmartguard/agent/internal/store"
)

// Security score: each website's state in the customer's words, from what
// the CMS checks, the scanner and the server audit already know, with the
// few things to do for an A.

// SiteScore is one website's grade.
type SiteScore struct {
	Domain string   `json:"domain"`
	Path   string   `json:"path"`
	Owner  string   `json:"owner"`
	Type   string   `json:"type"`
	Score  int      `json:"score"`
	Grade  string   `json:"grade"`
	ToDo   []string `json:"todo"`
}

func grade(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 65:
		return "C"
	case score >= 50:
		return "D"
	}
	return "F"
}

type scoreSite struct {
	typ, path, user, domain, version, latest, risk string
	outPlugins, outThemes, coreIssues, dbIssues    int
}

// siteScores grades every website found by the CMS checks (user = "" for all).
func (a *Agent) siteScores(user string) []SiteScore {
	q := `SELECT type, path, user, domain, version, latest, risk, outdated_plugins, outdated_themes, core_issues, db_issues FROM cms_sites`
	var args []any
	if user != "" {
		q += ` WHERE user = ?`
		args = append(args, user)
	}
	rows, err := a.DB.Query(q, args...)
	if err != nil {
		return nil
	}
	var sites []scoreSite
	for rows.Next() {
		var s scoreSite
		if rows.Scan(&s.typ, &s.path, &s.user, &s.domain, &s.version, &s.latest, &s.risk, &s.outPlugins, &s.outThemes, &s.coreIssues, &s.dbIssues) == nil {
			sites = append(sites, s)
		}
	}
	rows.Close()
	rep, _ := lastAudit()
	since := store.Now() - 30*86400
	out := make([]SiteScore, 0, len(sites))
	for _, s := range sites {
		score := 100
		var todo []string
		take := func(n int, what string) {
			score -= n
			todo = append(todo, what)
		}
		var open, removed int
		prefix := strings.TrimSuffix(s.path, "/") + "/"
		// A range on path (the index findings_path) instead of substr(),
		// which read the whole table twice per website: every path under
		// "dir/" sorts below "dir0" ("0" follows "/").
		end := strings.TrimSuffix(prefix, "/") + "0"
		_ = a.DB.QueryRow(`SELECT count(*) FROM findings WHERE path >= ? AND path < ? AND status = 'detected' AND category != 'symlink'`, prefix, end).Scan(&open)
		_ = a.DB.QueryRow(`SELECT count(*) FROM findings WHERE path >= ? AND path < ? AND status IN ('quarantined','cleaned','trimmed','disabled') AND updated_at >= ?`, prefix, end, since).Scan(&removed)
		if open > 0 {
			take(30, fmt.Sprintf("Deal with %d infected file(s) found on the website", open))
		} else if removed > 0 {
			take(10, "Malware was removed in the last 30 days: change the WordPress, FTP and database passwords")
		}
		if s.coreIssues > 0 {
			take(20, fmt.Sprintf("Repair %d changed core file(s)", s.coreIssues))
		}
		if s.dbIssues > 0 {
			take(20, fmt.Sprintf("Remove %d injected script(s) from the database", s.dbIssues))
		}
		switch s.risk {
		case "critical":
			take(20, "Update the plugin or theme with a known security hole")
		case "high":
			take(10, "Update the out-of-date plugins with security fixes")
		}
		if s.latest != "" && s.version != "" && s.version != s.latest {
			take(10, fmt.Sprintf("Update %s %s to %s", s.typ, s.version, s.latest))
		}
		if s.outPlugins > 0 {
			take(min(15, 3*s.outPlugins), fmt.Sprintf("Update %d plugin(s)", s.outPlugins))
		}
		if s.outThemes > 0 {
			take(min(6, 2*s.outThemes), fmt.Sprintf("Update %d theme(s)", s.outThemes))
		}
		seen := map[string]bool{}
		for _, it := range rep.Items {
			if seen[it.Check] || it.Path == "" || !(strings.HasPrefix(it.Path, prefix) || strings.TrimSuffix(it.Path, "/") == strings.TrimSuffix(s.path, "/")) {
				continue
			}
			seen[it.Check] = true
			switch it.Check {
			case "leaked_secret":
				take(15, "Remove the passwords or keys readable from the web ("+it.Title+")")
			case "public_backup":
				take(10, "Move the backup or database dump out of the website folder")
			case "wp_debug":
				take(5, "Switch WP_DEBUG off (it shows errors to visitors)")
			case "php_eol", "php":
				take(10, "Use a supported PHP version")
			case "wp_core":
				take(10, "Reinstall the missing WordPress core files")
			}
		}
		score = max(score, 0)
		out = append(out, SiteScore{Domain: s.domain, Path: s.path, Owner: s.user, Type: s.typ, Score: score, Grade: grade(score), ToDo: todo})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Score < out[j].Score || (out[i].Score == out[j].Score && out[i].Domain < out[j].Domain)
	})
	return out
}

func (a *Agent) scoreHandlers(h map[string]client.Handler) {
	h["sites.scores"] = func(_ context.Context, p json.RawMessage) (any, error) {
		in, err := decode[struct {
			User string `json:"user"`
		}](p)
		if err != nil {
			return nil, err
		}
		return map[string]any{"sites": a.siteScores(in.User)}, nil
	}
}

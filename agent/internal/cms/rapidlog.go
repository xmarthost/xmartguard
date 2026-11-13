package cms

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/xmarthost/xmartguard/agent/internal/store"
)

// What the fast response did, per site and advisory, for the portal's
// report (owner, 2026-11-13: "which vulnerabilities were sent on which day,
// what each server did, which websites were updated and which not").

// Rapid actions.
const (
	RapidUpdated             = "updated"
	RapidShielded            = "shielded"             // update failed, plugin folder shielded
	RapidShieldedDeactivated = "shielded_deactivated" // and deactivated (critical)
	RapidDeactivated         = "deactivated"          // shield failed, deactivated
	RapidManual              = "manual"               // a theme or core that could not be updated
	RapidFailed              = "failed"               // not updated, nothing else applied
	RapidGone                = "gone"                 // the site or component is gone since
)

// RapidResult is one site's outcome for one advisory.
type RapidResult struct {
	ID        int64   `json:"-"`
	At        int64   `json:"at"`
	Advisory  string  `json:"advisory"`
	Title     string  `json:"title,omitempty"`
	CVSS      float64 `json:"cvss"`
	Path      string  `json:"path"`
	Domain    string  `json:"domain,omitempty"`
	User      string  `json:"user,omitempty"`
	Kind      string  `json:"kind"`
	Slug      string  `json:"slug"`
	Version   string  `json:"version"`
	Action    string  `json:"action"`
	ToVersion string  `json:"to_version,omitempty"`
	Detail    string  `json:"detail,omitempty"`
}

func (m *Manager) logRapid(r RapidResult) {
	if r.At == 0 {
		r.At = store.Now()
	}
	if len(r.Detail) > 500 {
		r.Detail = r.Detail[:500]
	}
	_, err := m.DB.Exec(`INSERT INTO cms_rapid_log (at, advisory, title, cvss, path, domain, user, kind, slug, version, action, to_version, detail)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`, r.At, r.Advisory, r.Title, r.CVSS, r.Path, r.Domain, r.User, r.Kind, r.Slug, r.Version, r.Action, r.ToVersion, r.Detail)
	if err != nil {
		m.Log.Warn("fast response result not recorded", "err", err)
	}
}

// updateFailure says in a few words why an update left the version.
func updateFailure(out string, err error, premium bool) string {
	switch {
	case dbDown(err):
		return "the site's database is not reachable (account suspended or broken)"
	case err != nil:
		e := strings.TrimPrefix(err.Error(), "wp-cli failed: ")
		if len(e) > 300 {
			e = e[:300]
		}
		return "update failed: " + e
	case notUpdated(out) && premium:
		return "not on wordpress.org (premium or custom): no update wp-cli can install"
	case notUpdated(out):
		return "WordPress offered no update for it"
	default:
		return "the installed version is still vulnerable after the update"
	}
}

// PendingRapid returns results the portal does not have yet.
func (m *Manager) PendingRapid(limit int) ([]RapidResult, error) {
	rows, err := m.DB.Query(`SELECT id, at, advisory, title, cvss, path, domain, user, kind, slug, version, action, to_version, detail
		FROM cms_rapid_log WHERE reported = 0 ORDER BY id LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RapidResult
	for rows.Next() {
		var r RapidResult
		if err := rows.Scan(&r.ID, &r.At, &r.Advisory, &r.Title, &r.CVSS, &r.Path, &r.Domain, &r.User, &r.Kind, &r.Slug, &r.Version, &r.Action, &r.ToVersion, &r.Detail); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// MarkRapidReported marks results the portal stored; rows older than 90
// days that were reported are dropped.
func (m *Manager) MarkRapidReported(rs []RapidResult) {
	for _, r := range rs {
		_, _ = m.DB.Exec(`UPDATE cms_rapid_log SET reported = 1 WHERE id = ?`, r.ID)
	}
	_, _ = m.DB.Exec(`DELETE FROM cms_rapid_log WHERE reported = 1 AND at < ?`, store.Now()-90*86400)
}

const kvRapidBackfill = "cms_rapid_backfilled"

// BackfillRapid turns the fast response's earlier once-only marks
// (cms_rapid|path|kind|slug|version|advisory, before results were
// recorded) into results, judged by the site as it is now: the version
// changed (updated), the folder carries the advisory's shield, or nothing.
// Runs once.
func (m *Manager) BackfillRapid() int {
	if store.GetKV(m.DB, kvRapidBackfill) != "" {
		return 0
	}
	rows, err := m.DB.Query(`SELECT key, value FROM kv WHERE key LIKE 'cms_rapid|%'`)
	if err != nil {
		return 0
	}
	type mark struct {
		path, kind, slug, version, adv string
		at                             int64
	}
	var marks []mark
	for rows.Next() {
		var k, v string
		if rows.Scan(&k, &v) != nil {
			continue
		}
		p := strings.Split(k, "|")
		if len(p) < 6 {
			continue
		}
		n := len(p)
		at, _ := strconv.ParseInt(v, 10, 64)
		marks = append(marks, mark{strings.Join(p[1:n-4], "|"), p[n-4], p[n-3], p[n-2], p[n-1], at})
	}
	rows.Close()
	sites := map[string]*Site{}
	for _, mk := range marks {
		s, ok := sites[mk.path]
		if !ok {
			if list, _, err := m.Sites(SiteFilter{Type: WordPress, Path: mk.path, Limit: 1}); err == nil && len(list) == 1 && list[0].Path == mk.path {
				s = &list[0]
			}
			sites[mk.path] = s
		}
		r := RapidResult{At: mk.at, Advisory: mk.adv, Path: mk.path, Kind: mk.kind, Slug: mk.slug, Version: mk.version, Action: RapidFailed,
			Detail: "recorded before results were kept: judged from the site as it is now"}
		cur := ""
		if s != nil {
			r.Domain, r.User = s.Domain, s.User
			switch mk.kind {
			case "core":
				cur = s.Version
			case "plugin":
				for _, c := range s.Plugins {
					if c.Slug == mk.slug {
						cur = c.Version
					}
				}
			case "theme":
				for _, c := range s.Themes {
					if c.Slug == mk.slug {
						cur = c.Version
					}
				}
			}
		}
		switch {
		case s == nil || cur == "":
			r.Action = RapidGone
		case cur != mk.version:
			r.Action, r.ToVersion = RapidUpdated, cur
		case mk.kind == "plugin" && shieldedFor(filepath.Join(mk.path, "wp-content", "plugins", mk.slug), mk.adv):
			r.Action = RapidShielded
		case mk.kind != "plugin":
			r.Action = RapidManual
		}
		m.logRapid(r)
	}
	_ = store.SetKV(m.DB, kvRapidBackfill, strconv.FormatInt(store.Now(), 10))
	return len(marks)
}

// shieldedFor reports whether the folder's .htaccess carries the
// advisory's shield.
func shieldedFor(dir, adv string) bool {
	b, err := os.ReadFile(filepath.Join(dir, ".htaccess"))
	return err == nil && strings.Contains(string(b), shieldBegin) && strings.Contains(string(b), "# xPGuard: "+adv+" ")
}

// CorrectRapid records "updated" for results that said otherwise while the
// site's files now hold another version: an update the fast response
// misread (wp-cli output with PHP warnings, 2026-11-13), or one the nightly
// automatic update or the customer made later. The portal replaces the
// earlier result. Returns how many it corrected.
func (m *Manager) CorrectRapid() int {
	rows, err := m.DB.Query(`SELECT advisory, max(title), max(cvss), path, max(domain), max(user), kind, slug, version FROM cms_rapid_log r
		WHERE action NOT IN ('updated', 'gone') AND NOT EXISTS (
		  SELECT 1 FROM cms_rapid_log u WHERE u.advisory = r.advisory AND u.path = r.path AND u.version = r.version AND u.action IN ('updated', 'gone'))
		GROUP BY advisory, path, kind, slug, version`)
	if err != nil {
		return 0
	}
	var open []RapidResult
	for rows.Next() {
		var r RapidResult
		if rows.Scan(&r.Advisory, &r.Title, &r.CVSS, &r.Path, &r.Domain, &r.User, &r.Kind, &r.Slug, &r.Version) == nil {
			open = append(open, r)
		}
	}
	rows.Close()
	sites := map[string]*Site{}
	n := 0
	for _, r := range open {
		s, ok := sites[r.Path]
		if !ok {
			if list, _, err := m.Sites(SiteFilter{Type: WordPress, Path: r.Path, Limit: 1}); err == nil && len(list) == 1 && list[0].Path == r.Path {
				s = &list[0]
			}
			sites[r.Path] = s
		}
		if s == nil {
			continue // not listed now (a scan error): judged later
		}
		cur, found := "", false
		switch r.Kind {
		case "core":
			cur, found = s.Version, true
		case "plugin", "theme":
			list := s.Plugins
			if r.Kind == "theme" {
				list = s.Themes
			}
			for _, c := range list {
				if c.Slug == r.Slug {
					cur, found = c.Version, true
				}
			}
		}
		switch {
		case !found:
			r.Action, r.Detail = RapidGone, "removed from the site since"
		case cur != "" && cur != r.Version:
			r.Action, r.ToVersion, r.Detail = RapidUpdated, cur, "updated: confirmed from the site's files"
		default:
			continue
		}
		r.At = 0
		m.logRapid(r)
		n++
	}
	return n
}

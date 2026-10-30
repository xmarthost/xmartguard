package cms

import (
	"context"
	"regexp"

	"github.com/xmarthost/xmartguard/agent/internal/store"
)

// Plugin watch. Attackers with an administrator's password upload their
// plugin through wp-admin (server1, 2026-10-28: system-defence,
// core-wp.zip), and kits clone themselves under a timestamped name
// (contact_1772129663). A plugin that appears after xPGuard first listed
// the site and is not a wordpress.org plugin (or claims a version newer
// than wordpress.org has) is reported for a person to check, and so is a
// folder named with a Unix time. Nothing is changed: the file scanner
// judges the files themselves.

const (
	PluginCategory = "plugin"
	pluginSigNew   = "WP.Plugin.NewUnknown"
	pluginSigClone = "WP.Plugin.TimestampClone"
)

// A Unix time of 2020-2033 at the end of a folder name.
var reEpochName = regexp.MustCompile(`[_-]1[5-9][0-9]{8}$`)

// pluginFindings judges a site's plugins against its baseline (nil: the
// first listing).
func pluginFindings(plugins []Component, baseline map[string]bool) []DBFinding {
	var out []DBFinding
	for _, p := range plugins {
		desc := p.Name
		if p.Version != "" {
			desc += " " + p.Version
		}
		if reEpochName.MatchString(p.Slug) {
			out = append(out, DBFinding{Table: "wp-content/plugins", Row: "slug=" + p.Slug, Signature: pluginSigClone, Column: "folder",
				Category: PluginCategory, Snippet: "plugin folder " + p.Slug + " (" + desc + ") is named with a Unix time, as kits clone themselves"})
			continue
		}
		if baseline == nil || baseline[p.Slug] {
			continue
		}
		why := ""
		switch {
		case p.Latest == "":
			why = "not a wordpress.org plugin"
		case p.Version != "" && CompareVersions(p.Version, p.Latest) > 0:
			why = "claims version " + p.Version + ", newer than wordpress.org's " + p.Latest
		}
		if why != "" {
			out = append(out, DBFinding{Table: "wp-content/plugins", Row: "slug=" + p.Slug, Signature: pluginSigNew, Column: "folder",
				Category: PluginCategory, Snippet: "new plugin " + p.Slug + " (" + desc + "): " + why + "; check who installed it"})
		}
		if len(out) == 20 {
			break
		}
	}
	return out
}

// watchPlugins reports a site's new unknown plugins (the first listing
// becomes the baseline) and records them like database findings.
func (m *Manager) watchPlugins(s Site) {
	if s.Type != WordPress {
		return
	}
	var baseline map[string]bool
	if rows, err := m.DB.Query(`SELECT slug FROM cms_plugin_base WHERE site_path = ?`, s.Path); err == nil {
		for rows.Next() {
			var slug string
			if rows.Scan(&slug) == nil {
				if baseline == nil {
					baseline = map[string]bool{}
				}
				baseline[slug] = true
			}
		}
		rows.Close()
	}
	// wordpress.org did not answer (no plugin has a release version): every
	// plugin would look unknown, and earlier rows would read as removed.
	if lookupsFailed(s.Plugins) {
		return
	}
	found := pluginFindings(s.Plugins, baseline)
	if baseline == nil {
		tx, err := m.DB.Begin()
		if err == nil {
			_, _ = tx.Exec(`INSERT OR IGNORE INTO cms_plugin_base (site_path, slug) VALUES (?, '')`, s.Path)
			for _, p := range s.Plugins {
				if !reEpochName.MatchString(p.Slug) {
					_, _ = tx.Exec(`INSERT OR IGNORE INTO cms_plugin_base (site_path, slug) VALUES (?, ?)`, s.Path, p.Slug)
				}
			}
			_ = tx.Commit()
		}
	}
	m.recordWatch(s, PluginCategory, found)
}

// WatchPluginsAt lists a stored site's plugins again and runs the plugin
// watch (no updates, no saving: the nightly scan does those).
func (m *Manager) WatchPluginsAt(ctx context.Context, path string) {
	sites, _, err := m.Sites(SiteFilter{Type: WordPress, Path: path, Limit: 1})
	if err != nil || len(sites) != 1 {
		return
	}
	s := sites[0]
	s.Plugins = Plugins(s.Path)
	for i := range s.Plugins {
		if m.Versions != nil {
			s.Plugins[i].Latest = m.Versions.Latest(ctx, "wp-plugin", s.Plugins[i].Slug)
		}
	}
	m.watchPlugins(s)
}

// lookupsFailed: three or more plugins and none known to wordpress.org,
// which every site with a few plugins has (akismet, contact-form-7...).
func lookupsFailed(plugins []Component) bool {
	if len(plugins) < 3 {
		return false
	}
	for _, p := range plugins {
		if p.Latest != "" {
			return false
		}
	}
	return true
}

// recordWatch stores what a watch found for a site: rows no longer found
// are "cleaned" (the plugin was removed), archived rows stay archived, and
// only new rows notify.
func (m *Manager) recordWatch(s Site, category string, found []DBFinding) {
	known := map[string]bool{}
	if rows, err := m.DB.Query(`SELECT tbl, row_ref, signature FROM db_findings WHERE site_path = ? AND category = ? AND status IN ('detected','archived')`, s.Path, category); err == nil {
		for rows.Next() {
			var t, r, sig string
			if rows.Scan(&t, &r, &sig) == nil {
				known[t+"\x00"+r+"\x00"+sig] = true
			}
		}
		rows.Close()
	}
	_, _ = m.DB.Exec(`UPDATE db_findings SET status = 'cleaned' WHERE site_path = ? AND category = ? AND status = 'detected'`, s.Path, category)
	for _, f := range found {
		now := store.Now()
		_, err := m.DB.Exec(`INSERT INTO db_findings (at, site_path, user, db_name, tbl, row_ref, signature, status, column_name, category, snippet, first_seen)
			VALUES (?,?,?,'',?,?,?,'detected',?,?,?,?)
			ON CONFLICT(site_path, tbl, row_ref, signature) DO UPDATE SET at = excluded.at, snippet = excluded.snippet,
				status = CASE WHEN db_findings.status = 'archived' THEN 'archived' ELSE 'detected' END`,
			now, s.Path, s.User, f.Table, f.Row, f.Signature, f.Column, f.Category, f.Snippet, now)
		if err == nil && m.OnFinding != nil && !known[f.Table+"\x00"+f.Row+"\x00"+f.Signature] {
			m.OnFinding(s, f)
		}
	}
}

// watchCategory: findings of the watches, not database infections; never
// cleaned.
func watchCategory(c string) bool {
	return c == AdminCategory || c == PluginCategory || c == IntegrityCategory
}

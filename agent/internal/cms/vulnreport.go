package cms

import (
	"sort"
	"strings"

	"github.com/xmarthost/xmartguard/agent/internal/store"
)

// VulnReport summarises how the vulnerable plugins, themes and cores of
// the stored inventory stand, and what the automatic updates did with the
// ones they tried (cms_update_try keys): the owner's question of
// 2026-11-12, "did the old system really patch the hacked plugins?".
type VulnReport struct {
	Sites         int `json:"sites"`
	Components    int `json:"components"`     // plugins + themes + cores listed
	Vulnerable    int `json:"vulnerable"`     // with a known hole now
	SitesAffected int `json:"sites_affected"` // sites with at least one
	// Now, by what can be done about them.
	Fixable      int `json:"fixable"`         // a newer release exists
	DueNotPatch  int `json:"due_not_patched"` // the policy would update it, still vulnerable
	SiteDownDue  int `json:"site_down_due"`   // due, but the site's database does not answer (wp-cli cannot run)
	BelowPolicy  int `json:"below_policy"`    // fix exists, but the score or age is under the setting
	NoUpdate     int `json:"no_update"`       // not on wordpress.org (premium, custom): wp-cli cannot update
	NoFix        int `json:"no_fix"`          // no fixed release yet
	ExcludedUser int `json:"excluded_user"`   // the account is excluded from automatic patches
	Suspended    int `json:"suspended"`       // the panel suspended the account: nothing is served
	// By the highest score of each vulnerable component.
	Critical int `json:"critical"` // 9+
	High     int `json:"high"`     // 7-8.9
	Medium   int `json:"medium"`   // 4-6.9
	Low      int `json:"low"`      // under 4 or no score
	// Automatic update attempts remembered (one per site, component and
	// old version; kept until the next attempt).
	Tried    int     `json:"tried"`
	Updated  int     `json:"updated"`   // the version changed since
	Failed   int     `json:"failed"`    // still the same version
	SiteDown int     `json:"site_down"` // same version, the site's database or account is down (not a failed patch)
	Removed  int     `json:"removed"`   // the component or site is gone
	AutoOn   bool    `json:"auto_update"`
	AutoCVSS float64 `json:"auto_update_cvss"`
	AutoDays int     `json:"auto_update_days"`
	// The components most often left vulnerable, and most often failed.
	TopOpen   []VulnItem `json:"top_open"`
	TopFailed []VulnItem `json:"top_failed"`
}

// VulnItem is one component across sites.
type VulnItem struct {
	Kind  string  `json:"kind"`
	Slug  string  `json:"slug"`
	Sites int     `json:"sites"`
	CVSS  float64 `json:"cvss"`
	Why   string  `json:"why,omitempty"`
}

func (m *Manager) VulnReport() (VulnReport, error) {
	cfg := m.Settings.Get().CMS
	r := VulnReport{AutoOn: cfg.AutoUpdate, AutoCVSS: cfg.AutoUpdateCVSS, AutoDays: cfg.AutoUpdateDays}
	sites, _, err := m.Sites(SiteFilter{Type: WordPress, Limit: -1})
	if err != nil {
		return r, err
	}
	now := store.Now()
	type key struct{ kind, slug string }
	open := map[key]*VulnItem{}
	installed := map[string]map[string]string{} // path -> kind|slug -> version
	excluded := map[string]bool{}
	for _, u := range cfg.ExcludeUsers {
		excluded[u] = true
	}
	down := map[string]bool{}
	if rows, err := m.DB.Query(`SELECT key FROM kv WHERE key LIKE ?`, siteDownKV+"%"); err == nil {
		for rows.Next() {
			var k string
			if rows.Scan(&k) == nil {
				down[strings.TrimPrefix(k, siteDownKV)] = true
			}
		}
		rows.Close()
	}
	owner := map[string]string{}
	susp := map[string]bool{}
	isSusp := func(u string) bool {
		v, ok := susp[u]
		if !ok {
			v = m.suspended(u)
			susp[u] = v
		}
		return v
	}
	for _, s := range sites {
		r.Sites++
		inst := map[string]string{}
		installed[s.Path] = inst
		owner[s.Path] = s.User
		comps := []struct {
			kind string
			c    Component
		}{{"core", Component{Slug: "wordpress", Version: s.Version, Latest: s.Latest, Vulns: s.Core.Vulns}}}
		for _, p := range s.Plugins {
			comps = append(comps, struct {
				kind string
				c    Component
			}{"plugin", p})
		}
		for _, t := range s.Themes {
			comps = append(comps, struct {
				kind string
				c    Component
			}{"theme", t})
		}
		hit := false
		for _, x := range comps {
			r.Components++
			inst[x.kind+"|"+x.c.Slug] = x.c.Version
			if len(x.c.Vulns) == 0 {
				continue
			}
			hit = true
			r.Vulnerable++
			top := maxCVSS(x.c.Vulns)
			switch {
			case top >= 9:
				r.Critical++
			case top >= 7:
				r.High++
			case top >= 4:
				r.Medium++
			default:
				r.Low++
			}
			why := ""
			switch {
			case excluded[s.User]:
				r.ExcludedUser++
				why = "account excluded"
			case isSusp(s.User):
				r.Suspended++
				why = "account suspended"
			case x.c.Latest == "" && x.kind != "core":
				r.NoUpdate++
				why = "not on wordpress.org"
			case CompareVersions(x.c.Version, x.c.Latest) >= 0:
				r.NoFix++
				why = "no fix released"
			case down[s.Path] && autoUpdateDue(cfg, x.c, now):
				r.Fixable++
				r.SiteDownDue++
				why = "site database down"
			case autoUpdateDue(cfg, x.c, now):
				r.Fixable++
				r.DueNotPatch++
				why = "update due, not applied"
			default:
				r.Fixable++
				r.BelowPolicy++
				why = "under the automatic update setting"
			}
			k := key{x.kind, x.c.Slug}
			it := open[k]
			if it == nil {
				it = &VulnItem{Kind: x.kind, Slug: x.c.Slug, Why: why}
				open[k] = it
			}
			it.Sites++
			it.CVSS = max(it.CVSS, top)
		}
		if hit {
			r.SitesAffected++
		}
	}
	failed := map[key]*VulnItem{}
	rows, err := m.DB.Query(`SELECT key FROM kv WHERE key LIKE 'cms_update_try|%'`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var k string
			if rows.Scan(&k) != nil {
				continue
			}
			// cms_update_try|<path>|<kind>|<slug>|<version>
			parts := strings.Split(k, "|")
			if len(parts) < 5 {
				continue
			}
			ver, slug, kind := parts[len(parts)-1], parts[len(parts)-2], parts[len(parts)-3]
			path := strings.Join(parts[1:len(parts)-3], "|")
			r.Tried++
			inst, ok := installed[path]
			cur, has := inst[kind+"|"+slug]
			switch {
			case !ok || !has:
				r.Removed++
			case cur == ver && (down[path] || isSusp(owner[path])):
				r.SiteDown++
			case cur == ver:
				r.Failed++
				fk := key{kind, slug}
				if failed[fk] == nil {
					failed[fk] = &VulnItem{Kind: kind, Slug: slug}
				}
				failed[fk].Sites++
			default:
				r.Updated++
			}
		}
	}
	r.TopOpen = topItems(open, 25)
	r.TopFailed = topItems(failed, 15)
	return r, nil
}

func topItems[K comparable](m map[K]*VulnItem, n int) []VulnItem {
	out := make([]VulnItem, 0, len(m))
	for _, it := range m {
		out = append(out, *it)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Sites != out[j].Sites {
			return out[i].Sites > out[j].Sites
		}
		return out[i].CVSS > out[j].CVSS
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

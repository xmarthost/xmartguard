package cms

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"

	"github.com/xmarthost/xmartguard/agent/internal/store"
)

// Fast response to new plugin vulnerabilities (owner, 2026-11-12). The
// full scan runs every 72 hours to spare the servers; a plugin that is
// being exploited cannot wait that long. The portal reads the Wordfence
// feed every few hours and sends the new advisories; Rapid matches them
// against the last scan's inventory (no new scan) and acts on the affected
// sites at once: update; if the vulnerable version stays (premium, no fix,
// update refused), shield the plugin's folder (.htaccess: its PHP files
// cannot be requested directly) and, for a critical hole, deactivate it.
// The shield goes when the plugin is updated.

// Advisory is one vulnerability of one component, from the portal.
type Advisory struct {
	ID      string   `json:"id"`
	Kind    string   `json:"kind"` // plugin | theme | core
	Slug    string   `json:"slug"`
	Title   string   `json:"title"`
	CVSS    float64  `json:"cvss"`
	Ranges  []VRange `json:"ranges"`
	Patched []string `json:"patched"`
	Seq     int64    `json:"seq,omitempty"` // the portal's number (for its report)
}

// VRange is an affected version range ("*" or "" = open end).
type VRange struct {
	From    string `json:"from"`
	FromInc bool   `json:"from_inc"`
	To      string `json:"to"`
	ToInc   bool   `json:"to_inc"`
}

func openEnd(v string) bool { return v == "" || v == "*" }

// Affects reports whether version is in one of the ranges.
func (a Advisory) Affects(version string) bool {
	if version == "" {
		return false
	}
	for _, r := range a.Ranges {
		lo := openEnd(r.From) || CompareVersions(version, r.From) > 0 || (r.FromInc && CompareVersions(version, r.From) == 0)
		hi := openEnd(r.To) || CompareVersions(version, r.To) < 0 || (r.ToInc && CompareVersions(version, r.To) == 0)
		if lo && hi {
			return true
		}
	}
	return false
}

// fixFor is the lowest patched release above version ("" none).
func (a Advisory) fixFor(version string) string {
	fix := ""
	for _, p := range a.Patched {
		if CompareVersions(p, version) > 0 && (fix == "" || CompareVersions(p, fix) < 0) {
			fix = p
		}
	}
	return fix
}

// rapidCritical is the score from which an unfixable plugin is deactivated.
const rapidCritical = 9.0

// Rapid acts on the sites the advisories affect and returns how many
// sites it touched.
func (m *Manager) Rapid(ctx context.Context, advs []Advisory) int {
	cfg := m.Settings.Get().CMS
	if !cfg.Enabled || !cfg.Rapid || len(advs) == 0 {
		return 0
	}
	byKey := map[string][]Advisory{}
	for _, a := range advs {
		// Unscored new holes count: many get their score days later.
		if a.CVSS > 0 && a.CVSS < cfg.RapidCVSS {
			continue
		}
		byKey[a.Kind+"|"+strings.ToLower(a.Slug)] = append(byKey[a.Kind+"|"+strings.ToLower(a.Slug)], a)
	}
	if len(byKey) == 0 {
		return 0
	}
	sites, _, err := m.Sites(SiteFilter{Type: WordPress, Limit: -1})
	if err != nil {
		m.Log.Warn("fast vulnerability check: sites not listed", "err", err)
		return 0
	}
	touched := 0
	for _, s := range sites {
		if ctx.Err() != nil {
			break
		}
		if slices.Contains(cfg.ExcludeUsers, s.User) {
			continue
		}
		if acts := m.rapidSite(ctx, s, byKey, cfg.RapidDeactivate); len(acts) > 0 {
			touched++
			if m.OnAutoAction != nil {
				m.OnAutoAction(s, acts)
			}
			m.refresh(ctx, s) // the list shows the site as it is now
		}
	}
	return touched
}

func (m *Manager) rapidSite(ctx context.Context, s Site, byKey map[string][]Advisory, deactivate bool) []string {
	wp := m.WPCLI
	if m.RunWPCLI != nil {
		wp = m.RunWPCLI
	}
	var done []string
	type comp struct {
		kind string
		c    Component
	}
	comps := []comp{{"core", Component{Slug: "wordpress", Version: s.Version, Latest: s.Latest}}}
	for _, p := range s.Plugins {
		comps = append(comps, comp{"plugin", p})
	}
	for _, t := range s.Themes {
		comps = append(comps, comp{"theme", t})
	}
	for _, x := range comps {
		for _, a := range byKey[x.kind+"|"+strings.ToLower(x.c.Slug)] {
			if !a.Affects(x.c.Version) {
				continue
			}
			key := "cms_rapid|" + s.Path + "|" + x.kind + "|" + x.c.Slug + "|" + x.c.Version + "|" + a.ID
			if store.GetKV(m.DB, key) != "" {
				continue
			}
			_ = store.SetKV(m.DB, key, fmt.Sprint(store.Now()))
			label := fmt.Sprintf("%s %s %s (%s, CVSS %.1f)", x.kind, x.c.Slug, x.c.Version, a.Title, a.CVSS)
			res := RapidResult{Advisory: a.ID, Title: a.Title, CVSS: a.CVSS, Path: s.Path, Domain: s.Domain, User: s.User, Kind: x.kind, Slug: x.c.Slug, Version: x.c.Version}
			// 1. Update.
			var args []string
			to := ""
			switch x.kind {
			case "core":
				args, to = []string{"core", "update", "--minor"}, "its security release"
			default:
				fix := a.fixFor(x.c.Version)
				args, to = UpdateArgs(x.kind, Component{Slug: x.c.Slug, Version: x.c.Version, Latest: x.c.Latest, Vulns: []Vuln{{FixedIn: fix}}})
				if fix != "" && x.c.Latest == "" {
					args, to = []string{x.kind, "update", x.c.Slug}, fix
				}
			}
			out, err := wp(ctx, s.Path, args...)
			now := m.currentVersion(ctx, wp, s.Path, x.kind, x.c.Slug)
			if err == nil && !notUpdated(out) && now != "" && !a.Affects(now) {
				done = append(done, fmt.Sprintf("updated vulnerable %s → %s right after it was disclosed", label, now))
				res.Action, res.ToVersion = RapidUpdated, now
				m.logRapid(res)
				continue
			}
			res.Detail = updateFailure(out, err, x.c.Latest == "" && x.kind != "core")
			if x.kind != "plugin" {
				done = append(done, fmt.Sprintf("vulnerable %s could not be updated to %s: update it by hand", label, to))
				res.Action = RapidManual
				m.logRapid(res)
				continue
			}
			// 2. Shield the folder; 3. deactivate a critical one.
			dir := filepath.Join(s.Path, "wp-content", "plugins", x.c.Slug)
			res.Action = RapidFailed
			if err := Shield(dir, a.ID, x.c.Version); err != nil {
				m.Log.Warn("plugin shield not written", "dir", dir, "err", err)
				res.Detail += "; shield not written: " + err.Error()
			} else {
				res.Action = RapidShielded
				done = append(done, fmt.Sprintf("vulnerable %s could not be updated: its PHP files are shielded from direct requests until it is updated", label))
			}
			if deactivate && (a.CVSS >= rapidCritical || a.CVSS == 0) && x.c.Active {
				if _, err := wp(ctx, s.Path, "plugin", "deactivate", x.c.Slug); err == nil {
					done = append(done, fmt.Sprintf("deactivated critical vulnerable %s (no update could be installed); activate it again after updating it", label))
					if res.Action == RapidShielded {
						res.Action = RapidShieldedDeactivated
					} else {
						res.Action = RapidDeactivated
					}
				}
			}
			m.logRapid(res)
		}
	}
	return done
}

// currentVersion asks wp-cli for a component's installed version.
func (m *Manager) currentVersion(ctx context.Context, wp func(context.Context, string, ...string) (string, error), path, kind, slug string) string {
	var out string
	var err error
	if kind == "core" {
		out, err = wp(ctx, path, "core", "version")
	} else {
		out, err = wp(ctx, path, kind, "get", slug, "--field=version")
	}
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

const (
	shieldBegin = "# BEGIN xPGuard shield"
	shieldEnd   = "# END xPGuard shield"
)

var reShield = regexp.MustCompile(`(?s)# BEGIN xPGuard shield\n.*?# END xPGuard shield\n?`)
var reShieldVer = regexp.MustCompile(`# xPGuard: \S+ version (\S+)`)

// shieldBlock refuses direct requests to the folder's PHP files (Apache
// 2.2/2.4, LiteSpeed; read at request time, no web server reload).
func shieldBlock(id, version string) string {
	return shieldBegin + "\n# xPGuard: " + id + " version " + version + " is vulnerable and could not be updated.\n" +
		"# Removed by xPGuard when the plugin is updated.\n" +
		"<FilesMatch \"\\.(?i:php[0-9]?|phtml|phar|pht)$\">\n" +
		"<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n" +
		"<IfModule !mod_authz_core.c>\nOrder allow,deny\nDeny from all\n</IfModule>\n" +
		"</FilesMatch>\n" + shieldEnd + "\n"
}

// Shield adds the block to the plugin folder's .htaccess (created when
// missing, owned by the folder's owner), safely: the folder must be a real
// folder, the file is never followed through a symlink.
func Shield(dir, id, version string) error {
	st, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s: not a folder", dir)
	}
	p := filepath.Join(dir, ".htaccess")
	f, err := os.OpenFile(p, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	fst, err := f.Stat()
	if err != nil || !fst.Mode().IsRegular() || fst.Size() > MaxConfigSize {
		return fmt.Errorf("%s: not a small regular file", p)
	}
	old, _ := io.ReadAll(f)
	text := reShield.ReplaceAllString(string(old), "")
	if text != "" && !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	text += shieldBlock(id, version)
	if err := f.Truncate(0); err != nil {
		return err
	}
	if _, err := f.WriteAt([]byte(text), 0); err != nil {
		return err
	}
	if uid, ok := fileUID(st); ok {
		if s, ok := st.Sys().(*syscall.Stat_t); ok {
			_ = f.Chown(int(uid), int(s.Gid))
		}
	}
	return f.Close()
}

// unshield removes the block when the plugin's version is no longer the
// shielded one (updated); it reports whether it removed one.
func unshield(dir, version string) bool {
	p := filepath.Join(dir, ".htaccess")
	b, err := ReadUserFile(p, MaxConfigSize)
	if err != nil || !strings.Contains(string(b), shieldBegin) {
		return false
	}
	m := reShieldVer.FindStringSubmatch(string(b))
	if m != nil && m[1] == version {
		return false
	}
	text := reShield.ReplaceAllString(string(b), "")
	if strings.TrimSpace(text) == "" {
		return os.Remove(p) == nil
	}
	f, _, err := openUserFile(p, os.O_WRONLY, -1)
	if err != nil {
		return false
	}
	defer f.Close()
	if f.Truncate(0) != nil {
		return false
	}
	_, err = f.WriteAt([]byte(text), 0)
	return err == nil
}

// unshieldUpdated lifts the shields of a site's updated plugins.
func unshieldUpdated(s *Site) []string {
	var out []string
	for _, p := range s.Plugins {
		if unshield(filepath.Join(s.Path, "wp-content", "plugins", p.Slug), p.Version) {
			out = append(out, "removed the shield of updated plugin "+p.Slug+" "+p.Version)
		}
	}
	return out
}

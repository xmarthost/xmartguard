package cms

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/store"
)

// Vuln is one known vulnerability of a plugin, theme or core version.
type Vuln struct {
	ID      string  `json:"id"` // CVE id when there is one
	Title   string  `json:"title"`
	CVSS    float64 `json:"cvss"`
	FixedIn string  `json:"fixed_in"` // "" when there is no fix yet
	Date    int64   `json:"date"`     // disclosure date (unix)
	Link    string  `json:"link"`
}

// VulnDB looks components up in WPVulnerability (wpvulnerability.net, a
// free public database, no API key), caching answers for a day.
type VulnDB struct {
	DB     *sql.DB
	Client *http.Client
	Base   string // overridable in tests
}

func NewVulnDB(db *sql.DB) *VulnDB {
	return &VulnDB{DB: db, Client: &http.Client{Timeout: 20 * time.Second}, Base: "https://www.wpvulnerability.net"}
}

// wpvFlex accepts a JSON string or number.
type wpvFlex string

func (f *wpvFlex) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "null" {
		s = ""
	}
	*f = wpvFlex(s)
	return nil
}

type wpvResponse struct {
	Error int `json:"error"`
	Data  struct {
		Vulnerability []struct {
			Name     string `json:"name"`
			Operator struct {
				MinVersion  wpvFlex `json:"min_version"`
				MinOperator wpvFlex `json:"min_operator"`
				MaxVersion  wpvFlex `json:"max_version"`
				MaxOperator wpvFlex `json:"max_operator"`
				Unfixed     wpvFlex `json:"unfixed"`
			} `json:"operator"`
			Source []struct {
				ID   string `json:"id"`
				Link string `json:"link"`
				Date string `json:"date"`
			} `json:"source"`
			Impact struct {
				CVSS struct {
					Score wpvFlex `json:"score"`
				} `json:"cvss"`
			} `json:"impact"`
		} `json:"vulnerability"`
	} `json:"data"`
}

// raw fetches (or reads from cache) the vulnerability list of one component.
func (v *VulnDB) raw(ctx context.Context, kind, slug string) (*wpvResponse, error) {
	key := kind + ":" + slug
	var body string
	var at int64
	if v.DB.QueryRow(`SELECT body, fetched_at FROM cms_vulns WHERE key = ?`, key).Scan(&body, &at) == nil && store.Now()-at < 86400 {
		var r wpvResponse
		if json.Unmarshal([]byte(body), &r) == nil {
			return &r, nil
		}
	}
	u := fmt.Sprintf("%s/%s/%s/", v.Base, kind, url.PathEscape(slug))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	res, err := v.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if err != nil || res.StatusCode != 200 {
		return nil, fmt.Errorf("wpvulnerability: HTTP %d", res.StatusCode)
	}
	var r wpvResponse
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, err
	}
	_, _ = v.DB.Exec(`INSERT INTO cms_vulns (key, body, fetched_at) VALUES (?,?,?)
		ON CONFLICT(key) DO UPDATE SET body = excluded.body, fetched_at = excluded.fetched_at`, key, string(raw), store.Now())
	return &r, nil
}

func cmpOp(ver, op, bound string) bool {
	c := CompareVersions(ver, bound)
	switch op {
	case "lt":
		return c < 0
	case "le":
		return c <= 0
	case "gt":
		return c > 0
	case "ge":
		return c >= 0
	case "eq":
		return c == 0
	}
	return true
}

// Affecting returns the vulnerabilities affecting a version. kind is
// plugin, theme or core (slug is ignored for core; pass the version).
func (v *VulnDB) Affecting(ctx context.Context, kind, slug, version string) ([]Vuln, error) {
	if version == "" {
		return nil, nil
	}
	name := slug
	if kind == "core" {
		name = version
	}
	r, err := v.raw(ctx, kind, name)
	if err != nil {
		return nil, err
	}
	var out []Vuln
	for _, x := range r.Data.Vulnerability {
		op := x.Operator
		if kind != "core" {
			if op.MinVersion != "" && !cmpOp(version, string(op.MinOperator), string(op.MinVersion)) {
				continue
			}
			if op.MaxVersion != "" && !cmpOp(version, string(op.MaxOperator), string(op.MaxVersion)) {
				continue
			}
		}
		vu := Vuln{Title: x.Name}
		vu.CVSS, _ = strconv.ParseFloat(string(x.Impact.CVSS.Score), 64)
		if op.Unfixed != "1" && string(op.MaxOperator) == "lt" {
			vu.FixedIn = string(op.MaxVersion)
		}
		for _, s := range x.Source {
			if vu.ID == "" || strings.HasPrefix(s.ID, "CVE-") {
				vu.ID, vu.Link = s.ID, s.Link
			}
			if t, err := time.Parse("2006-01-02", s.Date); err == nil && (vu.Date == 0 || t.Unix() < vu.Date) {
				vu.Date = t.Unix()
			}
		}
		out = append(out, vu)
	}
	return out, nil
}

// maxCVSS returns the highest score in a list.
func maxCVSS(vs []Vuln) float64 {
	m := 0.0
	for _, v := range vs {
		m = max(m, v.CVSS)
	}
	return m
}

// ------------------------------------------------------------ automation

var reCronDefine = regexp.MustCompile(`(?m)^\s*define\s*\(\s*['"]DISABLE_WP_CRON['"]`)

// EnsureRealCron replaces page-load wp-cron with a real cron job for the
// site owner (cPGuard's "Override wordpress wp-cron.php"): it adds
// DISABLE_WP_CRON to wp-config.php and a crontab entry running wp-cron.php
// every N hours. It returns true when it changed something.
func EnsureRealCron(site, owner string, hours int) (bool, error) {
	if owner == "" || strings.ContainsAny(owner, " /;&|$`") {
		return false, fmt.Errorf("invalid owner")
	}
	cfgPath := filepath.Join(site, "wp-config.php")
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		return false, err
	}
	changed := false
	if !reCronDefine.Match(raw) {
		text := string(raw)
		i := strings.Index(text, "<?php")
		if i < 0 {
			return false, fmt.Errorf("unexpected wp-config.php")
		}
		i += len("<?php")
		text = text[:i] + cronDefineLine + text[i:]
		st, _ := os.Stat(cfgPath)
		if err := os.WriteFile(cfgPath, []byte(text), st.Mode().Perm()); err != nil {
			return false, err
		}
		changed = true
	}
	line := cronLine(site, hours)
	out, _ := exec.Command("crontab", "-u", owner, "-l").Output()
	cur := strings.ReplaceAll(string(out), legacyCronMarker, cronMarker)
	// Keep one line for the site, with the current interval.
	var keep []string
	found := false
	for _, l := range strings.Split(strings.TrimRight(cur, "\n"), "\n") {
		if isOurCronLine(l, site) {
			if !found && l == line {
				keep = append(keep, l)
			}
			found = found || l == line
			continue
		}
		keep = append(keep, l)
	}
	if !found {
		keep = append(keep, line)
	}
	next := strings.TrimLeft(strings.Join(keep, "\n")+"\n", "\n")
	if next == strings.TrimLeft(string(out), "\n") {
		return changed, nil
	}
	if err := installCrontab(owner, next); err != nil {
		return changed, err
	}
	return true, nil
}

// cronLine is the crontab entry for a site. Every site gets its own minute
// and hour from a hash of its path: with "every 24 hours" at 0:00 for all
// of them, hundreds of wp-cron.php runs started at midnight together and
// overloaded the server. It runs at a lower priority (nice) as well.
func cronLine(site string, hours int) string {
	hours = max(1, min(hours, 24))
	php := "/usr/local/bin/php"
	if _, err := os.Stat(php); err != nil {
		php = "php"
	}
	h := fnv.New32a()
	h.Write([]byte(site))
	sum := h.Sum32()
	minute := sum % 60
	hourField := "*"
	if hours > 1 {
		var hs []string
		for x := int(sum/60) % hours; x < 24; x += hours {
			hs = append(hs, strconv.Itoa(x))
		}
		hourField = strings.Join(hs, ",")
	}
	return fmt.Sprintf("%d %s * * * cd %s && nice -n 15 %s -q wp-cron.php >/dev/null 2>&1 %s", minute, hourField, site, php, cronMarker)
}

// RespreadCrons rewrites the wp-cron lines xPGuard added in earlier
// versions (all at minute 0, the 24-hour ones all at midnight) to their
// spread-out times. It returns how many accounts' crontabs changed.
func RespreadCrons(hours int) int {
	files, _ := filepath.Glob(filepath.Join(cronSpool, "*"))
	changed := 0
	for _, f := range files {
		owner := filepath.Base(f)
		raw, err := os.ReadFile(f)
		if err != nil || (!strings.Contains(string(raw), cronMarker) && !strings.Contains(string(raw), legacyCronMarker)) {
			continue
		}
		if strings.ContainsAny(owner, " /;&|$`") {
			continue
		}
		out, err := exec.Command("crontab", "-u", owner, "-l").Output()
		if err != nil {
			continue
		}
		lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
		dirty := false
		for i, l := range lines {
			if !strings.Contains(l, cronMarker) && !strings.Contains(l, legacyCronMarker) {
				continue
			}
			m := reOurCron.FindStringSubmatch(l)
			if m == nil {
				continue
			}
			if want := cronLine(m[1], hours); l != want {
				lines[i], dirty = want, true
			}
		}
		if dirty && installCrontab(owner, strings.Join(lines, "\n")+"\n") == nil {
			changed++
		}
	}
	return changed
}

// cronSpool holds the users' crontabs (RHEL/AlmaLinux; Debian keeps them in
// /var/spool/cron/crontabs).
var cronSpool = func() string {
	if st, err := os.Stat("/var/spool/cron/crontabs"); err == nil && st.IsDir() {
		return "/var/spool/cron/crontabs"
	}
	return "/var/spool/cron"
}()

var reOurCron = regexp.MustCompile(`\bcd (/\S+) && `)

const (
	cronMarker       = "# xpguard-wp-cron"
	legacyCronMarker = "# xmartguard-wp-cron" // before the xPGuard name
	cronDefine       = "// added by xPGuard (real cron job)"
	cronDefineLine   = "\ndefine( 'DISABLE_WP_CRON', true ); " + cronDefine + "\n"
)

func isOurCronLine(l, site string) bool {
	return strings.Contains(l, "cd "+site+" && ") && (strings.Contains(l, cronMarker) || strings.Contains(l, legacyCronMarker))
}

// RemoveRealCron undoes EnsureRealCron (the option was turned off or the
// site was removed): it deletes the crontab line and, when the site still
// exists, the DISABLE_WP_CRON line xPGuard added, so WordPress runs its
// scheduled tasks on page loads again. It returns true when it changed
// something.
func RemoveRealCron(site, owner string) (bool, error) {
	if owner == "" || strings.ContainsAny(owner, " /;&|$`") {
		return false, fmt.Errorf("invalid owner")
	}
	changed := false
	cfgPath := filepath.Join(site, "wp-config.php")
	if raw, err := os.ReadFile(cfgPath); err == nil && strings.Contains(string(raw), cronDefine) {
		text := string(raw)
		if strings.Contains(text, cronDefineLine) {
			text = strings.Replace(text, cronDefineLine, "", 1) // exactly what was inserted
		} else {
			var keep []string
			for _, l := range strings.Split(text, "\n") {
				if !strings.Contains(l, cronDefine) {
					keep = append(keep, l)
				}
			}
			text = strings.Join(keep, "\n")
		}
		st, _ := os.Stat(cfgPath)
		if err := os.WriteFile(cfgPath, []byte(text), st.Mode().Perm()); err != nil {
			return false, err
		}
		changed = true
	}
	out, err := exec.Command("crontab", "-u", owner, "-l").Output()
	if err != nil {
		return changed, nil // no crontab
	}
	var keep []string
	drop := false
	for _, l := range strings.Split(strings.TrimRight(string(out), "\n"), "\n") {
		if isOurCronLine(l, site) {
			drop = true
			continue
		}
		keep = append(keep, l)
	}
	if !drop {
		return changed, nil
	}
	return true, installCrontab(owner, strings.Join(keep, "\n")+"\n")
}

func installCrontab(owner, text string) error {
	cmd := exec.Command("crontab", "-u", owner, "-")
	cmd.Stdin = strings.NewReader(strings.TrimLeft(text, "\n"))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("crontab: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// autoActions applies the automatic CMS policies to one scanned site and
// returns a description of what it did.
func (m *Manager) autoActions(ctx context.Context, s *Site) []string {
	cfg := m.Settings.Get().CMS
	if s.Type != WordPress || slices.Contains(cfg.ExcludeUsers, s.User) {
		return nil
	}
	var done []string
	run := func(desc string, args ...string) {
		if out, err := m.WPCLI(ctx, s.Path, args...); err != nil {
			m.Log.Warn("CMS automatic action failed", "site", s.Path, "action", desc, "err", err)
		} else {
			m.Log.Info("CMS automatic action", "site", s.Path, "action", desc, "out", out)
			done = append(done, desc)
		}
	}
	for _, p := range s.Plugins {
		if p.Active && slices.Contains(cfg.BlacklistPlugins, strings.ToLower(p.Slug)) {
			run("deactivated blacklisted plugin "+p.Slug, "plugin", "deactivate", p.Slug)
		}
	}
	if cfg.AutoUpdate {
		due := func(c Component) bool {
			if len(c.Vulns) == 0 || c.Latest == "" || CompareVersions(c.Version, c.Latest) >= 0 {
				return false
			}
			if cfg.AutoUpdateCVSS > 0 && maxCVSS(c.Vulns) <= cfg.AutoUpdateCVSS {
				return false
			}
			if cfg.AutoUpdateDays > 0 {
				oldest := int64(0)
				for _, v := range c.Vulns {
					if v.Date > 0 && (oldest == 0 || v.Date < oldest) {
						oldest = v.Date
					}
				}
				if oldest == 0 || store.Now()-oldest < int64(cfg.AutoUpdateDays)*86400 {
					return false
				}
			}
			return true
		}
		for _, p := range s.Plugins {
			if due(p) {
				run(fmt.Sprintf("updated vulnerable plugin %s %s → %s", p.Slug, p.Version, p.Latest), "plugin", "update", p.Slug)
			}
		}
		for _, t := range s.Themes {
			if due(t) {
				run(fmt.Sprintf("updated vulnerable theme %s %s → %s", t.Slug, t.Version, t.Latest), "theme", "update", t.Slug)
			}
		}
	}
	// The wp-cron override is a performance setting, not a security fix:
	// it is logged, not reported as a patch (as cPGuard does).
	if cfg.WPCron {
		if changed, err := EnsureRealCron(s.Path, s.User, cfg.WPCronHours); err != nil {
			m.Log.Warn("wp-cron override failed", "site", s.Path, "err", err)
		} else if changed {
			m.Log.Info("wp-cron.php now runs from the account's crontab", "site", s.Path, "every_hours", cfg.WPCronHours)
		}
	} else if changed, err := RemoveRealCron(s.Path, s.User); err == nil && changed {
		m.Log.Info("wp-cron override removed", "site", s.Path)
	}
	return done
}

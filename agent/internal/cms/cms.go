package cms

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/prio"

	"github.com/xmarthost/xmartguard/agent/internal/settings"
	"github.com/xmarthost/xmartguard/agent/internal/store"
)

// Manager scans CMS installations on a schedule and on demand.
type Manager struct {
	// Zone is the time zone of the nightly schedule (nil: the server's).
	Zone     func() *time.Location
	DB       *sql.DB
	Settings *settings.Store
	Log      *slog.Logger
	Versions *Versions
	// Accounts returns the hosting accounts to search.
	Accounts func() []Account
	// Docroots maps document roots to domains ("" -> cPanel userdata).
	Docroots func() map[string]string
	// OnFinding is called for new database infections (notifications).
	OnFinding func(site Site, f DBFinding)
	// Vulns looks up known vulnerabilities (nil = off).
	Vulns *VulnDB
	// OnAutoAction reports automatic updates/deactivations (notifications).
	OnAutoAction func(site Site, actions []string)
	// RunWPCLI replaces wp-cli in tests (nil: WPCLI).
	RunWPCLI func(ctx context.Context, path string, args ...string) (string, error)

	mu      sync.Mutex
	bulk    BulkStatus
	running bool
	last    time.Time
	lastErr string
}

// Site is one stored CMS installation.
type Site struct {
	ID              int64       `json:"id"`
	Type            string      `json:"type"`
	Path            string      `json:"path"`
	User            string      `json:"user"`
	Domain          string      `json:"domain"`
	Version         string      `json:"version"`
	Latest          string      `json:"latest"`
	Plugins         []Component `json:"plugins"`
	Themes          []Component `json:"themes"`
	MUPlugins       []string    `json:"mu_plugins"`
	OutdatedPlugins int         `json:"outdated_plugins"`
	OutdatedThemes  int         `json:"outdated_themes"`
	Core            CoreReport  `json:"core"`
	CoreIssues      int         `json:"core_issues"`
	DBIssues        int         `json:"db_issues"`
	// Vulnerable counts plugins/themes/core with known vulnerabilities.
	Vulnerable int    `json:"vulnerable"`
	Risk       string `json:"risk"`
	ScannedAt  int64  `json:"scanned_at"`
}

// Status reports scan progress.
type Status struct {
	Running  bool   `json:"running"`
	LastScan int64  `json:"last_scan"`
	Error    string `json:"error"`
}

func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	var last int64
	if !m.last.IsZero() {
		last = m.last.Unix()
	}
	if last == 0 {
		last, _ = strconv.ParseInt(store.GetKV(m.DB, "cms_last_scan"), 10, 64)
	}
	return Status{Running: m.running, LastScan: last, Error: m.lastErr}
}

// Start runs a scan in the background (error if one is running).
func (m *Manager) Start() error {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return errors.New("a CMS scan is already running")
	}
	m.running = true
	m.mu.Unlock()
	go func() {
		// Checking hundreds of sites (core file checksums, databases) waits
		// for the websites: lowest CPU and disk priority.
		prio.LowThread()
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Hour)
		defer cancel()
		err := m.scan(ctx)
		m.mu.Lock()
		m.running, m.last, m.lastErr = false, time.Now(), ""
		if err != nil {
			m.lastErr = err.Error()
		}
		m.mu.Unlock()
		_ = store.SetKV(m.DB, "cms_last_scan", strconv.FormatInt(time.Now().Unix(), 10))
	}()
	return nil
}

// kvScanRequested: "Scan now" asked for a full scan, run the next night.
const kvScanRequested = "cms_scan_requested"

// RequestScan queues a full scan for the night (CMS Threat Alerts » Scan
// now): checking hundreds of sites' core files and databases in the day
// slowed the websites. It returns when the scan starts.
func (m *Manager) RequestScan() time.Time {
	_ = store.SetKV(m.DB, kvScanRequested, strconv.FormatInt(time.Now().Unix(), 10))
	return nextNight(time.Now().In(m.zone()))
}

// ScanRequested reports a full scan queued for the night.
func (m *Manager) ScanRequested() bool { return store.GetKV(m.DB, kvScanRequested) != "" }

// nextNight is when the night window starts next (now, inside it).
func nextNight(t time.Time) time.Time {
	if nightHour(t) {
		return t
	}
	n := time.Date(t.Year(), t.Month(), t.Day(), 2, 0, 0, 0, t.Location())
	if !n.After(t) {
		n = n.AddDate(0, 0, 1)
	}
	return n
}

// kvDBRules remembers the database rules version of the last full scan.
const kvDBRules = "db_rules_version"

// Run schedules scans according to settings.
func (m *Manager) Run(ctx context.Context) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(5 * time.Minute):
	}
	t := time.NewTicker(15 * time.Minute)
	defer t.Stop()
	for {
		cfg := m.Settings.Get().CMS
		last, _ := strconv.ParseInt(store.GetKV(m.DB, "cms_last_scan"), 10, 64)
		// New database rules: scan now, so earlier false detections go.
		newRules := cfg.DBScan && store.GetKV(m.DB, kvDBRules) != DBRulesVersion
		// Every check runs at night (2:00-6:00 in the scan schedule's time
		// zone), slowly: the full scan at most once per interval (every 3
		// days by default) or when "Scan now" asked for one, the daily
		// vulnerability check on the other nights.
		requested := store.GetKV(m.DB, kvScanRequested) != ""
		due := newRules || requested || time.Now().Unix()-last >= int64(cfg.IntervalHours)*3600-3*3600
		night := nightHour(time.Now().In(m.zone()))
		if cfg.Enabled && due && night {
			if m.Start() == nil {
				_ = store.SetKV(m.DB, kvScanRequested, "")
			}
		} else if pass, _ := strconv.ParseInt(store.GetKV(m.DB, kvVulnPass), 10, 64); cfg.Enabled && cfg.Vulns && m.Vulns != nil && night &&
			time.Now().Unix()-max(pass, last) >= vulnPassEvery {
			prio.LowThread()
			if err := m.VulnPass(ctx); err != nil && ctx.Err() == nil {
				m.Log.Info("CMS vulnerability check skipped", "err", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// sitePause is the rest between two sites of a scheduled check, and
// idleLoad the load (per CPU) it waits to drop below, up to idleWait.
var (
	sitePause = 2 * time.Second
	idleLoad  = 0.7
	idleWait  = 2 * time.Minute
)

func slowDown(ctx context.Context) {
	prio.WaitIdle(ctx, idleLoad, idleWait)
	select {
	case <-ctx.Done():
	case <-time.After(sitePause):
	}
}

// nightHour: scheduled checks start between 2:00 and 6:00 (the owner's
// choice: 2:00 PKT, when the websites are quietest).
func nightHour(t time.Time) bool { return t.Hour() >= 2 && t.Hour() < 6 }

// zone is the time zone of the night window (Settings » Virus Scanner »
// schedule time zone; the server's own zone when unset).
func (m *Manager) zone() *time.Location {
	if m.Zone != nil {
		return m.Zone()
	}
	return time.Local
}

func risk(s *Site) string {
	switch {
	case s.CoreIssues > 0 || s.DBIssues > 0:
		return "critical"
	case s.Vulnerable > 0 && s.maxCVSS() >= 7:
		return "critical" // a known high-severity hole
	case s.Vulnerable > 0:
		return "high"
	case s.Latest != "" && s.Version != "" && leadingInt(s.Version) < leadingInt(s.Latest):
		return "critical" // a whole major version behind
	case (s.Latest != "" && CompareVersions(s.Version, s.Latest) < 0) || s.OutdatedPlugins >= 5:
		return "high"
	case s.OutdatedPlugins+s.OutdatedThemes > 0:
		return "medium"
	}
	return "ok"
}

func (m *Manager) scan(ctx context.Context) error {
	cfg := m.Settings.Get().CMS
	recheck := store.GetKV(m.DB, kvDBRules) != DBRulesVersion
	docroots := map[string]string{}
	if m.Docroots != nil {
		docroots = m.Docroots()
	}
	installs := Discover(m.Accounts(), docroots)
	seen := map[string]bool{}
	cacheDir := filepath.Join(store.StateDir(), "sigs")
	for _, in := range installs {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// A busy server (websites, MySQL) comes first, and every site is
		// followed by a pause: a slow scan the websites do not feel.
		slowDown(ctx)
		seen[in.Path] = true
		s := Site{Type: in.Type, Path: in.Path, User: in.User, Domain: in.Domain, Version: Version(in),
			Plugins: []Component{}, Themes: []Component{}, MUPlugins: []string{}, Core: CoreReport{Modified: []string{}, Unknown: []string{}}}
		switch in.Type {
		case WordPress:
			m.inventory(ctx, &s)
			if cfg.CoreCheck && s.Version != "" {
				if sums, err := m.Versions.Checksums(ctx, cacheDir, s.Version, Locale(in.Path)); err == nil {
					s.Core = VerifyCore(in.Path, sums)
				} else {
					s.Core.Error = err.Error()
				}
				s.CoreIssues = len(s.Core.Modified) + len(s.Core.Unknown)
			}
			if cfg.DBScan {
				s.DBIssues = m.scanDB(ctx, s, recheck)
			}
		case Joomla:
			s.Latest = m.Versions.Latest(ctx, "joomla", "")
		}
		if s.Type == WordPress && cfg.Vulns && m.Vulns != nil {
			m.lookupVulns(ctx, &s)
		}
		s.Risk = risk(&s)
		if acts := m.autoActions(ctx, &s); len(acts) > 0 && m.OnAutoAction != nil {
			m.OnAutoAction(s, acts)
		}
		s.ScannedAt = store.Now()
		m.save(s)
	}
	// Forget installations that no longer exist.
	rows, err := m.DB.Query(`SELECT path, user FROM cms_sites`)
	if err == nil {
		type site struct{ path, user string }
		var gone []site
		for rows.Next() {
			var x site
			if rows.Scan(&x.path, &x.user) == nil && !seen[x.path] {
				gone = append(gone, x)
			}
		}
		rows.Close()
		for _, x := range gone {
			_, _ = m.DB.Exec(`DELETE FROM cms_sites WHERE path = ?`, x.path)
			// Its wp-cron job would only fail now.
			if x.user != "" {
				_, _ = RemoveRealCron(x.path, x.user)
			}
		}
	}
	if cfg.DBScan {
		_ = store.SetKV(m.DB, kvDBRules, DBRulesVersion)
	}
	return nil
}

// inventory reads a WordPress site's plugins and themes and the newest
// releases of them and of WordPress.
func (m *Manager) inventory(ctx context.Context, s *Site) {
	s.Latest = m.Versions.Latest(ctx, "wp-core", "")
	s.Plugins = Plugins(s.Path)
	s.Themes = Themes(s.Path)
	s.MUPlugins = []string{}
	if mu := MUPlugins(s.Path); mu != nil {
		s.MUPlugins = mu
	}
	s.OutdatedPlugins, s.OutdatedThemes = 0, 0
	for i := range s.Plugins {
		c := &s.Plugins[i]
		c.Latest = m.Versions.Latest(ctx, "wp-plugin", c.Slug)
		if c.Latest != "" && c.Version != "" && CompareVersions(c.Version, c.Latest) < 0 {
			c.Outdated = true
			s.OutdatedPlugins++
		}
	}
	for i := range s.Themes {
		c := &s.Themes[i]
		c.Latest = m.Versions.Latest(ctx, "wp-theme", c.Slug)
		if c.Latest != "" && c.Version != "" && CompareVersions(c.Version, c.Latest) < 0 {
			c.Outdated = true
			s.OutdatedThemes++
		}
	}
}

// vulnPassEvery: the known vulnerabilities of every WordPress site are
// checked (and fixed, with automatic updates on) this often, between the
// full scans (every 3 days by default, with core files and databases):
// new plugin holes are attacked within hours of disclosure.
const vulnPassEvery = 20 * 3600

// refresh re-reads one stored WordPress site's plugins, themes and version
// and its known vulnerabilities, applies the automatic updates and saves it;
// the core file and database results of the last full scan stay.
func (m *Manager) refresh(ctx context.Context, s Site) {
	s.Version = Version(Install{Type: WordPress, Path: s.Path})
	m.inventory(ctx, &s)
	if m.Vulns != nil && m.Settings.Get().CMS.Vulns {
		m.lookupVulns(ctx, &s)
	}
	s.Risk = risk(&s)
	if acts := m.autoActions(ctx, &s); len(acts) > 0 {
		if m.OnAutoAction != nil {
			m.OnAutoAction(s, acts)
		}
		// What the updates left (the list shows the site as it is now).
		s.Version = Version(Install{Type: WordPress, Path: s.Path})
		m.inventory(ctx, &s)
		if m.Vulns != nil && m.Settings.Get().CMS.Vulns {
			m.lookupVulns(ctx, &s)
		}
		s.Risk = risk(&s)
	}
	m.save(s)
}

// RefreshSite re-reads one WordPress site after an update from the portal
// (not a full scan of every site, as before).
func (m *Manager) RefreshSite(ctx context.Context, path string) {
	if sites, _, err := m.Sites(SiteFilter{Type: WordPress, Path: path, Limit: 1}); err == nil && len(sites) == 1 {
		m.refresh(ctx, sites[0])
	}
}

// VulnPass runs refresh for every stored WordPress site.
func (m *Manager) VulnPass(ctx context.Context) error {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return errors.New("a CMS scan is already running")
	}
	m.running = true
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		m.running = false
		m.mu.Unlock()
	}()
	sites, _, err := m.Sites(SiteFilter{Type: WordPress, Limit: -1})
	if err != nil {
		return err
	}
	for _, s := range sites {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		slowDown(ctx)
		if _, err := os.Stat(filepath.Join(s.Path, "wp-includes", "version.php")); err != nil {
			continue // gone: the next full scan forgets it
		}
		m.refresh(ctx, s)
	}
	_ = store.SetKV(m.DB, kvVulnPass, strconv.FormatInt(time.Now().Unix(), 10))
	return nil
}

// kvVulnPass remembers when VulnPass last ran.
const kvVulnPass = "cms_last_vuln_pass"

func (m *Manager) scanDB(ctx context.Context, s Site, recheck bool) int {
	c, err := ReadWPConfig(s.Path)
	if err != nil {
		return 0
	}
	dctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	// A database that did not change since the last check keeps its result:
	// searching posts and postmeta of hundreds of sites every day is the
	// heaviest part of the check for MySQL.
	var prevAt int64
	prevIssues := -1
	_ = m.DB.QueryRow(`SELECT scanned_at, db_issues FROM cms_sites WHERE path = ?`, s.Path).Scan(&prevAt, &prevIssues)
	if !recheck && prevAt > 0 && prevIssues >= 0 {
		if changed, ok := DBChangedSince(dctx, c, prevAt); ok && !changed {
			return prevIssues
		}
	}
	start := time.Now()
	found, err := ScanDatabase(dctx, c)
	// Give MySQL a rest as long as the search took (at most 5 seconds).
	select {
	case <-ctx.Done():
	case <-time.After(min(time.Since(start), 5*time.Second)):
	}
	if err != nil {
		m.Log.Info("database scan skipped", "site", s.Path, "err", err)
		return 0
	}
	// Signatures the admin whitelisted (false positives) are dropped.
	if wl := m.Settings.Get().Scanner.DBWhitelist; len(wl) > 0 {
		skip := map[string]bool{}
		for _, x := range wl {
			skip[x.ID] = true
			skip["DB."+x.ID] = true
		}
		kept := found[:0]
		for _, f := range found {
			if !skip[f.Signature] {
				kept = append(kept, f)
			}
		}
		found = kept
	}
	// Remember what was already known so only new infections notify.
	known := map[string]bool{}
	if rows, err := m.DB.Query(`SELECT tbl, row_ref, signature FROM db_findings WHERE site_path = ? AND status IN ('detected','archived')`, s.Path); err == nil {
		for rows.Next() {
			var t, r, sig string
			if rows.Scan(&t, &r, &sig) == nil {
				known[t+"\x00"+r+"\x00"+sig] = true
			}
		}
		rows.Close()
	}
	// Mark previous findings cleaned; the ones still present are re-detected
	// below. After a change of the rules, what they no longer find was a
	// false positive ("cleared"), not cleaned.
	gone := "cleaned"
	if recheck {
		gone = "cleared"
	}
	_, _ = m.DB.Exec(`UPDATE db_findings SET status = ? WHERE site_path = ? AND status = 'detected'`, gone, s.Path)
	for _, f := range found {
		key := f.Table + "\x00" + f.Row + "\x00" + f.Signature
		// Archived findings stay archived (the admin has seen them).
		now := store.Now()
		_, err := m.DB.Exec(`INSERT INTO db_findings (at, site_path, user, db_name, tbl, row_ref, signature, status, column_name, category, snippet, first_seen)
			VALUES (?,?,?,?,?,?,?,'detected',?,?,?,?)
			ON CONFLICT(site_path, tbl, row_ref, signature) DO UPDATE SET at = excluded.at,
				column_name = excluded.column_name, category = excluded.category, snippet = excluded.snippet,
				first_seen = CASE WHEN db_findings.first_seen = 0 THEN excluded.first_seen ELSE db_findings.first_seen END,
				note = CASE WHEN db_findings.status IN ('detected','archived') THEN db_findings.note ELSE 'found again after it was cleaned' END,
				status = CASE WHEN db_findings.status = 'archived' THEN 'archived' ELSE 'detected' END`,
			now, s.Path, s.User, c.Name, f.Table, f.Row, f.Signature, f.Column, f.Category, f.Snippet, now)
		if err == nil && m.OnFinding != nil && !known[key] {
			m.OnFinding(s, f)
		}
	}
	return len(found)
}

func (m *Manager) save(s Site) {
	j := func(v any) string { b, _ := json.Marshal(v); return string(b) }
	_, err := m.DB.Exec(`INSERT INTO cms_sites (type, path, user, domain, version, latest, plugins, themes, mu_plugins,
			outdated_plugins, outdated_themes, core, core_issues, db_issues, risk, scanned_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(path) DO UPDATE SET type=excluded.type, user=excluded.user, domain=excluded.domain, version=excluded.version,
			latest=excluded.latest, plugins=excluded.plugins, themes=excluded.themes, mu_plugins=excluded.mu_plugins,
			outdated_plugins=excluded.outdated_plugins, outdated_themes=excluded.outdated_themes, core=excluded.core,
			core_issues=excluded.core_issues, db_issues=excluded.db_issues, risk=excluded.risk, scanned_at=excluded.scanned_at`,
		s.Type, s.Path, s.User, s.Domain, s.Version, s.Latest, j(s.Plugins), j(s.Themes), j(s.MUPlugins),
		s.OutdatedPlugins, s.OutdatedThemes, j(s.Core), s.CoreIssues, s.DBIssues, s.Risk, s.ScannedAt)
	if err != nil {
		m.Log.Warn("save cms site", "err", err)
	}
}

// SiteFilter narrows Sites.
type SiteFilter struct {
	// User limits the list to one hosting account (panel users).
	User string `json:"-"`
	// Path is one site (the agent's own use).
	Path string `json:"-"`
	// Account is the portal's filter by hosting account.
	Account string `json:"account"`
	Type    string `json:"type"`
	Risk    string `json:"risk"`
	Query   string `json:"q"`
	Limit   int    `json:"limit"`
	Offset  int    `json:"offset"`
}

// Counts summarises installations for the stat cards.
type Counts struct {
	WithIssues int `json:"with_issues"`
	WordPress  int `json:"wordpress"`
	Joomla     int `json:"joomla"`
	OpenCart   int `json:"opencart"`
	Outdated   int `json:"outdated"`
	DBInfected int `json:"db_infected"`
}

func (m *Manager) Counts() Counts {
	var c Counts
	_ = m.DB.QueryRow(`SELECT count(*) FROM cms_sites WHERE risk != 'ok'`).Scan(&c.WithIssues)
	_ = m.DB.QueryRow(`SELECT count(*) FROM cms_sites WHERE type = 'wordpress'`).Scan(&c.WordPress)
	_ = m.DB.QueryRow(`SELECT count(*) FROM cms_sites WHERE type = 'joomla'`).Scan(&c.Joomla)
	_ = m.DB.QueryRow(`SELECT count(*) FROM cms_sites WHERE type = 'opencart'`).Scan(&c.OpenCart)
	_ = m.DB.QueryRow(`SELECT count(*) FROM cms_sites WHERE outdated_plugins + outdated_themes > 0 OR (latest != '' AND version != latest)`).Scan(&c.Outdated)
	_ = m.DB.QueryRow(`SELECT count(*) FROM db_findings WHERE status = 'detected'`).Scan(&c.DBInfected)
	return c
}

// Sites lists installations, most at-risk first.
func (m *Manager) Sites(f SiteFilter) ([]Site, int, error) {
	where, args := []string{"1=1"}, []any{}
	if f.Type != "" {
		where, args = append(where, "type = ?"), append(args, f.Type)
	}
	if f.User != "" {
		where, args = append(where, "user = ?"), append(args, f.User)
	} else if f.Account != "" {
		where, args = append(where, "user = ?"), append(args, f.Account)
	}
	if f.Risk != "" {
		where, args = append(where, "risk = ?"), append(args, f.Risk)
	}
	if f.Path != "" {
		where, args = append(where, "path = ?"), append(args, f.Path)
	}
	if f.Query != "" {
		where, args = append(where, "(domain LIKE ? OR path LIKE ? OR user LIKE ?)"), append(args, "%"+f.Query+"%", "%"+f.Query+"%", "%"+f.Query+"%")
	}
	switch {
	case f.Limit < 0:
		f.Limit = -1 // all (the agent's own passes)
	case f.Limit == 0 || f.Limit > 500:
		f.Limit = 25
	}
	cond := strings.Join(where, " AND ")
	var total int
	if err := m.DB.QueryRow(`SELECT count(*) FROM cms_sites WHERE `+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := m.DB.Query(`SELECT id, type, path, user, domain, version, latest, plugins, themes, mu_plugins, outdated_plugins,
			outdated_themes, core, core_issues, db_issues, risk, scanned_at FROM cms_sites WHERE `+cond+`
		ORDER BY CASE risk WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
		         outdated_plugins + outdated_themes DESC, domain LIMIT ? OFFSET ?`, append(args, f.Limit, f.Offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []Site{}
	for rows.Next() {
		var s Site
		var pl, th, mu, core string
		if err := rows.Scan(&s.ID, &s.Type, &s.Path, &s.User, &s.Domain, &s.Version, &s.Latest, &pl, &th, &mu,
			&s.OutdatedPlugins, &s.OutdatedThemes, &core, &s.CoreIssues, &s.DBIssues, &s.Risk, &s.ScannedAt); err != nil {
			return nil, 0, err
		}
		_ = json.Unmarshal([]byte(pl), &s.Plugins)
		_ = json.Unmarshal([]byte(th), &s.Themes)
		_ = json.Unmarshal([]byte(mu), &s.MUPlugins)
		_ = json.Unmarshal([]byte(core), &s.Core)
		s.countVulns()
		out = append(out, s)
	}
	return out, total, rows.Err()
}

// DBRow is a stored database finding.
type DBRow struct {
	ID        int64  `json:"id"`
	At        int64  `json:"at"`
	SitePath  string `json:"site_path"`
	User      string `json:"user"`
	Database  string `json:"database"`
	Table     string `json:"table"`
	Row       string `json:"row"`
	Signature string `json:"signature"`
	Status    string `json:"status"`
	Column    string `json:"column"`
	Category  string `json:"category"`
	Snippet   string `json:"snippet"`
	FirstSeen int64  `json:"first_seen"`
	Note      string `json:"note,omitempty"`
	// Restorable: the value from before an xPGuard clean is saved.
	Restorable bool `json:"restorable,omitempty"`
}

// DBFindings lists database infections.
func (m *Manager) DBFindings(status, q string, limit, offset int) ([]DBRow, int, error) {
	where, args := []string{"1=1"}, []any{}
	if status != "" {
		where, args = append(where, "status = ?"), append(args, status)
	}
	if q != "" {
		where, args = append(where, "(db_name LIKE ? OR tbl LIKE ? OR signature LIKE ? OR user LIKE ? OR snippet LIKE ?)"), append(args, "%"+q+"%", "%"+q+"%", "%"+q+"%", "%"+q+"%", "%"+q+"%")
	}
	if limit <= 0 || limit > 1000 {
		limit = 25
	}
	cond := strings.Join(where, " AND ")
	var total int
	if err := m.DB.QueryRow(`SELECT count(*) FROM db_findings WHERE `+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := m.DB.Query(`SELECT id, at, site_path, user, db_name, tbl, row_ref, signature, status, column_name, category, snippet, first_seen, note,
		EXISTS(SELECT 1 FROM db_clean_backup b WHERE b.finding_id = db_findings.id) FROM db_findings WHERE `+cond+
		` ORDER BY id DESC LIMIT ? OFFSET ?`, append(args, limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []DBRow{}
	for rows.Next() {
		var r DBRow
		if err := rows.Scan(&r.ID, &r.At, &r.SitePath, &r.User, &r.Database, &r.Table, &r.Row, &r.Signature, &r.Status, &r.Column, &r.Category, &r.Snippet, &r.FirstSeen, &r.Note, &r.Restorable); err != nil {
			return nil, 0, err
		}
		out = append(out, r)
	}
	return out, total, rows.Err()
}

// ArchiveDBFindings hides handled findings from the default view.
func (m *Manager) ArchiveDBFindings(ids []int64) (int, error) {
	n := 0
	for _, id := range ids {
		res, err := m.DB.Exec(`UPDATE db_findings SET status = 'archived' WHERE id = ?`, id)
		if err != nil {
			return n, err
		}
		k, _ := res.RowsAffected()
		n += int(k)
	}
	return n, nil
}

// ---- WP-CLI actions

// wpCLI returns a command prefix that runs WP-CLI, or an error.
func wpCLI() ([]string, error) {
	if p, err := exec.LookPath("wp"); err == nil {
		return []string{p}, nil
	}
	for _, p := range []string{"/usr/local/bin/wp", "/opt/xpguard/bin/wp-cli.phar"} {
		if _, err := os.Stat(p); err == nil {
			php := "php"
			for _, c := range []string{"/usr/local/bin/php", "/usr/bin/php"} {
				if _, err := os.Stat(c); err == nil {
					php = c
					break
				}
			}
			return []string{php, p}, nil
		}
	}
	return nil, errors.New("WP-CLI is not installed on this server (install it as /usr/local/bin/wp)")
}

// Update updates a WordPress component as the site owner. what is
// core | plugin | theme; slug is required for plugin/theme.
func (m *Manager) Update(ctx context.Context, path, what, slug string) (string, error) {
	var args []string
	switch what {
	case "core":
		args = []string{"core", "update"}
	case "core-repair":
		var ver string
		_ = m.DB.QueryRow(`SELECT version FROM cms_sites WHERE path = ?`, path).Scan(&ver)
		args = []string{"core", "download", "--force", "--skip-content", "--version=" + ver}
	case "plugin", "theme":
		if !reSlug.MatchString(slug) {
			return "", errors.New("invalid slug")
		}
		args = []string{what, "update", slug}
	default:
		return "", fmt.Errorf("unknown update %q", what)
	}
	return m.WPCLI(ctx, path, args...)
}

// reSlug is a plugin or theme slug (a directory name on wordpress.org).
var reSlug = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)

// reWPRelease is a WordPress version ("6.5.2", "6.6-RC1").
var reWPRelease = regexp.MustCompile(`^[0-9][0-9A-Za-z.-]{0,30}$`)

// wpArgAllowed refuses options other than the few xPGuard passes: a slug
// such as "--exec=..." or "--require=file" (from the portal, or a plugin
// directory a customer named so) would make wp-cli run PHP.
func wpArgAllowed(a string) bool {
	if !strings.HasPrefix(a, "-") {
		return true
	}
	switch a {
	case "--force", "--skip-content", "--minor", "--all":
		return true
	}
	v, ok := strings.CutPrefix(a, "--version=")
	return ok && reWPRelease.MatchString(v)
}

// wpArgv is runuser's command line for wp-cli as the site owner. Without
// loading the site's plugins and theme: a site broken by one of them
// (brandaville.com: Elementor Pro 2.7 with Elementor 4, "There has been a
// critical error") failed every update with that fatal error, the update
// that would mend it included. Updates and deactivations need neither.
func wpArgv(owner string, wp []string, path string, args []string) []string {
	cmd := append(append(slices.Clone(wp), args...), "--path="+path, "--no-color", "--skip-plugins", "--skip-themes")
	return append([]string{"-u", owner, "--"}, cmd...)
}

// WPCLI runs a wp-cli command as the site owner.
func (m *Manager) WPCLI(ctx context.Context, path string, args ...string) (string, error) {
	var owner string
	if err := m.DB.QueryRow(`SELECT user FROM cms_sites WHERE path = ? AND type = 'wordpress'`, path).Scan(&owner); err != nil || owner == "" {
		return "", errors.New("WordPress site not found (run a CMS scan first)")
	}
	for _, a := range args {
		if strings.ContainsAny(a, "\n;&|$`") || !wpArgAllowed(a) {
			return "", fmt.Errorf("invalid argument %q", a)
		}
	}
	wp, err := wpCLI()
	if err != nil {
		return "", err
	}
	argv := wpArgv(owner, wp, path, args)
	cctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(cctx, "runuser", argv...).CombinedOutput()
	text := strings.TrimSpace(string(out))
	if len(text) > 4000 {
		text = text[len(text)-4000:]
	}
	if err != nil {
		return text, fmt.Errorf("wp-cli failed: %s", text)
	}
	return text, nil
}

func (s *Site) countVulns() {
	s.Vulnerable = 0
	if len(s.Core.Vulns) > 0 {
		s.Vulnerable++
	}
	for _, c := range append(append([]Component{}, s.Plugins...), s.Themes...) {
		if len(c.Vulns) > 0 {
			s.Vulnerable++
		}
	}
}

func (s *Site) maxCVSS() float64 {
	m := maxCVSS(s.Core.Vulns)
	for _, c := range append(append([]Component{}, s.Plugins...), s.Themes...) {
		m = max(m, maxCVSS(c.Vulns))
	}
	return m
}

func (m *Manager) lookupVulns(ctx context.Context, s *Site) {
	for i := range s.Plugins {
		if v, err := m.Vulns.Affecting(ctx, "plugin", s.Plugins[i].Slug, s.Plugins[i].Version); err == nil {
			s.Plugins[i].Vulns = v
		}
	}
	for i := range s.Themes {
		if v, err := m.Vulns.Affecting(ctx, "theme", s.Themes[i].Slug, s.Themes[i].Version); err == nil {
			s.Themes[i].Vulns = v
		}
	}
	if v, err := m.Vulns.Affecting(ctx, "core", "", s.Version); err == nil {
		s.Core.Vulns = v
	}
	s.countVulns()
}

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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/settings"
	"github.com/xmarthost/xmartguard/agent/internal/store"
)

// Manager scans CMS installations on a schedule and on demand.
type Manager struct {
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

	mu      sync.Mutex
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
	Risk            string      `json:"risk"`
	ScannedAt       int64       `json:"scanned_at"`
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
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Hour)
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
		if cfg.Enabled && time.Now().Unix()-last >= int64(cfg.IntervalHours)*3600 {
			_ = m.Start()
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func risk(s *Site) string {
	switch {
	case s.CoreIssues > 0 || s.DBIssues > 0:
		return "critical"
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
		seen[in.Path] = true
		s := Site{Type: in.Type, Path: in.Path, User: in.User, Domain: in.Domain, Version: Version(in),
			Plugins: []Component{}, Themes: []Component{}, MUPlugins: []string{}, Core: CoreReport{Modified: []string{}, Unknown: []string{}}}
		switch in.Type {
		case WordPress:
			s.Latest = m.Versions.Latest(ctx, "wp-core", "")
			s.Plugins = Plugins(in.Path)
			s.Themes = Themes(in.Path)
			if mu := MUPlugins(in.Path); mu != nil {
				s.MUPlugins = mu
			}
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
			if cfg.CoreCheck && s.Version != "" {
				if sums, err := m.Versions.Checksums(ctx, cacheDir, s.Version, Locale(in.Path)); err == nil {
					s.Core = VerifyCore(in.Path, sums)
				} else {
					s.Core.Error = err.Error()
				}
				s.CoreIssues = len(s.Core.Modified) + len(s.Core.Unknown)
			}
			if cfg.DBScan {
				s.DBIssues = m.scanDB(ctx, s)
			}
		case Joomla:
			s.Latest = m.Versions.Latest(ctx, "joomla", "")
		}
		s.Risk = risk(&s)
		s.ScannedAt = store.Now()
		m.save(s)
	}
	// Forget installations that no longer exist.
	rows, err := m.DB.Query(`SELECT path FROM cms_sites`)
	if err == nil {
		var gone []string
		for rows.Next() {
			var p string
			if rows.Scan(&p) == nil && !seen[p] {
				gone = append(gone, p)
			}
		}
		rows.Close()
		for _, p := range gone {
			_, _ = m.DB.Exec(`DELETE FROM cms_sites WHERE path = ?`, p)
		}
	}
	return nil
}

func (m *Manager) scanDB(ctx context.Context, s Site) int {
	c, err := ReadWPConfig(s.Path)
	if err != nil {
		return 0
	}
	dctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	found, err := ScanDatabase(dctx, c)
	if err != nil {
		m.Log.Info("database scan skipped", "site", s.Path, "err", err)
		return 0
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
	// Mark previous findings cleaned; the ones still present are re-detected below.
	_, _ = m.DB.Exec(`UPDATE db_findings SET status = 'cleaned' WHERE site_path = ? AND status = 'detected'`, s.Path)
	for _, f := range found {
		key := f.Table + "\x00" + f.Row + "\x00" + f.Signature
		// Archived findings stay archived (the admin has seen them).
		_, err := m.DB.Exec(`INSERT INTO db_findings (at, site_path, user, db_name, tbl, row_ref, signature, status) VALUES (?,?,?,?,?,?,?,'detected')
			ON CONFLICT(site_path, tbl, row_ref, signature) DO UPDATE SET at = excluded.at,
				status = CASE WHEN db_findings.status = 'archived' THEN 'archived' ELSE 'detected' END`,
			store.Now(), s.Path, s.User, c.Name, f.Table, f.Row, f.Signature)
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
	Type   string `json:"type"`
	Risk   string `json:"risk"`
	Query  string `json:"q"`
	Limit  int    `json:"limit"`
	Offset int    `json:"offset"`
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
	if f.Risk != "" {
		where, args = append(where, "risk = ?"), append(args, f.Risk)
	}
	if f.Query != "" {
		where, args = append(where, "(domain LIKE ? OR path LIKE ? OR user LIKE ?)"), append(args, "%"+f.Query+"%", "%"+f.Query+"%", "%"+f.Query+"%")
	}
	if f.Limit <= 0 || f.Limit > 500 {
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
}

// DBFindings lists database infections.
func (m *Manager) DBFindings(status, q string, limit, offset int) ([]DBRow, int, error) {
	where, args := []string{"1=1"}, []any{}
	if status != "" {
		where, args = append(where, "status = ?"), append(args, status)
	}
	if q != "" {
		where, args = append(where, "(db_name LIKE ? OR tbl LIKE ? OR signature LIKE ? OR user LIKE ?)"), append(args, "%"+q+"%", "%"+q+"%", "%"+q+"%", "%"+q+"%")
	}
	if limit <= 0 || limit > 500 {
		limit = 25
	}
	cond := strings.Join(where, " AND ")
	var total int
	if err := m.DB.QueryRow(`SELECT count(*) FROM db_findings WHERE `+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := m.DB.Query(`SELECT id, at, site_path, user, db_name, tbl, row_ref, signature, status FROM db_findings WHERE `+cond+
		` ORDER BY id DESC LIMIT ? OFFSET ?`, append(args, limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []DBRow{}
	for rows.Next() {
		var r DBRow
		if err := rows.Scan(&r.ID, &r.At, &r.SitePath, &r.User, &r.Database, &r.Table, &r.Row, &r.Signature, &r.Status); err != nil {
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
	for _, p := range []string{"/usr/local/bin/wp", "/opt/xmartguard/bin/wp-cli.phar"} {
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
	var owner string
	if err := m.DB.QueryRow(`SELECT user FROM cms_sites WHERE path = ? AND type = 'wordpress'`, path).Scan(&owner); err != nil {
		return "", errors.New("WordPress site not found (run a CMS scan first)")
	}
	wp, err := wpCLI()
	if err != nil {
		return "", err
	}
	var args []string
	switch what {
	case "core":
		args = []string{"core", "update"}
	case "core-repair":
		var ver string
		_ = m.DB.QueryRow(`SELECT version FROM cms_sites WHERE path = ?`, path).Scan(&ver)
		args = []string{"core", "download", "--force", "--skip-content", "--version=" + ver}
	case "plugin", "theme":
		if slug == "" || strings.ContainsAny(slug, " /\\;&|$`") {
			return "", errors.New("invalid slug")
		}
		args = []string{what, "update", slug}
	default:
		return "", fmt.Errorf("unknown update %q", what)
	}
	argv := append([]string{"-u", owner, "--"}, append(wp, append(args, "--path="+path, "--no-color")...)...)
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

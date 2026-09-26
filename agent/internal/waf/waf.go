package waf

import (
	"context"
	"database/sql"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/logtail"
	"github.com/xmarthost/xmartguard/agent/internal/settings"
	"github.com/xmarthost/xmartguard/agent/internal/store"
)

// Banner temp-bans an IP (implemented by the firewall manager).
type Banner interface {
	AutoBan(ip, reason, source string)
}

// Manager renders and installs the rules, reads ModSecurity events from the
// web-server error log, and bans IPs with repeated failed CMS logins.
type Manager struct {
	DB       *sql.DB
	Settings *settings.Store
	Log      *slog.Logger
	RulesDir string
	AgentBin string
	Firewall Banner

	mu     sync.Mutex
	target Target
	err    string
}

// Status is shown in the portal.
type Status struct {
	Available bool   `json:"available"`
	Enabled   bool   `json:"enabled"`
	WebServer string `json:"web_server"`
	Panel     string `json:"panel"`
	Error     string `json:"error"`
	Warning   string `json:"warning"`
	Rules     int    `json:"rules"`
}

func (m *Manager) Status() Status {
	m.mu.Lock()
	t, e := m.target, m.err
	m.mu.Unlock()
	cfg := m.Settings.Get().WAF
	n := 0
	for _, r := range Catalog {
		if categoryEnabled(cfg, r.Category) {
			n++
		}
	}
	warn := ""
	switch t.Engine {
	case "DetectionOnly":
		warn = "ModSecurity is in detection-only mode on this server: XMart Guard rules log attacks but do not block them. Set SecRuleEngine On to enforce."
	case "Off":
		warn = "ModSecurity's rule engine is turned off on this server (SecRuleEngine Off): the WAF rules are inactive."
	}
	return Status{Available: t.ModSec && t.IncludeFile != "", Enabled: cfg.Enabled, WebServer: t.WebServer,
		Panel: t.Name, Error: e, Warning: warn, Rules: n}
}

func categoryEnabled(c settings.WAF, cat string) bool {
	switch cat {
	case "upload_scan":
		return c.UploadScan
	case "sensitive_files":
		return c.SensitiveFiles
	case "wordpress":
		return c.WordPress
	case "bruteforce":
		return c.BruteForce
	case "bad_bots":
		return c.BadBots
	case "seo_bots":
		return c.SEOBots
	case "ai_bots":
		return c.AIBots
	case "custom_bots":
		return len(c.CustomBots) > 0
	}
	return false
}

// Apply detects the web server, renders and installs the rules.
func (m *Manager) Apply() error {
	t := Detect()
	cfg := m.Settings.Get().WAF
	var err error
	if !cfg.Enabled {
		err = m.uninstall(t)
	} else if t.ModSec && t.IncludeFile != "" {
		opts := Options{Dir: m.RulesDir, UploadScan: true}
		if cfg.UploadScan {
			opts.InspectPath = InspectScript(m.RulesDir, m.AgentBin)
		}
		err = m.install(t, Render(cfg, opts), BotFiles(cfg))
	}
	m.mu.Lock()
	m.target = t
	m.err = ""
	if err != nil {
		m.err = err.Error()
	}
	m.mu.Unlock()
	if err != nil {
		m.Log.Error("waf apply failed", "err", err)
	}
	return err
}

// Rule catalog with each rule's enabled state, for the settings page.
type CatalogRule struct {
	RuleInfo
	Enabled bool `json:"enabled"`
}

func (m *Manager) RuleCatalog() []CatalogRule {
	cfg := m.Settings.Get().WAF
	disabled := map[int]bool{}
	for _, id := range cfg.DisabledRules {
		disabled[id] = true
	}
	out := make([]CatalogRule, 0, len(Catalog))
	for _, r := range Catalog {
		out = append(out, CatalogRule{r, categoryEnabled(cfg, r.Category) && !disabled[r.ID]})
	}
	return out
}

// ---- log parsing

// ModSecurity v2 audit lines in the Apache error log look like:
//
//	[Fri ...] [client 1.2.3.4] ModSecurity: Access denied with code 403 ...
//	[msg "..."] ... [id "7700501"] [hostname "site.com"] [uri "/x"] ...
var (
	reClient = regexp.MustCompile(`\[client (` + ipPat + `)(?::\d+)?\]`)
	reField  = regexp.MustCompile(`\[(msg|id|hostname|uri|severity) "((?:[^"\\]|\\.)*)"\]`)
	reDenied = regexp.MustCompile(`(?:Access denied with code (\d+)|denied by server)`)
	reMethod = regexp.MustCompile(`\[method "([A-Z]+)"\]`)
)

const ipPat = `(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{3,45}`

// Event is one ModSecurity hit.
type Event struct {
	ID       int64  `json:"id"`
	At       int64  `json:"at"`
	IP       string `json:"ip"`
	Method   string `json:"method"`
	Host     string `json:"host"`
	URI      string `json:"uri"`
	RuleID   int    `json:"rule_id"`
	Msg      string `json:"msg"`
	Category string `json:"category"`
	Action   string `json:"action"`
	User     string `json:"user"`
}

// ParseLine turns one error-log line into an Event, or false.
func ParseLine(line string) (Event, bool) {
	if !strings.Contains(line, "ModSecurity") {
		return Event{}, false
	}
	c := reClient.FindStringSubmatch(line)
	if c == nil {
		return Event{}, false
	}
	e := Event{IP: c[1], At: store.Now()}
	for _, f := range reField.FindAllStringSubmatch(line, -1) {
		val := strings.ReplaceAll(f[2], `\"`, `"`)
		switch f[1] {
		case "msg":
			e.Msg = val
		case "id":
			e.RuleID, _ = strconv.Atoi(val)
		case "hostname":
			e.Host = val
		case "uri":
			e.URI = val
		}
	}
	if mm := reMethod.FindStringSubmatch(line); mm != nil {
		e.Method = mm[1]
	}
	if d := reDenied.FindStringSubmatch(line); d != nil && d[1] != "" {
		e.Action = "Access denied with code " + d[1]
	} else {
		e.Action = "Logged"
	}
	e.Category = classify(e.RuleID, e.Msg)
	return e, true
}

func classify(id int, msg string) string {
	switch {
	case id >= IDLoginWP && id <= IDLoginOpenCart:
		return "login"
	case id >= IDBadBots && id <= IDCustomBots:
		return "bot"
	case strings.Contains(msg, "Bad Bot") || strings.Contains(msg, "crawler") || strings.Contains(msg, "UserAgent"):
		return "bot"
	default:
		return "waf"
	}
}

var loginRuleName = map[int]string{
	IDLoginWP: "WordPress", IDLoginXMLRPC: "WordPress XML-RPC", IDLoginJoomla: "Joomla", IDLoginOpenCart: "OpenCart",
}

// Run tails the error logs, records events and bans brute-force login sources.
func (m *Manager) Run(ctx context.Context) {
	_ = m.Apply()
	// Re-detect and re-apply on settings change is handled by the command
	// handler; here we also refresh every 10 min so a new vhost log is picked up.
	go m.tailLogs(ctx)
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if m.Settings.Get().WAF.Enabled {
				_ = m.Apply()
			}
		}
	}
}

func (m *Manager) tailLogs(ctx context.Context) {
	seen := map[string]bool{}
	lines := make(chan string, 512)
	start := func(path string) {
		if path == "" || seen[path] {
			return
		}
		seen[path] = true
		go logtail.Follow(ctx, path, lines)
	}
	for _, p := range Detect().ErrorLogs {
		start(p)
	}
	// Periodically discover new log files (cPanel writes per-domain logs).
	rescan := time.NewTicker(2 * time.Minute)
	defer rescan.Stop()
	counter := newCounter()
	for {
		select {
		case <-ctx.Done():
			return
		case <-rescan.C:
			for _, p := range Detect().ErrorLogs {
				start(p)
			}
		case line := <-lines:
			ev, ok := ParseLine(line)
			if !ok {
				continue
			}
			m.record(ev)
			if ev.Category == "login" {
				m.maybeBan(ev, counter)
			}
		}
	}
}

func (m *Manager) record(e Event) {
	_, _ = m.DB.Exec(`INSERT INTO waf_events (at, ip, method, host, uri, rule_id, msg, category, action, user)
		VALUES (?,?,?,?,?,?,?,?,?,?)`, e.At, e.IP, e.Method, e.Host, e.URI, e.RuleID, e.Msg, e.Category, e.Action, e.User)
	// Keep the table bounded.
	if e.ID%512 == 0 {
		_, _ = m.DB.Exec(`DELETE FROM waf_events WHERE at < ?`, store.Now()-30*86400)
	}
}

func (m *Manager) maybeBan(e Event, c *counter) {
	cfg := m.Settings.Get().WAF
	if !cfg.BruteForce || m.Firewall == nil {
		return
	}
	n := c.hit(e.IP, time.Duration(cfg.BFWindowMin)*time.Minute)
	if n >= cfg.BFThreshold {
		c.reset(e.IP)
		name := loginRuleName[e.RuleID]
		m.Firewall.AutoBan(e.IP, "WAF: "+strconv.Itoa(n)+" failed "+name+" logins", "waf")
	}
}

// EventFilter narrows Events.
type EventFilter struct {
	Category string `json:"category"`
	Query    string `json:"q"`
	Limit    int    `json:"limit"`
	Offset   int    `json:"offset"`
}

// Events lists ModSecurity hits, newest first.
func (m *Manager) Events(f EventFilter) ([]Event, int, error) {
	where, args := []string{"1=1"}, []any{}
	if f.Category != "" {
		where, args = append(where, "category = ?"), append(args, f.Category)
	}
	if f.Query != "" {
		where, args = append(where, "(ip LIKE ? OR host LIKE ? OR uri LIKE ? OR msg LIKE ?)"),
			append(args, "%"+f.Query+"%", "%"+f.Query+"%", "%"+f.Query+"%", "%"+f.Query+"%")
	}
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 50
	}
	cond := strings.Join(where, " AND ")
	var total int
	if err := m.DB.QueryRow(`SELECT count(*) FROM waf_events WHERE `+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := m.DB.Query(`SELECT id, at, ip, method, host, uri, rule_id, msg, category, action, user
		FROM waf_events WHERE `+cond+` ORDER BY id DESC LIMIT ? OFFSET ?`, append(args, f.Limit, f.Offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ID, &e.At, &e.IP, &e.Method, &e.Host, &e.URI, &e.RuleID, &e.Msg, &e.Category, &e.Action, &e.User); err != nil {
			return nil, 0, err
		}
		out = append(out, e)
	}
	return out, total, rows.Err()
}

// Stats summarises WAF activity for dashboards.
type Stats struct {
	Blocked24h int `json:"blocked_24h"`
	Bots24h    int `json:"bots_24h"`
	Logins24h  int `json:"logins_24h"`
	Total      int `json:"total"`
}

func (m *Manager) Stats() Stats {
	var s Stats
	day := store.Now() - 86400
	_ = m.DB.QueryRow(`SELECT count(*) FROM waf_events WHERE category='waf' AND at>=?`, day).Scan(&s.Blocked24h)
	_ = m.DB.QueryRow(`SELECT count(*) FROM waf_events WHERE category='bot' AND at>=?`, day).Scan(&s.Bots24h)
	_ = m.DB.QueryRow(`SELECT count(*) FROM waf_events WHERE category='login' AND at>=?`, day).Scan(&s.Logins24h)
	_ = m.DB.QueryRow(`SELECT count(*) FROM waf_events`).Scan(&s.Total)
	return s
}

// counter tracks failures per IP in a sliding window (same shape as firewall).
type counter struct {
	mu   sync.Mutex
	hits map[string][]time.Time
}

func newCounter() *counter { return &counter{hits: map[string][]time.Time{}} }

func (c *counter) hit(ip string, window time.Duration) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	cut := now.Add(-window)
	keep := c.hits[ip][:0]
	for _, t := range c.hits[ip] {
		if t.After(cut) {
			keep = append(keep, t)
		}
	}
	keep = append(keep, now)
	c.hits[ip] = keep
	if len(c.hits) > 50000 {
		for k, v := range c.hits {
			if len(v) == 0 || v[len(v)-1].Before(cut) {
				delete(c.hits, k)
			}
		}
	}
	return len(keep)
}

func (c *counter) reset(ip string) {
	c.mu.Lock()
	delete(c.hits, ip)
	c.mu.Unlock()
}

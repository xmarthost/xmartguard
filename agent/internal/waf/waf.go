package waf

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"regexp"
	"sort"
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

	mu       sync.Mutex
	target   Target
	err      string
	sources  []string // logs being read
	ruleSets RuleSets
	states   []RuleSetState
	selfTest *SelfTest
	// SelfTestWait: how long the self-test waits for a reload (tests set 0).
	SelfTestWait time.Duration
	// NoSelfTest disables the self-test (unit tests without a web server).
	NoSelfTest bool
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
	// Logs the agent reads ModSecurity hits from.
	Logs     []string       `json:"logs"`
	RuleSets []RuleSetState `json:"rule_sets"`
	SelfTest *SelfTest      `json:"self_test,omitempty"`
}

func (m *Manager) Status() Status {
	m.mu.Lock()
	t, e := m.target, m.err
	logs := append([]string(nil), m.sources...)
	sets := append([]RuleSetState(nil), m.states...)
	selfTest := m.selfTest
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
	if t.Plain && !t.Hooked && cfg.Enabled {
		warn = "One step left in LiteSpeed: " + t.Hint
	}
	return Status{Available: t.ModSec && t.IncludeFile != "", Enabled: cfg.Enabled, WebServer: t.WebServer,
		Panel: t.Name, Error: e, Warning: warn, Rules: n, Logs: logs, RuleSets: sets, SelfTest: selfTest}
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
	case "webshell":
		return c.Webshell
	case "block_php_upload":
		return c.BlockPHPUpload
	}
	return false
}

// ToggleRule returns the settings change that switches one of our rules on
// or off. Switching a rule on whose group is off turns the group on and keeps
// the group's other rules off, so only the chosen rule starts working.
func ToggleRule(c settings.WAF, id int, on bool) (map[string]any, error) {
	var rule *RuleInfo
	for i := range Catalog {
		if Catalog[i].ID == id {
			rule = &Catalog[i]
		}
	}
	if rule == nil {
		return nil, fmt.Errorf("unknown XMart Guard rule %d", id)
	}
	disabled := map[int]bool{}
	for _, d := range c.DisabledRules {
		disabled[d] = true
	}
	patch := map[string]any{}
	if on {
		delete(disabled, id)
		if !categoryEnabled(c, rule.Category) {
			if rule.Category == "custom_bots" {
				return nil, errors.New("add custom User-Agents first")
			}
			patch[rule.Category] = true
			for _, r := range Catalog {
				if r.Category == rule.Category && r.ID != id {
					disabled[r.ID] = true
				}
			}
		}
	} else {
		disabled[id] = true
	}
	ids := []int{}
	for d := range disabled {
		ids = append(ids, d)
	}
	sort.Ints(ids)
	patch["disabled_rules"] = ids
	return patch, nil
}

// Apply detects the web server, renders and installs the rules: XMart
// Guard's own (when enabled) plus the OWASP CRS and custom rules from the
// portal's WAF Rule Sets. If the web server rejects the extra rule sets,
// they are left out so XMart Guard's rules keep protecting the sites.
func (m *Manager) Apply() error {
	t := Detect()
	cfg := m.Settings.Get().WAF
	extra, extraFiles, states := m.extras(t)
	var err error
	switch {
	case !t.ModSec || t.IncludeFile == "":
		for i := range states {
			if states[i].State == "active" {
				states[i].State, states[i].Detail = "unsupported", "ModSecurity is not available on this web server"
			}
		}
	case !cfg.Enabled && extra == "":
		err = m.uninstall(t)
	default:
		rules := ""
		if cfg.Enabled {
			opts := Options{Dir: m.RulesDir, UploadScan: true}
			if cfg.UploadScan {
				opts.InspectPath = InspectScript(m.RulesDir, m.AgentBin)
			}
			rules = Render(cfg, opts)
		} else {
			rules = "# XMart Guard's own rules are turned off; rule sets from the portal follow.\n"
		}
		rules = selfTestRule + "\n" + rules
		bots := BotFiles(cfg)
		for k, v := range extraFiles {
			bots[strings.TrimPrefix(k, m.RulesDir+"/")] = v
		}
		err = m.install(t, rules+extra, bots)
		if err != nil && extra != "" {
			for i := range states {
				if states[i].State == "active" {
					states[i].State, states[i].Detail = "error", err.Error()
				}
			}
			extra = ""
			if cfg.Enabled {
				err = m.install(t, rules, BotFiles(cfg))
			} else {
				err = m.uninstall(t)
			}
		}
	}
	// Prove the rules are enforced, not just written.
	var st *SelfTest
	if err == nil && !m.NoSelfTest && t.ModSec && t.IncludeFile != "" && (cfg.Enabled || extra != "") && !(t.Plain && !t.Hooked) {
		crsActive := false
		for _, s := range states {
			if s.ID == "owasp_crs" && s.State == "active" {
				crsActive = true
			}
		}
		wait := m.SelfTestWait
		if wait == 0 {
			wait = 30 * time.Second
		}
		r := runSelfTest(crsActive, wait)
		st = &r
		for i := range states {
			if states[i].ID == "owasp_crs" && states[i].State == "active" && r.CRS != "" && r.CRS != "blocked" {
				states[i].State, states[i].Detail = "error", r.CRS
			}
			if !r.OK && states[i].State == "active" {
				states[i].State, states[i].Detail = "error", r.Detail
			}
		}
		if !r.OK {
			m.Log.Warn("WAF self-test failed", "detail", r.Detail)
		}
	}
	m.mu.Lock()
	m.target = t
	m.states = states
	m.selfTest = st
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

// RuleSetStates reports each portal rule set's state after the last Apply.
func (m *Manager) RuleSetStates() []RuleSetState {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]RuleSetState(nil), m.states...)
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
	// LiteSpeed: "[NOTICE] [pid] [T0] [1.2.3.4:51234-3#APVH_example.com:443] [Module:mod_security] ..."
	reLSClient = regexp.MustCompile(`\[(` + ipPat + `):\d+-[^\]#]*#APVH_([^\]:]+)`)
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
	// UID is ModSecurity's unique_id (dedupes error and audit log copies).
	UID string `json:"-"`
}

// ParseLine turns one error-log line into an Event, or false.
func ParseLine(line string) (Event, bool) {
	// Apache writes "ModSecurity:"; LiteSpeed's own engine "[Module:mod_security]".
	if !strings.Contains(line, "ModSecurity") && !strings.Contains(line, "mod_security") {
		return Event{}, false
	}
	if !strings.Contains(line, `[id "`) {
		return Event{}, false // start-up notices, not a rule hit
	}
	var e Event
	if c := reClient.FindStringSubmatch(line); c != nil {
		e = Event{IP: c[1], At: store.Now()}
	} else if c := reLSClient.FindStringSubmatch(line); c != nil {
		e = Event{IP: c[1], Host: strings.TrimPrefix(c[2], "www."), At: store.Now()}
	} else {
		return Event{}, false
	}
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
	if u := reUniqueID.FindStringSubmatch(line); u != nil {
		e.UID = u[1]
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
	case id >= IDLoginWP && id <= IDLoginCustom:
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
	IDLoginCustom: "protected URL",
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
	audits := make(chan auditHit, 256)
	start := func(path string) {
		if real, err := filepath.EvalSymlinks(path); err == nil {
			path = real // /usr/local/apache/logs is a link to /etc/apache2/logs on cPanel
		}
		if path == "" || seen[path] {
			return
		}
		seen[path] = true
		m.noteSource(path)
		go logtail.Follow(ctx, path, lines)
	}
	startAudit := func(path string) {
		if seen[path] {
			return
		}
		seen[path] = true
		m.noteSource(path)
		go followAudit(ctx, path, audits)
	}
	discover := func() {
		for _, p := range Detect().ErrorLogs {
			if exists(p) {
				start(p)
			}
		}
		for _, p := range auditLogs() {
			startAudit(p)
		}
	}
	discover()
	// Periodically discover new log files (cPanel writes per-domain logs).
	rescan := time.NewTicker(2 * time.Minute)
	defer rescan.Stop()
	counter, blocks := newCounter(), newCounter()
	dedupe := newSeenIDs(4096)
	reasons := newReasons(2048)
	handle := func(ev Event) {
		ev = reasons.apply(ev)
		// Third-party rule sets (OWASP CRS scoring) log a warning for every
		// matched rule; only the request they block is an attack to record.
		// (The warnings share the request's unique id, so this comes first.)
		if !strings.HasPrefix(ev.Action, "Access denied") && (ev.RuleID < 7700000 || ev.RuleID > 7709999) {
			return
		}
		if isSelfTest(ev) || !dedupe.add(ev.UID) {
			return
		}
		m.record(ev)
		if ev.Category == "login" {
			m.maybeBan(ev, counter)
		} else if strings.HasPrefix(ev.Action, "Access denied") {
			m.maybeBanBlocked(ev, blocks)
		}
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-rescan.C:
			discover()
		case line := <-lines:
			if ev, ok := ParseLine(line); ok {
				handle(ev)
			}
		case h := <-audits:
			h.e.UID = h.uid
			handle(h.e)
		}
	}
}

// noteSource remembers which logs are read (shown in the WAF status).
func (m *Manager) noteSource(path string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, p := range m.sources {
		if p == path {
			return
		}
	}
	m.sources = append(m.sources, path)
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

// maybeBanBlocked temporarily bans addresses the WAF keeps blocking
// ("WAF Temporary IP Ban"): a scanner probing many URLs gets dropped at the
// firewall instead of costing a web server request each time.
func (m *Manager) maybeBanBlocked(e Event, c *counter) {
	fw := m.Settings.Get().Firewall
	if !fw.WAFBan || m.Firewall == nil {
		return
	}
	n := c.hit(e.IP, time.Duration(m.Settings.Get().WAF.BFWindowMin)*time.Minute)
	if n >= fw.WAFBanThreshold {
		c.reset(e.IP)
		m.Firewall.AutoBan(e.IP, strconv.Itoa(n)+" WAF blocked", "waf")
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

package waf

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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
	// BlockedIPs returns the firewall's blocked addresses (proxy IP check).
	BlockedIPs func() []string
	// TrustedIPs returns trusted services' addresses (bot rules skip them).
	TrustedIPs func() []string
	// VerifiedBots are the search crawlers whose official lists are loaded.
	VerifiedBots func() []string
	// IPDBIPs, TorIPs and RBLExempt feed the IPDB POST block and Tor rules.
	IPDBIPs   func() []string
	TorIPs    func() []string
	RBLExempt func() []string
	// Intel is the portal's fleet intelligence (nil or returning nil = none).
	Intel func() *Intel
	// Gate is the login-page CAPTCHA for the rules (nil or returning nil = off).
	Gate func() *Gate
	// Central is the portal's CAPTCHA page for suspicious visitors (nil or
	// returning nil = off).
	Central func() *Central

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
	// ReplacedBy: xPGuard's own blocking rules are off here because this
	// rule set is used instead (e.g. Malware.Expert).
	ReplacedBy string `json:"replaced_by,omitempty"`
	// EnabledSince is when the rules were first hooked into the web server.
	EnabledSince int64 `json:"enabled_since"`
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
		warn = "ModSecurity is in detection-only mode on this server: xPGuard rules log attacks but do not block them. Set SecRuleEngine On to enforce."
	case "Off":
		warn = "ModSecurity's rule engine is turned off on this server (SecRuleEngine Off): the WAF rules are inactive."
	}
	if t.Plain && !t.Hooked && cfg.Enabled {
		warn = "One step left in LiteSpeed: " + t.Hint
	}
	since, _ := strconv.ParseInt(store.GetKV(m.DB, "waf_enabled_since"), 10, 64)
	return Status{Available: t.ModSec && t.IncludeFile != "", Enabled: cfg.Enabled, WebServer: t.WebServer,
		Panel: t.Name, Error: e, Warning: warn, Rules: n, Logs: logs, RuleSets: sets, SelfTest: selfTest, EnabledSince: since,
		ReplacedBy: m.OwnRulesReplacedBy()}
}

func categoryEnabled(c settings.WAF, cat string) bool {
	switch cat {
	case "exclusions":
		return true
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
	case "bot_blocker":
		return c.BotBlocker && len(c.BotList) > 0
	case "proxy_ip_check":
		return c.ProxyIPCheck
	case "webshell":
		return c.Webshell
	case "generic":
		return c.Generic
	case "virtual_patches":
		return c.VirtualPatches
	case "ipdb_post":
		return c.IPDBPost
	case "tor":
		return c.TorAction != "off" && c.TorAction != ""
	case "block_php_upload":
		return c.BlockPHPUpload
	}
	return false
}

func (m *Manager) trustedList() []string {
	if m.TrustedIPs == nil {
		return nil
	}
	var ok []string
	seen := map[string]bool{}
	for _, a := range m.TrustedIPs() {
		if a = modsecAddr(a); validAddr(a) && !seen[a] {
			seen[a] = true
			ok = append(ok, a)
		}
	}
	sort.Strings(ok)
	return ok
}

// TrustedListChanged reports whether trusted-ips.txt is out of date.
func (m *Manager) TrustedListChanged() bool {
	cur, _ := os.ReadFile(filepath.Join(m.RulesDir, FileTrustedIPs))
	l := m.trustedList()
	if len(l) == 0 {
		return len(cur) > 0
	}
	return string(cur) != strings.Join(l, "\n")+"\n"
}

// listFiles returns the list files the rules read.
func (m *Manager) listFiles(cfg settings.WAF) map[string]string {
	files := BotFiles(cfg)
	if l := m.trustedList(); len(l) > 0 {
		files[FileTrustedIPs] = strings.Join(l, "\n") + "\n"
	}
	var blocked []string
	if cfg.ProxyIPCheck && m.BlockedIPs != nil {
		blocked = m.BlockedIPs()
	}
	// The proxy networks are also used by the IPDB and Tor rules.
	for k, v := range ProxyFiles(blocked) {
		if k == FileProxyRanges || cfg.ProxyIPCheck {
			files[k] = v
		}
	}
	for k, v := range m.rblFiles(cfg) {
		files[k] = v
	}
	return files
}

// rblFiles are the address lists of the IPDB POST block and Tor rules.
func (m *Manager) rblFiles(cfg settings.WAF) map[string]string {
	tor := cfg.TorAction == "post" || cfg.TorAction == "block" || cfg.TorAction == "captcha"
	if !cfg.IPDBPost && !tor {
		return nil
	}
	get := func(f func() []string) []string {
		if f == nil {
			return nil
		}
		return f()
	}
	files := map[string]string{FileRBLExempt: AddrFile(get(m.RBLExempt))}
	if cfg.IPDBPost {
		files[FileIPDBIPs] = AddrFile(get(m.IPDBIPs))
	}
	if tor {
		files[FileTorIPs] = AddrFile(get(m.TorIPs))
	}
	return files
}

// CentralChanged reports whether the central CAPTCHA's address lists on
// disk differ from the current ones (so a reload is due).
func (m *Manager) CentralChanged() bool {
	if m.Central == nil || !m.Settings.Get().WAF.Enabled || m.OwnRulesReplacedBy() != "" {
		return false
	}
	c := m.Central()
	if c == nil {
		return false
	}
	for name, body := range CentralFiles(c) {
		cur, err := os.ReadFile(filepath.Join(m.RulesDir, name))
		if err != nil || string(cur) != body {
			return true
		}
	}
	return false
}

// BlockedListChanged reports whether the address lists on disk (proxy IP
// check, IPDB POST block, Tor) differ from the current ones (so a reload
// is due).
func (m *Manager) BlockedListChanged() bool {
	cfg := m.Settings.Get().WAF
	want := m.rblFiles(cfg)
	if cfg.ProxyIPCheck && m.BlockedIPs != nil {
		want[FileBlockedIPs] = ProxyFiles(m.BlockedIPs())[FileBlockedIPs]
	}
	if want == nil {
		want = map[string]string{}
	}
	m.mu.Lock()
	crs, tg := m.ruleSets.CRS, m.target
	m.mu.Unlock()
	if crs.Enabled && crs.ReplacedBy == "" && systemCRS(tg) == "" && m.CRSInstalled(crs.Version) {
		if sb, ok := m.softBlock(crs, m.crsThreshold(crs)); ok {
			for k, v := range sb.files {
				want[strings.TrimPrefix(k, m.RulesDir+"/")] = v
			}
		}
	}
	for name, body := range want {
		cur, err := os.ReadFile(filepath.Join(m.RulesDir, name))
		if err != nil || string(cur) != body {
			return true
		}
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
	if rule == nil && id >= IDPortalPatchMin && id <= IDPortalPatchMax {
		rule = &RuleInfo{ID: id, Category: "virtual_patches"}
	}
	if rule == nil {
		return nil, fmt.Errorf("unknown xPGuard rule %d", id)
	}
	disabled := map[int]bool{}
	for _, d := range c.DisabledRules {
		disabled[d] = true
	}
	patch := map[string]any{}
	if on {
		if id == IDCustomBots && len(c.BotList) == 0 {
			return nil, errors.New("add User-Agents to the Bad Bot blocker list first")
		}
		delete(disabled, id)
		if !categoryEnabled(c, rule.Category) {
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

// Apply detects the web server, renders and installs the rules: xPGuard's
// own (when enabled) plus the OWASP CRS and custom rules from the
// portal's WAF Rule Sets. If the web server rejects the extra rule sets,
// they are left out so xPGuard's rules keep protecting the sites.
func (m *Manager) Apply() error {
	t := Detect()
	cfg := m.Settings.Get().WAF
	extra, extraFiles, states := m.extras(t)
	var err error
	var central *Central
	switch {
	case !t.ModSec || t.IncludeFile == "":
		for i := range states {
			if states[i].State == "active" {
				states[i].State, states[i].Detail = "unsupported", "ModSecurity is not available on this web server"
			}
		}
	case !cfg.Enabled && extra == "":
		err = m.uninstall(t)
		_ = store.SetKV(m.DB, "waf_enabled_since", "")
	default:
		rules := ""
		if by := m.OwnRulesReplacedBy(); cfg.Enabled && by != "" {
			// Only the vendor's rules block here. The failed-login detectors
			// stay: they block nothing and feed the brute-force bans.
			rules = RenderLoginWatch(cfg, by, m.dynamic())
		} else if cfg.Enabled {
			opts := Options{Dir: m.RulesDir, UploadScan: true, Trusted: len(m.trustedList()) > 0}
			// A vendor's own login CAPTCHA (Malware.Expert recaptcha) wins.
			if m.Gate != nil && m.VendorLoginCaptcha() == "" {
				opts.Gate = m.Gate()
			}
			if opts.Gate == nil && m.Central != nil && m.VendorLoginCaptcha() == "" {
				opts.Central = m.Central()
			}
			central = opts.Central
			if m.Intel != nil {
				opts.Intel = m.Intel().Clean()
			}
			if m.VerifiedBots != nil && opts.Trusted {
				opts.VerifiedBots = m.VerifiedBots()
			}
			opts.Dynamic = m.dynamic()
			if cfg.UploadScan {
				opts.InspectPath = InspectScript(m.RulesDir, m.AgentBin)
			}
			rules = Render(cfg, opts)
		} else {
			rules = RenderExclusionsOnly(cfg, m.dynamic())
		}
		rules = selfTestRule + "\n" + rules
		bots := m.listFiles(cfg)
		if central != nil {
			for k, v := range CentralFiles(central) {
				bots[k] = v
			}
		}
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
				err = m.install(t, rules, m.listFiles(cfg))
			} else {
				err = m.uninstall(t)
			}
		}
	}
	if err == nil && t.ModSec && t.IncludeFile != "" && (cfg.Enabled || extra != "") && store.GetKV(m.DB, "waf_enabled_since") == "" {
		_ = store.SetKV(m.DB, "waf_enabled_since", strconv.FormatInt(time.Now().Unix(), 10))
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
		captchaURL := ""
		if m.Central != nil {
			if c := m.Central(); c != nil {
				captchaURL = c.URL
			}
		}
		r := runSelfTest(crsActive, captchaURL, wait)
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
	// Remote feeds: ModSecurity only warns when the vendor refuses the
	// download; report what it logged when loading them.
	if err == nil && !m.NoSelfTest && extra != "" {
		m.checkRemoteStates(states, t.ErrorLogs)
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
	Hits24h int  `json:"hits_24h"`
	Hits7d  int  `json:"hits_7d"`
}

func (m *Manager) RuleCatalog() []CatalogRule {
	cfg := m.Settings.Get().WAF
	disabled := map[int]bool{}
	for _, id := range cfg.DisabledRules {
		disabled[id] = true
	}
	now := store.Now()
	day, week := m.ruleHits(now-86400), m.ruleHits(now-7*86400)
	rules := append([]RuleInfo(nil), Catalog...)
	if m.Intel != nil {
		if in := m.Intel().Clean(); in != nil {
			for _, p := range in.Patches {
				t := "Portal patch: " + p.Title
				if p.CVE != "" {
					t += " (" + p.CVE + ")"
				}
				rules = append(rules, RuleInfo{p.ID, "virtual_patches", t, "block"})
			}
		}
	}
	out := make([]CatalogRule, 0, len(rules))
	for _, r := range rules {
		on := categoryEnabled(cfg, r.Category) && !disabled[r.ID]
		// Only the Tor rule of the chosen action is used.
		switch r.ID {
		case IDTorPost:
			on = on && (cfg.TorAction == "post" || cfg.TorAction == "captcha")
		case IDTorBlock:
			on = on && cfg.TorAction == "block"
		}
		out = append(out, CatalogRule{r, on, day[r.ID], week[r.ID]})
	}
	return out
}

// PackageState is a rule package with its state on this server and how
// often its rules blocked something.
type PackageState struct {
	Package
	Enabled bool `json:"enabled"`
	Rules   int  `json:"rules"`
	Active  int  `json:"active"`
	Hits24h int  `json:"hits_24h"`
	Hits7d  int  `json:"hits_7d"`
}

// pairRules are second rules (id+1000) that count for the first.
var pairRules = map[int]int{IDEmptyUAWP + 1000: IDEmptyUAWP, IDRootProbe + 1000: IDRootProbe,
	IDIPDBPost + 1000: IDIPDBPost, IDTorPost + 1000: IDTorPost, IDTorBlock + 1000: IDTorBlock,
	IDTorPost + 2000: IDTorPost, IDTorBlock + 2000: IDTorBlock}

// ruleHits counts each catalog rule's logged events since a time.
func (m *Manager) ruleHits(since int64) map[int]int {
	out := map[int]int{}
	rows, err := m.DB.Query(`SELECT rule_id, count(*) FROM waf_events WHERE at >= ? AND rule_id BETWEEN 7700000 AND 7709999 GROUP BY rule_id`, since)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var id, n int
		if rows.Scan(&id, &n) != nil {
			continue
		}
		if first, ok := pairRules[id]; ok {
			id = first
		}
		out[id] += n
	}
	return out
}

// PackageStates lists the rule packages for the portal's cards.
func (m *Manager) PackageStates() []PackageState {
	cat := m.RuleCatalog()
	var out []PackageState
	for _, p := range Packages {
		ps := PackageState{Package: p}
		in := map[string]bool{}
		for _, c := range p.Categories {
			in[c] = true
		}
		for _, r := range cat {
			if in[r.Category] {
				ps.Rules++
				ps.Hits24h += r.Hits24h
				ps.Hits7d += r.Hits7d
				if r.Enabled {
					ps.Active++
				}
			}
		}
		ps.Enabled = ps.Active > 0
		out = append(out, ps)
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
	// Detail is what the rule matched ("Pattern match ... at REQUEST_URI").
	Detail string `json:"detail"`
	// UID is ModSecurity's unique_id (dedupes error and audit log copies).
	UID string `json:"-"`
}

// Busy servers log thousands of these lines a second, and Go's regexps are
// slow on long lines: each pattern runs only on the short piece of the line
// that starts with its literal.

// findAt is re.FindStringSubmatch(line) for a pattern that starts with lit
// and matches at most span bytes.
func findAt(line, lit string, re *regexp.Regexp, span int) []string {
	for off := 0; ; {
		i := strings.Index(line[off:], lit)
		if i < 0 {
			return nil
		}
		i += off
		if m := re.FindStringSubmatch(line[i:min(len(line), i+span)]); m != nil {
			return m
		}
		off = i + len(lit)
	}
}

// lsClient is reLSClient on the bracket before LiteSpeed's "#APVH_".
func lsClient(line string) []string {
	for off := 0; ; {
		i := strings.Index(line[off:], "#APVH_")
		if i < 0 {
			return nil
		}
		i += off
		if b := strings.LastIndexByte(line[:i], '['); b >= 0 && i-b <= 120 {
			if m := reLSClient.FindStringSubmatch(line[b:min(len(line), i+300)]); m != nil {
				return m
			}
		}
		off = i + 6
	}
}

// detailMatch is reMatch's group: the text from after the first "Warning."
// or "Access denied with code N (phase N)." to the "[file" after it.
func detailMatch(line string) (string, bool) {
	start := -1
	for _, lit := range []string{"Warning.", "Access denied with code "} {
		if i := strings.Index(line, lit); i >= 0 && (start < 0 || i < start) {
			start = i
		}
	}
	if start < 0 {
		return "", false
	}
	f := strings.Index(line[start:], `[file "`)
	if f < 0 {
		return "", false
	}
	rest := line[start : start+f]
	p := deniedPrefix(rest)
	if strings.HasPrefix(rest, "Warning.") {
		p = len("Warning.")
	}
	if p < 0 || strings.ContainsRune(rest, '\n') {
		// Unusual layout: let the regexp decide.
		if m := reMatch.FindStringSubmatch(line); m != nil {
			return m[1], true
		}
		return "", false
	}
	return strings.Trim(rest[p:], " \t\r\f"), true
}

// deniedPrefix is the length of "Access denied with code N (phase N)." at
// the start of s, or -1.
func deniedPrefix(s string) int {
	const lit = "Access denied with code "
	if !strings.HasPrefix(s, lit) {
		return -1
	}
	i := len(lit)
	j := i
	for j < len(s) && s[j] >= '0' && s[j] <= '9' {
		j++
	}
	if j == i || !strings.HasPrefix(s[j:], " (phase ") {
		return -1
	}
	j += len(" (phase ")
	if j+2 >= len(s) || s[j] < '0' || s[j] > '9' || s[j+1:j+3] != ")." {
		return -1
	}
	return j + 3
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
	if c := findAt(line, "[client ", reClient, 80); c != nil {
		e = Event{IP: c[1], At: store.Now()}
	} else if c := lsClient(line); c != nil {
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
	if mm := findAt(line, `[method "`, reMethod, 64); mm != nil {
		e.Method = mm[1]
	}
	if u := findAt(line, `[unique_id "`, reUniqueID, 256); u != nil {
		e.UID = u[1]
	}
	e.Detail = matchDetail(line)
	// (The first of "Access denied" and "denied by server" decides, as one regexp would.)
	if d := findAt(line, "Access denied with code ", reDenied, 40); d != nil && d[1] != "" &&
		!strings.Contains(line[:strings.Index(line, "Access denied with code ")], "denied by server") {
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

// LogLines counts the web server error-log lines read (for the agent's
// CPU profile).
var LogLines atomic.Int64

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
		// Visitors sent to the login-page CAPTCHA are not attacks.
		if isSelfTest(ev) || isGateRule(ev.RuleID) || !dedupe.add(ev.UID) {
			return
		}
		// Summary lines without the request or reason duplicate a full entry.
		if ev.URI == "" && ev.Msg == "" {
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
			LogLines.Add(1)
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
	_, _ = m.DB.Exec(`INSERT INTO waf_events (at, ip, method, host, uri, rule_id, msg, category, action, user, detail)
		VALUES (?,?,?,?,?,?,?,?,?,?,?)`, e.At, e.IP, e.Method, e.Host, e.URI, e.RuleID, e.Msg, e.Category, e.Action, e.User, e.Detail)
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
	// User limits events to one hosting account's websites (panel users).
	User     string `json:"-"`
	Category string `json:"category"`
	Query    string `json:"q"`
	Limit    int    `json:"limit"`
	Offset   int    `json:"offset"`
}

// Events lists ModSecurity hits, newest first.
func (m *Manager) Events(f EventFilter) ([]Event, int, error) {
	where, args := []string{"1=1"}, []any{}
	if f.User != "" {
		where, args = append(where, "user = ?"), append(args, f.User)
	}
	if f.Category != "" {
		where, args = append(where, "category = ?"), append(args, f.Category)
	}
	if f.Query != "" {
		where, args = append(where, "(ip LIKE ? OR host LIKE ? OR uri LIKE ? OR msg LIKE ?)"),
			append(args, "%"+f.Query+"%", "%"+f.Query+"%", "%"+f.Query+"%", "%"+f.Query+"%")
	}
	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 50
	}
	cond := strings.Join(where, " AND ")
	var total int
	if err := m.DB.QueryRow(`SELECT count(*) FROM waf_events WHERE `+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := m.DB.Query(`SELECT id, at, ip, method, host, uri, rule_id, msg, category, action, user, detail
		FROM waf_events WHERE `+cond+` ORDER BY id DESC LIMIT ? OFFSET ?`, append(args, f.Limit, f.Offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ID, &e.At, &e.IP, &e.Method, &e.Host, &e.URI, &e.RuleID, &e.Msg, &e.Category, &e.Action, &e.User, &e.Detail); err != nil {
			return nil, 0, err
		}
		out = append(out, e)
	}
	return out, total, rows.Err()
}

// DeleteEvents removes hits from the log (not from the web server's logs).
func (m *Manager) DeleteEvents(ids []int64) (int64, error) {
	var n int64
	for _, id := range ids {
		r, err := m.DB.Exec(`DELETE FROM waf_events WHERE id = ?`, id)
		if err != nil {
			return n, err
		}
		c, _ := r.RowsAffected()
		n += c
	}
	return n, nil
}

var reMatch = regexp.MustCompile(`(?:Access denied with code \d+ \(phase \d\)\.|Warning\.)\s*(.*?)\s*\[file "`)

// matchDetail extracts what the rule matched, e.g.
// `Pattern match "\.env$" at REQUEST_FILENAME.`
func matchDetail(line string) string {
	m, ok := detailMatch(line)
	if !ok {
		return ""
	}
	// The log escapes backslashes in patterns ("\\.env" means "\.env").
	d := strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(m), `\\\\`, `\`), `\\`, `\`)
	if len(d) > 300 {
		d = d[:300] + "…"
	}
	return d
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

// OwnRulesReplacedBy names the rule set used instead of xPGuard's own
// blocking rules on this server ("" = ours are used).
func (m *Manager) OwnRulesReplacedBy() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ruleSets.OwnRules != nil {
		return m.ruleSets.OwnRules.ReplacedBy
	}
	return ""
}

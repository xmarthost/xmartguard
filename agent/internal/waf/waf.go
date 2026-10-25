package waf

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net"
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
	// ExemptIPs returns the addresses the WAF never inspects: this server,
	// its fleet, the portal and the firewall whitelist.
	ExemptIPs func() []string
	// VerifiedBots are the search crawlers whose official lists are loaded.
	VerifiedBots func() []string
	// IPDBIPs, TorIPs and RBLExempt feed the IPDB POST block and Tor rules.
	IPDBIPs   func() []string
	TorIPs    func() []string
	RBLExempt func() []string
	// TrustedCountryIPs are the networks of the whitelisted countries: their
	// visitors get the relaxed CRS threshold even on the IPDB (shared mobile
	// and office addresses) and are never sent to the CAPTCHA.
	TrustedCountryIPs func() []string
	// Intel is the portal's fleet intelligence (nil or returning nil = none).
	Intel func() *Intel
	// Gate is the login-page CAPTCHA for the rules (nil or returning nil = off).
	Gate func() *Gate
	// Central is the portal's CAPTCHA page for suspicious visitors (nil or
	// returning nil = off).
	Central func() *Central
	// OnBotBlocked is told about requests the bot lists refused (address
	// and what matched), so real SEO and AI crawlers can be verified and trusted.
	OnBotBlocked func(ip, matched string)
	// OnPassCookie is told which pass-cookie slot a suspect sent
	// (IDCentralPassUsed): the agent withdraws a value used by an address
	// it was not given to.
	OnPassCookie func(ip string, slot int)
	// Owner names the cPanel account of a website (Host without port), so
	// the account's own panel lists its sites' events (nil = none).
	Owner func(host string) string

	mu       sync.Mutex
	counts   countCache
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

	// One web server reload at a time, and address lists not more often
	// than ListReloadGap allows (see install).
	reloadMu   sync.Mutex
	lastReload time.Time
	// reloadPending: the last reload failed, so the rules on disk are not
	// the ones running; the next apply reloads even without a change.
	reloadPending bool
	deferred      *time.Timer
}

// Status is shown in the portal.
type Status struct {
	Available bool   `json:"available"`
	Enabled   bool   `json:"enabled"`
	WebServer string `json:"web_server"`
	Panel     string `json:"panel"`
	Error     string `json:"error"`
	Warning   string `json:"warning"`
	// ModSecCheck says why ModSecurity was not found.
	ModSecCheck string `json:"modsec_check,omitempty"`
	Rules       int    `json:"rules"`
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
		ModSecCheck: t.ModSecCheck}
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

// exemptList is ExemptIPs without proxy networks: an address behind
// Cloudflare or a local reverse proxy is any visitor's.
func (m *Manager) exemptList() []string {
	if m.ExemptIPs == nil {
		return nil
	}
	var proxies []*net.IPNet
	for _, p := range ProxyRanges {
		if !strings.Contains(p, "/") {
			if strings.Contains(p, ":") {
				p += "/128"
			} else {
				p += "/32"
			}
		}
		if _, n, err := net.ParseCIDR(p); err == nil {
			proxies = append(proxies, n)
		}
	}
	var ok []string
	seen := map[string]bool{}
	for _, a := range m.ExemptIPs() {
		a = modsecAddr(a)
		if !validAddr(a) || seen[a] {
			continue
		}
		ip, n, err := net.ParseCIDR(a)
		if err != nil {
			ip = net.ParseIP(a)
		}
		if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
			continue
		}
		overlaps := false
		for _, p := range proxies {
			if p.Contains(ip) || (n != nil && n.Contains(p.IP)) {
				overlaps = true
				break
			}
		}
		if overlaps {
			continue
		}
		seen[a] = true
		ok = append(ok, a)
	}
	sort.Strings(ok)
	return ok
}

// ExemptListChanged reports whether exempt-ips.txt is out of date.
func (m *Manager) ExemptListChanged() bool {
	cur, _ := os.ReadFile(filepath.Join(m.RulesDir, FileExemptIPs))
	l := m.exemptList()
	if len(l) == 0 {
		return len(cur) > 0
	}
	return string(cur) != strings.Join(l, "\n")+"\n"
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
	if l := m.exemptList(); len(l) > 0 {
		files[FileExemptIPs] = strings.Join(l, "\n") + "\n"
	}
	var blocked []string
	if cfg.ProxyIPCheck && m.BlockedIPs != nil {
		blocked = m.BlockedIPs()
	}
	// The proxy networks are also used by the IPDB and Tor rules.
	for k, v := range ProxyFiles(blocked) {
		if k == FileProxyRanges || k == FileCFRanges || k == FileLocalProxys || cfg.ProxyIPCheck {
			files[k] = v
		}
	}
	for k, v := range m.rblFiles(cfg) {
		files[k] = v
	}
	return files
}

// SharedEgressRanges are relays thousands of people share: iCloud Private
// Relay (Apple's 17.0.0.0/8; Cloudflare's egress for it and WARP,
// 104.28.0.0/15 with 2606:54c1::/32 and 2a09:bac0::/29). One user's abuse
// puts the address on the IPDB, so it never blocks their POSTs (the CRS
// still inspects them). The same relays' 104.29.x and IPv6 addresses were
// missing (the CAPTCHA log of 2026-10-23 shows customers on all of them).
// 87.81.0.0/16: the website side of Private Relay visitors who solve the
// CAPTCHA from 2606:54c1::/32 (14 websites in the log of 2026-10-24).
var SharedEgressRanges = []string{"17.0.0.0/8", "87.81.0.0/16", "104.28.0.0/15", "2606:54c1::/32", "2a09:bac0::/29"}

// ipdbMarks reports whether the IPDB list is read once into marks
// (renderIPDBMarks) for the rules that need it: the IPDB POST block, and
// the CAPTCHA (its suspects and soft blocking).
func (m *Manager) ipdbMarks(cfg settings.WAF) bool {
	if !cfg.Enabled || m.IPDBIPs == nil || m.Settings == nil {
		return false
	}
	return cfg.IPDBPost || m.Settings.Get().Captcha.Central
}

// markedIPDB is the IPDB list the marks read (nil without marks).
func (m *Manager) markedIPDB(cfg settings.WAF) []string {
	if !m.ipdbMarks(cfg) {
		return nil
	}
	l := m.IPDBIPs()
	if l == nil {
		l = []string{}
	}
	return l
}

// rblFiles are the address lists of the IPDB POST block and Tor rules.
func (m *Manager) rblFiles(cfg settings.WAF) map[string]string {
	tor := cfg.TorAction == "post" || cfg.TorAction == "block" || cfg.TorAction == "captcha"
	marks := m.ipdbMarks(cfg)
	if !cfg.IPDBPost && !tor && !marks {
		return nil
	}
	get := func(f func() []string) []string {
		if f == nil {
			return nil
		}
		return f()
	}
	files := map[string]string{FileRBLExempt: AddrFile(get(m.RBLExempt))}
	if cfg.IPDBPost || marks {
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
	if m.Central == nil || !m.Settings.Get().WAF.Enabled {
		return false
	}
	c := m.Central()
	if c == nil {
		return false
	}
	for name, body := range CentralFiles(c, m.markedIPDB(m.Settings.Get().WAF)) {
		cur, err := os.ReadFile(filepath.Join(m.RulesDir, name))
		if err != nil || string(cur) != body {
			return true
		}
	}
	return false
}

// CentralSitesAdded reports whether sites names a website under a login
// attack that the rules on disk do not hold yet (the agent then reloads at
// once instead of at the next 10-minute refresh; a site leaving waits for
// that). The caller passes the sites: building the whole Central (the
// suspects with the IPDB) every minute would cost too much.
func (m *Manager) CentralSitesAdded(sites []string) bool {
	if !m.Settings.Get().WAF.Enabled {
		return false
	}
	cur, _ := os.ReadFile(filepath.Join(m.RulesDir, FileCaptchaSites))
	have := map[string]bool{}
	for _, h := range strings.Fields(string(cur)) {
		have[h] = true
	}
	for _, h := range AttackSites(sites) {
		if !have[h] {
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
	if crs.Enabled && systemCRS(tg) == "" && m.CRSInstalled(crs.Version) {
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
// When a change reloads the web server (see install).
type applyMode int

const (
	// modeNormal: rules apply at once; address lists wait for the gap.
	modeNormal applyMode = iota
	// modeNow: changes someone made (settings, the Apply button).
	modeNow
	// modeBackground: periodic refreshes (lists, learned exclusions,
	// fleet intelligence): even rule changes wait for the gap.
	modeBackground
)

// Apply writes the rules and reloads the web server when they changed.
func (m *Manager) Apply() error { return m.apply(modeNormal) }

// ApplyNow applies at once, without waiting for the reload gap.
func (m *Manager) ApplyNow() error { return m.apply(modeNow) }

// ApplyBackground applies a periodic refresh: the web server reloads only
// when the last reload is old enough.
func (m *Manager) ApplyBackground() error { return m.apply(modeBackground) }

func (m *Manager) apply(mode applyMode) error {
	t := Detect()
	cfg := m.Settings.Get().WAF
	extra, extraFiles, states := m.extras(t)
	var err error
	var central *Central
	switch {
	case !t.ModSec || t.IncludeFile == "":
		detail := "ModSecurity is not available on this web server"
		if t.ModSecCheck != "" {
			detail += " (" + t.ModSecCheck + ")"
		}
		for i := range states {
			if states[i].State == "active" {
				states[i].State, states[i].Detail = "unsupported", detail
			}
		}
	case !cfg.Enabled && extra == "":
		err = m.uninstall(t)
		_ = store.SetKV(m.DB, "waf_enabled_since", "")
	default:
		rules := ""
		if cfg.Enabled {
			opts := Options{Dir: m.RulesDir, UploadScan: true, Trusted: len(m.trustedList()) > 0}
			if m.Gate != nil {
				opts.Gate = m.Gate()
			}
			if opts.Gate == nil && m.Central != nil {
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
			opts.IPDBMarks = m.ipdbMarks(cfg)
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
			for k, v := range CentralFiles(central, m.markedIPDB(cfg)) {
				bots[k] = v
			}
		}
		for k, v := range extraFiles {
			bots[strings.TrimPrefix(k, m.RulesDir+"/")] = v
		}
		err = m.installMode(t, rules+extra, bots, mode)
		if err != nil && extra != "" {
			for i := range states {
				if states[i].State == "active" {
					states[i].State, states[i].Detail = "error", err.Error()
				}
			}
			extra = ""
			if cfg.Enabled {
				err = m.installMode(t, rules, m.listFiles(cfg), mode)
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
	c := m.cachedCounts()
	day, week := c.day, c.week
	rules := append([]RuleInfo(nil), Catalog...)
	var in *Intel
	if m.Intel != nil {
		in = m.Intel().Clean()
	}
	watching := Monitored(in)
	for i := range rules {
		if watching[rules[i].ID] {
			rules[i].Action = "watch"
		}
	}
	{
		if in != nil {
			for _, p := range in.Patches {
				t := "Portal patch: " + p.Title
				if p.CVE != "" {
					t += " (" + p.CVE + ")"
				}
				act := "block"
				if p.Monitor {
					act = "watch"
				}
				rules = append(rules, RuleInfo{p.ID, "virtual_patches", t, act})
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

// countCache keeps the WAF log counts (rule hits and totals): counting a
// week of a busy server's log takes seconds, and the WAF settings page and
// the heartbeat ask often. Counts older than countFresh are served while a
// fresh count runs in the background.
type countCache struct {
	at       time.Time
	running  bool
	day      map[int]int
	week     map[int]int
	stats    Stats
	computed bool
}

const countFresh = time.Minute

func (m *Manager) countNow() countCache {
	now := store.Now()
	return countCache{at: time.Now(), day: m.ruleHits(now - 86400), week: m.ruleHits(now - 7*86400), stats: m.countStats(), computed: true}
}

func (m *Manager) cachedCounts() countCache {
	m.mu.Lock()
	c := m.counts
	if !c.computed {
		m.mu.Unlock()
		fresh := m.countNow()
		m.mu.Lock()
		m.counts = fresh
		m.mu.Unlock()
		return fresh
	}
	if time.Since(c.at) > countFresh && !c.running {
		m.counts.running = true
		go func() {
			fresh := m.countNow()
			m.mu.Lock()
			m.counts = fresh
			m.mu.Unlock()
		}()
	}
	m.mu.Unlock()
	return c
}

// WarmCounts fills the count cache so the first page view is quick.
func (m *Manager) WarmCounts() { m.cachedCounts() }

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
func (m *Manager) PackageStates() []PackageState { return PackagesOf(m.RuleCatalog()) }

// PackagesOf builds the package cards from an already built rule catalog.
func PackagesOf(cat []CatalogRule) []PackageState {
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
	reField  = regexp.MustCompile(`\[(msg|id|hostname|uri|severity|data) "((?:[^"\\]|\\.)*)"\]`)
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
	// Data is the rule's logdata (the value it matched, such as a refused
	// Content-Type), used where the log names no matched variable.
	Data string `json:"-"`
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
		case "data":
			e.Data = val
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
				_ = m.ApplyBackground()
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
	t := newTailState()
	handle := func(ev Event) { m.handleEvent(ev, t) }
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
	if e.User == "" && m.Owner != nil {
		e.User = m.Owner(hostOnly(e.Host))
	}
	res, err := m.DB.Exec(`INSERT INTO waf_events (at, ip, method, host, uri, rule_id, msg, category, action, user, detail)
		VALUES (?,?,?,?,?,?,?,?,?,?,?)`, e.At, e.IP, e.Method, e.Host, e.URI, e.RuleID, e.Msg, e.Category, e.Action, e.User, e.Detail)
	if err != nil {
		return
	}
	// Keep the table bounded: every 512th row (e.ID was never set, so this
	// ran on every insert). 32 days, so the monthly report on the 1st
	// still sees the whole last month.
	if id, err := res.LastInsertId(); err == nil && id%512 == 0 {
		_, _ = m.DB.Exec(`DELETE FROM waf_events WHERE at < ?`, store.Now()-RetainDays*86400)
	}
}

// hostOnly is the website name of a Host header: lowercase, without the
// port and a leading "www.".
func hostOnly(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if i := strings.LastIndexByte(h, ':'); i >= 0 && !strings.HasSuffix(h, "]") {
		h = h[:i]
	}
	return strings.TrimPrefix(h, "www.")
}

// RetainDays is how long WAF events are kept at least.
const RetainDays = 32

func (m *Manager) maybeBan(e Event, c *counter) {
	cfg := m.Settings.Get().WAF
	if !cfg.BruteForce || m.Firewall == nil || isProxyAddr(e.IP) {
		return
	}
	n := c.hit(e.IP, time.Duration(cfg.BFWindowMin)*time.Minute)
	if n >= cfg.BFThreshold {
		c.reset(e.IP)
		name := loginRuleName[e.RuleID]
		m.Firewall.AutoBan(e.IP, "WAF: "+strconv.Itoa(n)+" failed "+name+" logins", "waf")
	}
}

// gateRedirect are the gate rules that send a browser to the CAPTCHA (the
// others refuse a client that is no browser).
var gateRedirect = map[int]bool{IDGateNoCookie: true, IDGateBadCookie: true, IDCentralGate: true, IDCentralGateBadCookie: true}

// noBanRules block a request but never count toward a ban: shop scrapers
// come from residential and mobile addresses real visitors share, and a
// request without browser headers may be another server's integration.
var noBanRules = map[int]bool{IDShopScrape: true, IDShopScrape + 1000: true, IDCartSpam: true, IDCartSpam + 1000: true,
	IDNoUAPost: true, IDNoUAPost + 1000: true,
	// The address is only refused POSTs: a ban would cut a shared or API
	// address off the whole website.
	IDIPDBPost: true, IDIPDBPost + 1000: true, IDIPDBPost + 3000: true,
	// Rules that only match proxied requests: the event's address is the
	// proxy's (a Cloudflare edge serves many websites).
	IDProxyBlocked: true, IDProxyBlocked + 1000: true,
	IDTorPost + 1000: true, IDTorPost + 2000: true, IDTorPost + 3000: true,
	IDTorBlock + 1000: true, IDTorBlock + 2000: true, IDTorBlock + 3000: true}

// proxyNets are ProxyRanges parsed.
var proxyNets = func() []*net.IPNet {
	var out []*net.IPNet
	for _, r := range ProxyRanges {
		if !strings.Contains(r, "/") {
			if strings.Contains(r, ":") {
				r += "/128"
			} else {
				r += "/32"
			}
		}
		if _, n, err := net.ParseCIDR(r); err == nil {
			out = append(out, n)
		}
	}
	return out
}()

// isProxyAddr: a Cloudflare edge or a local proxy. It is never banned: the
// visitor is behind it, and every website it serves would be cut off (on
// servers without mod_remoteip every event carries the proxy's address).
func isProxyAddr(ip string) bool {
	a := net.ParseIP(ip)
	if a == nil {
		return false
	}
	for _, n := range proxyNets {
		if n.Contains(a) {
			return true
		}
	}
	return false
}

// policyOnly: an OWASP CRS block from protocol and policy rules only
// (920xxx: content type, file extension, header limits). Browsers and APIs
// break those in normal use (a beacon, a broken font link), so the request
// is refused but the address is never banned for it.
func policyOnly(e Event) bool {
	rest, ok := strings.CutPrefix(e.Detail, ScoredPrefix)
	if !ok {
		return false
	}
	ids := strings.FieldsFunc(rest, func(r rune) bool { return r == ',' || r == ' ' || r == '(' || r == ')' })
	n := 0
	for _, id := range ids {
		if (len(id) != 6 && id != strconv.Itoa(IDContentType)) || id[0] < '0' || id[0] > '9' {
			continue
		}
		if !strings.HasPrefix(id, "920") && id != strconv.Itoa(IDContentType) {
			return false
		}
		n++
	}
	return n > 0
}

// maybeBanBlocked temporarily bans addresses the WAF keeps blocking
// ("WAF Temporary IP Ban"): a scanner probing many URLs gets dropped at the
// firewall instead of costing a web server request each time.
func (m *Manager) maybeBanBlocked(e Event, c *counter) {
	fw := m.Settings.Get().Firewall
	if !fw.WAFBan || m.Firewall == nil || isProxyAddr(e.IP) {
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
	// IP and Host match exactly (Host also with or without www.).
	IP     string `json:"ip"`
	Host   string `json:"host"`
	Limit  int    `json:"limit"`
	Offset int    `json:"offset"`
	// Since keeps hits from this time on; BeforeID pages through an export
	// without repeats while new hits arrive.
	Since    int64 `json:"since"`
	BeforeID int64 `json:"before_id"`
	// Blocked keeps refused requests only (not logged or watched ones);
	// Rule keeps one rule's hits.
	Blocked bool `json:"blocked"`
	Rule    int  `json:"rule"`
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
	if f.Since > 0 {
		where, args = append(where, "at >= ?"), append(args, f.Since)
	}
	if f.BeforeID > 0 {
		where, args = append(where, "id < ?"), append(args, f.BeforeID)
	}
	if f.IP != "" {
		where, args = append(where, "ip = ?"), append(args, f.IP)
	}
	if f.Blocked {
		where = append(where, "action LIKE 'Access denied%'")
	}
	if f.Rule > 0 {
		where, args = append(where, "rule_id = ?"), append(args, f.Rule)
	}
	if h := strings.TrimPrefix(strings.ToLower(f.Host), "www."); h != "" {
		where, args = append(where, "(host = ? OR host = ?)"), append(args, h, "www."+h)
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

func (m *Manager) Stats() Stats { return m.cachedCounts().stats }

func (m *Manager) countStats() Stats {
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

// tailState is what reading the logs remembers between lines.
type tailState struct {
	logins, blocks *counter
	dedupe         *seenIDs
	reasons        *reasons
}

func newTailState() *tailState {
	return &tailState{logins: newCounter(), blocks: newCounter(), dedupe: newSeenIDs(4096), reasons: newReasons(2048)}
}

// handleEvent records one WAF log entry and bans repeat offenders.
func (m *Manager) handleEvent(ev Event, t *tailState) {
	ev = t.reasons.apply(ev)
	// Third-party rule sets (OWASP CRS scoring) log a warning for every
	// matched rule; only the request they block is an attack to record.
	// (The warnings share the request's unique id, so this comes first.)
	if !strings.HasPrefix(ev.Action, "Access denied") && (ev.RuleID < 7700000 || ev.RuleID > 7709999) {
		return
	}
	// A suspect sent a pass cookie of the check on the website's address.
	if slot := CentralPassSlot(ev.RuleID); slot >= 0 {
		if m.OnPassCookie != nil && !isSelfTest(ev) {
			m.OnPassCookie(ev.IP, slot)
		}
		return
	}
	// Visitors sent to the login-page CAPTCHA are not attacks: logged
	// once per address and site in half an hour (category "captcha", so
	// the WAF log shows the step after failed logins), never counted.
	if isGateRule(ev.RuleID) && !isSelfTest(ev) {
		if NoteCaptchaSent(ev.IP, ev.Host, time.Now()) && t.dedupe.add(ev.UID) && ev.URI != "" {
			ev.Category = "captcha"
			if gateRedirect[ev.RuleID] {
				ev.Action = "Sent to the CAPTCHA"
			}
			m.record(ev)
		}
		return
	}
	if isSelfTest(ev) || !t.dedupe.add(ev.UID) {
		return
	}
	// Summary lines without the request or reason duplicate a full entry.
	if ev.URI == "" && ev.Msg == "" {
		return
	}
	m.record(ev)
	if m.OnBotBlocked != nil && (ev.RuleID == IDBadBots || ev.RuleID == IDSEOBots || ev.RuleID == IDAIBots || ev.RuleID == IDCustomBots) {
		m.OnBotBlocked(ev.IP, ev.Detail)
	}
	if ev.Category == "login" {
		m.maybeBan(ev, t.logins)
	} else if strings.HasPrefix(ev.Action, "Access denied") && !noBanRules[ev.RuleID] && !policyOnly(ev) {
		m.maybeBanBlocked(ev, t.blocks)
	}
}

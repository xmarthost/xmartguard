// Package settings holds the agent's security policy. It lives on the server
// (/etc/xmartguard/settings.json) so protection keeps working when the portal
// is unreachable; the portal reads and writes it through agent commands.
package settings

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/xmarthost/xmartguard/agent/internal/config"
)

// Action values for detections.
const (
	ActionNotify     = "notify"
	ActionQuarantine = "quarantine"
	ActionDisable    = "disable"
)

type Scanner struct {
	Enabled          bool     `json:"enabled"`
	Realtime         bool     `json:"realtime"`
	VirusAction      string   `json:"virus_action"`
	SuspiciousAction string   `json:"suspicious_action"`
	BinaryAction     string   `json:"binary_action"`
	DailyScan        bool     `json:"daily_scan"`
	WeeklyScan       bool     `json:"weekly_scan"`
	MaxFileSizeMB    int      `json:"max_file_size_mb"`
	WhitelistUsers   []string `json:"whitelist_users"`
	WhitelistPaths   []string `json:"whitelist_paths"`
	BlacklistNames   []string `json:"blacklist_names"`
	// DeleteSymlinks removes symbolic links that point outside the owner's
	// home (a common way to read other accounts' files).
	DeleteSymlinks bool `json:"delete_symlinks"`
	// AutoClean removes injected code from infected files when the rest of
	// the file is legitimate, instead of quarantining the whole file.
	AutoClean bool `json:"auto_clean"`
	// Feeds adds public malware signatures the portal collects (Linux
	// Malware Detect MD5/hex, web shell YARA rules).
	Feeds bool `json:"feeds"`
	// WPCoreRepair replaces an infected WordPress core file with the
	// official file of the site's WordPress version (verified against the
	// official checksum); the infected copy stays in quarantine.
	WPCoreRepair bool `json:"wp_core_repair"`
	// Trim removes only the injected code the AI scanner located (for
	// example a backdoor added to the top of a legitimate plugin file) and
	// keeps the site running, instead of quarantining the whole file. The
	// original is kept in quarantine; nothing is changed when the result
	// does not pass a syntax check and a rescan.
	Trim bool `json:"trim"`
	// TrimMaxPercent is the largest share of a file Trim may remove.
	TrimMaxPercent int `json:"trim_max_percent"`
	// UserScans lets cPanel users start scans of their own home.
	UserScans bool `json:"user_scans"`
	// YARA also runs YARA rules from /etc/xmartguard/yara when yara is installed.
	YARA bool `json:"yara"`
	// DBWhitelist lists database-scanner signature ids to ignore.
	DBWhitelist []Exclusion `json:"db_whitelist"`
	// KeepDays is how long logs and quarantined files are kept.
	KeepDays int `json:"keep_days"`
}

// Exclusion is an ignored id with the reason an admin gave.
type Exclusion struct {
	ID     string `json:"id"`
	Reason string `json:"reason"`
}

type Firewall struct {
	Enabled          bool     `json:"enabled"`
	Provider         string   `json:"provider"` // iptables (default) | nftables
	BruteForce       bool     `json:"bruteforce"`
	BFThreshold      int      `json:"bf_threshold"`
	BFWindowMinutes  int      `json:"bf_window_minutes"`
	BanMinutes       int      `json:"ban_minutes"`
	DoS              bool     `json:"dos"`
	DoSThreshold     int      `json:"dos_threshold"` // new connections per minute per IP
	BlockedCountries []string `json:"blocked_countries"`
	AllowedCountries []string `json:"allowed_countries"`
	// LogBlocked samples dropped connections for the live monitors.
	LogBlocked bool `json:"log_blocked"`
	// IgnoredCountries are never blocked by any firewall rule.
	IgnoredCountries []string `json:"ignored_countries"`
	// DDNS hostnames are resolved every few minutes and allowed.
	DDNS []string `json:"ddns"`
	// ExcludedJails are Intrusion Defense (log watcher) rules turned off.
	ExcludedJails []string `json:"excluded_jails"`
	// WAFBan temporarily bans addresses that trigger the WAF repeatedly.
	WAFBan          bool `json:"waf_ban"`
	WAFBanThreshold int  `json:"waf_ban_threshold"` // WAF blocks within the brute-force window
	// Captcha lets people behind a temporarily banned address unblock
	// themselves by solving a CAPTCHA (web traffic only).
	Captcha bool `json:"captcha"`
	// PortFilter restricts traffic to the listed ports.
	PortFilter bool   `json:"port_filter"`
	TCPIn      string `json:"tcp_in"`
	UDPIn      string `json:"udp_in"`
	TCPOut     string `json:"tcp_out"`
	UDPOut     string `json:"udp_out"`
}

// Captcha configures the page banned visitors see.
type Captcha struct {
	// Provider is builtin (no third party), turnstile (Cloudflare) or recaptcha (Google v2).
	Provider     string `json:"provider"`
	SiteKey      string `json:"site_key"`
	SecretKey    string `json:"secret_key"`
	AllowMinutes int    `json:"allow_minutes"` // how long a solved CAPTCHA allows the address
	HTTPPort     int    `json:"http_port"`
	HTTPSPort    int    `json:"https_port"`
}

// AI gives files a second opinion ("AI scanner"). The default provider is
// XMart Guard's built-in model: free, local, no network. "portal" sends files
// to the portal, which asks the free AI APIs configured there (Gemini, Groq,
// OpenRouter, ...) with automatic failover between keys, and shares every
// verdict with all linked servers.
type AI struct {
	Enabled  bool   `json:"enabled"`
	Provider string `json:"provider"` // builtin | portal
	// Scope is what the portal AI checks: "suspicious" findings only, or
	// "all" new and changed code files (to learn from them).
	Scope string `json:"scope"`
	// MaxPerHour caps files sent to the portal per hour (scope "all").
	MaxPerHour int `json:"max_per_hour"`
	// MaxKB caps how much of a file is sent (the excerpt keeps the
	// suspicious parts; long encoded strings are shortened).
	MaxKB int `json:"max_kb"`
	// Act lets a "malicious" verdict apply the virus action; otherwise the
	// verdict is only shown.
	Act bool `json:"act"`
	// RestoreClean restores a quarantined or disabled file when the AI is at
	// least 90% sure it is clean (a false positive), and the scanner stops
	// flagging that content on every server.
	RestoreClean bool `json:"restore_clean"`
	// Learn uses the fleet's shared knowledge: files any linked server's AI
	// found malicious are detected here at once, and the built-in model is
	// updated with what the AI taught it.
	Learn bool `json:"learn"`
}

// ProcessMonitor looks for malicious processes running under users.
type ProcessMonitor struct {
	Enabled          bool     `json:"enabled"`
	Kill             bool     `json:"kill"`
	WhitelistUsers   []string `json:"whitelist_users"`
	WhitelistStrings []string `json:"whitelist_strings"`
}

// CronMonitor checks user crontabs for malicious entries.
type CronMonitor struct {
	Enabled        bool     `json:"enabled"`
	WhitelistUsers []string `json:"whitelist_users"`
}

// Rootkit runs rkhunter (when installed) every week.
type Rootkit struct {
	Enabled bool `json:"enabled"`
}

type Reputation struct {
	Enabled       bool     `json:"enabled"`
	IPs           []string `json:"ips"` // empty = all server IPs
	RBLs          []string `json:"rbls"`
	IntervalHours int      `json:"interval_hours"`
}

// WAF is XMart Guard's ModSecurity rule set for Apache/LiteSpeed.
type WAF struct {
	Enabled        bool     `json:"enabled"`
	UploadScan     bool     `json:"upload_scan"`     // scan uploaded files with the malware engine
	SensitiveFiles bool     `json:"sensitive_files"` // .env, .git, backups, logs
	WordPress      bool     `json:"wordpress"`       // WordPress hardening
	BadBots        bool     `json:"bad_bots"`        // vulnerability scanners and abusive tools
	SEOBots        bool     `json:"seo_bots"`        // aggressive SEO crawlers
	AIBots         bool     `json:"ai_bots"`         // AI training crawlers
	CustomBots     []string `json:"custom_bots"`     // extra User-Agent fragments to block
	BruteForce     bool     `json:"bruteforce"`      // ban IPs with repeated failed CMS logins
	BFThreshold    int      `json:"bf_threshold"`
	BFWindowMin    int      `json:"bf_window_minutes"`
	DisabledRules  []int    `json:"disabled_rules"` // any ModSecurity rule id, ours or a vendor's
	WhitelistIPs   []string `json:"whitelist_ips"`  // never inspected by our rules
	// LoginURLs are the login pages whose failed attempts count toward bans.
	LoginURLs []string `json:"login_urls"`
	// Webshell blocks requests to known web shell file names and parameters.
	Webshell bool `json:"webshell"`
	// BlockPHPUpload rejects any uploaded file with a PHP extension.
	BlockPHPUpload bool `json:"block_php_upload"`
	// WhitelistDomains are websites our rules never inspect.
	WhitelistDomains []string `json:"whitelist_domains"`
}

// CMS controls WordPress/Joomla/OpenCart monitoring.
type CMS struct {
	Enabled       bool `json:"enabled"`
	CoreCheck     bool `json:"core_check"` // verify WordPress core files against official checksums
	DBScan        bool `json:"db_scan"`    // scan WordPress databases for injected code
	IntervalHours int  `json:"interval_hours"`
	// Vulns looks plugins, themes and core up in a public vulnerability
	// database (wpvulnerability.net, no key needed).
	Vulns bool `json:"vulns"`
	// AutoUpdate updates vulnerable components that meet the conditions.
	AutoUpdate       bool     `json:"auto_update"`
	AutoUpdateCVSS   float64  `json:"auto_update_cvss"`  // only if a vulnerability scores above this (0 = any)
	AutoUpdateDays   int      `json:"auto_update_days"`  // only if the fix was released more than N days ago (0 = any)
	BlacklistPlugins []string `json:"blacklist_plugins"` // deactivated automatically
	ExcludeUsers     []string `json:"exclude_users"`     // never patched automatically
	WPCron           bool     `json:"wp_cron"`           // replace wp-cron.php page loads with a real cron job
	WPCronHours      int      `json:"wp_cron_hours"`
}

// OSM is the Outgoing Spam Monitor (Exim).
type OSM struct {
	Enabled          bool     `json:"enabled"`
	PerMinute        int      `json:"per_minute"` // messages per sender per minute
	PerHour          int      `json:"per_hour"`   // messages per sender per hour
	Action           string   `json:"action"`     // notify | hold | suspend (cPanel outgoing mail)
	CheckSubjects    bool     `json:"check_subjects"`
	SpamPatterns     []string `json:"spam_patterns"` // subject fragments (case-insensitive)
	WhitelistSenders []string `json:"whitelist_senders"`
	WhitelistIPs     []string `json:"whitelist_ips"`
	WhitelistPaths   []string `json:"whitelist_paths"` // script directories (cwd prefixes)
}

// AutoSuspend suspends cPanel accounts that keep getting infected.
type AutoSuspend struct {
	Enabled      bool     `json:"enabled"`
	Detections   int      `json:"detections"`   // malware detections...
	WindowHours  int      `json:"window_hours"` // ...within this many hours
	ExcludeUsers []string `json:"exclude_users"`
	// OnDomainBlacklist suspends accounts whose domain is blacklisted.
	OnDomainBlacklist bool     `json:"on_domain_blacklist"`
	WhitelistDomains  []string `json:"whitelist_domains"`
}

// DomainReputation checks hosted domains against domain blocklists.
type DomainReputation struct {
	Enabled         bool   `json:"enabled"`
	IntervalHours   int    `json:"interval_hours"`
	SafeBrowsingKey string `json:"safe_browsing_key"` // optional Google Safe Browsing API key
}

// IPDB is the portal-wide shared blocklist: servers report attackers they
// ban, the portal aggregates the reports and distributes a list that every
// server drops at the firewall.
type IPDB struct {
	Enabled bool `json:"enabled"` // drop traffic from IPDB-listed addresses
	Report  bool `json:"report"`  // share this server's automatic bans with the IPDB
	Log     bool `json:"log"`     // sample blocked connections for the live monitor
	Captcha bool `json:"captcha"` // show IPDB-listed visitors a CAPTCHA instead of dropping web traffic
}

type Notifications struct {
	Email        string `json:"email"`
	OnVirus      bool   `json:"on_virus"`
	OnSuspicious bool   `json:"on_suspicious"`
	OnBinary     bool   `json:"on_binary"`
	OnBan        bool   `json:"on_ban"`
	OnBlacklist  bool   `json:"on_blacklist"`
	// Additional recipients and channels.
	ExtraEmail    string `json:"extra_email"`
	From          string `json:"from"`
	SlackWebhook  string `json:"slack_webhook"`
	TelegramToken string `json:"telegram_token"`
	TelegramChat  string `json:"telegram_chat"`
	DailyReport   bool   `json:"daily_report"`
	// User notifications go to the cPanel account's contact email.
	UserInfected   bool     `json:"user_infected"`
	UserSuspension bool     `json:"user_suspension"`
	UserPatches    bool     `json:"user_patches"`
	UserOutdated   string   `json:"user_outdated"` // never | weekly | monthly
	ExcludeUsers   []string `json:"exclude_users"`
}

// Settings is the full policy document.
type Settings struct {
	Scanner       Scanner          `json:"scanner"`
	Firewall      Firewall         `json:"firewall"`
	Reputation    Reputation       `json:"reputation"`
	IPDB          IPDB             `json:"ipdb"`
	WAF           WAF              `json:"waf"`
	CMS           CMS              `json:"cms"`
	OSM           OSM              `json:"osm"`
	AutoSuspend   AutoSuspend      `json:"auto_suspend"`
	DomainRep     DomainReputation `json:"domain_reputation"`
	Notifications Notifications    `json:"notifications"`
	Captcha       Captcha          `json:"captcha"`
	AI            AI               `json:"ai"`
	Processes     ProcessMonitor   `json:"processes"`
	Cron          CronMonitor      `json:"cron"`
	Rootkit       Rootkit          `json:"rootkit"`
}

// Defaults are safe: detections are reported, not acted on, until an admin
// opts into quarantine.
func Defaults() Settings {
	return Settings{
		Scanner: Scanner{
			Enabled: true, Realtime: true,
			VirusAction: ActionQuarantine, SuspiciousAction: ActionNotify, BinaryAction: ActionNotify,
			DailyScan: true, WeeklyScan: true, MaxFileSizeMB: 10,
			WhitelistUsers: []string{}, WhitelistPaths: []string{}, BlacklistNames: []string{},
			DeleteSymlinks: false, AutoClean: false, Feeds: true, WPCoreRepair: true, Trim: false, TrimMaxPercent: 20, UserScans: true, YARA: true, DBWhitelist: []Exclusion{}, KeepDays: 60,
		},
		Firewall: Firewall{
			Enabled: true, Provider: "iptables", BruteForce: true, BFThreshold: 5, BFWindowMinutes: 10, BanMinutes: 60,
			DoS: false, DoSThreshold: 150, BlockedCountries: []string{}, AllowedCountries: []string{}, LogBlocked: true,
			IgnoredCountries: []string{}, DDNS: []string{}, ExcludedJails: []string{}, WAFBan: true, WAFBanThreshold: 15,
			Captcha: false, TCPIn: DefaultTCPIn, UDPIn: DefaultUDPIn, TCPOut: DefaultTCPOut, UDPOut: DefaultUDPOut,
		},
		Reputation: Reputation{Enabled: true, IPs: []string{}, RBLs: DefaultRBLs(), IntervalHours: 12},
		IPDB:       IPDB{Enabled: true, Report: true, Log: true},
		CMS: CMS{Enabled: true, CoreCheck: true, DBScan: true, IntervalHours: 24, Vulns: true,
			AutoUpdateCVSS: 6, AutoUpdateDays: 7, BlacklistPlugins: []string{}, ExcludeUsers: []string{}, WPCronHours: 12},
		OSM: OSM{Enabled: true, PerMinute: 50, PerHour: 300, Action: "notify", CheckSubjects: true,
			SpamPatterns: []string{}, WhitelistSenders: []string{}, WhitelistIPs: []string{}, WhitelistPaths: []string{}},
		AutoSuspend: AutoSuspend{Enabled: false, Detections: 10, WindowHours: 24, ExcludeUsers: []string{}, WhitelistDomains: []string{}},
		DomainRep:   DomainReputation{Enabled: true, IntervalHours: 12},
		WAF: WAF{Enabled: true, UploadScan: true, SensitiveFiles: true, WordPress: true, BadBots: true,
			CustomBots: []string{}, BruteForce: true, BFThreshold: 10, BFWindowMin: 10, DisabledRules: []int{}, WhitelistIPs: []string{},
			LoginURLs: []string{"/wp-login.php", "/xmlrpc.php", "/administrator/index.php", "/admin/index.php"}, Webshell: true, WhitelistDomains: []string{}},
		Notifications: Notifications{
			OnVirus: true, OnSuspicious: false, OnBinary: false, OnBan: false, OnBlacklist: true,
			UserOutdated: "never", ExcludeUsers: []string{},
		},
		Captcha:   Captcha{Provider: "builtin", AllowMinutes: 60, HTTPPort: 7780, HTTPSPort: 7743},
		AI:        AI{Enabled: true, Provider: "builtin", Scope: "suspicious", MaxPerHour: 120, MaxKB: 12, Learn: true, RestoreClean: true},
		Processes: ProcessMonitor{Enabled: true, Kill: false, WhitelistUsers: []string{}, WhitelistStrings: []string{}},
		Cron:      CronMonitor{Enabled: true, WhitelistUsers: []string{}},
		Rootkit:   Rootkit{Enabled: true},
	}
}

// Store guards the settings file.
type Store struct {
	mu  sync.RWMutex
	cur Settings
}

func path() string { return filepath.Join(config.Dir(), "settings.json") }

// Load reads settings, filling missing fields with defaults.
func Load() (*Store, error) {
	s := Defaults()
	raw, err := os.ReadFile(path())
	if err == nil {
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, fmt.Errorf("settings: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	normalize(&s)
	return &Store{cur: s}, nil
}

// Get returns a copy of the current settings.
func (st *Store) Get() Settings {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return st.cur
}

// Patch applies a partial JSON document (e.g. {"scanner":{"realtime":false}})
// and persists the result.
func (st *Store) Patch(patch json.RawMessage) (Settings, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	next := st.cur
	if err := json.Unmarshal(patch, &next); err != nil {
		return st.cur, fmt.Errorf("invalid settings: %w", err)
	}
	normalize(&next)
	if err := validate(next); err != nil {
		return st.cur, err
	}
	if err := save(next); err != nil {
		return st.cur, err
	}
	st.cur = next
	return next, nil
}

func save(s Settings) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(config.Dir(), 0o700); err != nil {
		return err
	}
	tmp := path() + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path())
}

func clean(list []string, upper bool) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, v := range list {
		v = strings.TrimSpace(v)
		if upper {
			v = strings.ToUpper(v)
		}
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

func normalize(s *Settings) {
	s.Scanner.WhitelistUsers = clean(s.Scanner.WhitelistUsers, false)
	s.Scanner.WhitelistPaths = clean(s.Scanner.WhitelistPaths, false)
	s.Scanner.BlacklistNames = clean(s.Scanner.BlacklistNames, false)
	s.Firewall.BlockedCountries = clean(s.Firewall.BlockedCountries, true)
	s.Firewall.AllowedCountries = clean(s.Firewall.AllowedCountries, true)
	s.Reputation.IPs = clean(s.Reputation.IPs, false)
	s.Reputation.RBLs = clean(s.Reputation.RBLs, false)
	s.WAF.CustomBots = clean(s.WAF.CustomBots, false)
	s.WAF.WhitelistIPs = clean(s.WAF.WhitelistIPs, false)
	if s.WAF.DisabledRules == nil {
		s.WAF.DisabledRules = []int{}
	}
	s.OSM.SpamPatterns = clean(s.OSM.SpamPatterns, false)
	s.OSM.WhitelistSenders = clean(s.OSM.WhitelistSenders, false)
	s.OSM.WhitelistIPs = clean(s.OSM.WhitelistIPs, false)
	s.OSM.WhitelistPaths = clean(s.OSM.WhitelistPaths, false)
	s.AutoSuspend.ExcludeUsers = clean(s.AutoSuspend.ExcludeUsers, false)
	s.AutoSuspend.WhitelistDomains = clean(lower(s.AutoSuspend.WhitelistDomains), false)
	s.Firewall.IgnoredCountries = clean(s.Firewall.IgnoredCountries, true)
	s.Firewall.DDNS = clean(lower(s.Firewall.DDNS), false)
	s.Firewall.ExcludedJails = clean(s.Firewall.ExcludedJails, false)
	if s.Firewall.WAFBanThreshold <= 0 {
		s.Firewall.WAFBanThreshold = 15
	}
	for _, p := range []*string{&s.Firewall.TCPIn, &s.Firewall.UDPIn, &s.Firewall.TCPOut, &s.Firewall.UDPOut} {
		*p = strings.Join(splitPorts(*p), ",")
	}
	s.WAF.LoginURLs = clean(s.WAF.LoginURLs, false)
	s.WAF.WhitelistDomains = clean(lower(s.WAF.WhitelistDomains), false)
	s.CMS.BlacklistPlugins = clean(lower(s.CMS.BlacklistPlugins), false)
	s.CMS.ExcludeUsers = clean(s.CMS.ExcludeUsers, false)
	if s.CMS.WPCronHours <= 0 {
		s.CMS.WPCronHours = 12
	}
	if s.Scanner.KeepDays <= 0 {
		s.Scanner.KeepDays = 60
	}
	if s.Scanner.DBWhitelist == nil {
		s.Scanner.DBWhitelist = []Exclusion{}
	}
	if s.Captcha.Provider == "" {
		s.Captcha.Provider = "builtin"
	}
	if s.Captcha.AllowMinutes <= 0 {
		s.Captcha.AllowMinutes = 60
	}
	if s.Captcha.HTTPPort <= 0 {
		s.Captcha.HTTPPort = 7780
	}
	if s.Captcha.HTTPSPort <= 0 {
		s.Captcha.HTTPSPort = 7743
	}
	s.Captcha.SiteKey, s.Captcha.SecretKey = strings.TrimSpace(s.Captcha.SiteKey), strings.TrimSpace(s.Captcha.SecretKey)
	switch s.AI.Provider {
	case "":
		s.AI.Provider = "builtin"
	case "ollama", "anthropic":
		// 0.5 per-server LLM providers: AI APIs are now configured once on
		// the portal.
		s.AI.Provider = "portal"
	}
	if s.AI.Scope == "" {
		s.AI.Scope = "suspicious"
	}
	if s.AI.MaxPerHour <= 0 {
		s.AI.MaxPerHour = 120
	}
	if s.AI.MaxKB <= 0 || s.AI.MaxKB == 48 {
		s.AI.MaxKB = 12
	}
	if s.Scanner.TrimMaxPercent <= 0 {
		s.Scanner.TrimMaxPercent = 20
	}
	s.Processes.WhitelistUsers = clean(s.Processes.WhitelistUsers, false)
	s.Processes.WhitelistStrings = clean(s.Processes.WhitelistStrings, false)
	s.Cron.WhitelistUsers = clean(s.Cron.WhitelistUsers, false)
	s.Notifications.ExcludeUsers = clean(s.Notifications.ExcludeUsers, false)
	if s.Notifications.UserOutdated == "" {
		s.Notifications.UserOutdated = "never"
	}
	if s.OSM.PerMinute <= 0 {
		s.OSM.PerMinute = 50
	}
	if s.OSM.PerHour <= 0 {
		s.OSM.PerHour = 300
	}
	if s.OSM.Action == "" {
		s.OSM.Action = "notify"
	}
	if s.AutoSuspend.Detections <= 0 {
		s.AutoSuspend.Detections = 10
	}
	if s.AutoSuspend.WindowHours <= 0 {
		s.AutoSuspend.WindowHours = 24
	}
	if s.DomainRep.IntervalHours <= 0 {
		s.DomainRep.IntervalHours = 12
	}
	s.DomainRep.SafeBrowsingKey = strings.TrimSpace(s.DomainRep.SafeBrowsingKey)
	if s.CMS.IntervalHours <= 0 {
		s.CMS.IntervalHours = 24
	}
	if s.WAF.BFThreshold <= 0 {
		s.WAF.BFThreshold = 10
	}
	if s.WAF.BFWindowMin <= 0 {
		s.WAF.BFWindowMin = 10
	}
	if s.Scanner.MaxFileSizeMB <= 0 {
		s.Scanner.MaxFileSizeMB = 10
	}
	if s.Firewall.BFThreshold <= 0 {
		s.Firewall.BFThreshold = 5
	}
	if s.Firewall.BFWindowMinutes <= 0 {
		s.Firewall.BFWindowMinutes = 10
	}
	if s.Firewall.BanMinutes <= 0 {
		s.Firewall.BanMinutes = 60
	}
	if s.Firewall.DoSThreshold <= 0 {
		s.Firewall.DoSThreshold = 150
	}
	if s.Firewall.Provider == "" {
		s.Firewall.Provider = "iptables"
	}
	if s.Reputation.IntervalHours <= 0 {
		s.Reputation.IntervalHours = 12
	}
}

func validate(s Settings) error {
	for _, a := range []string{s.Scanner.VirusAction, s.Scanner.SuspiciousAction, s.Scanner.BinaryAction} {
		switch a {
		case ActionNotify, ActionQuarantine, ActionDisable:
		default:
			return fmt.Errorf("invalid action %q", a)
		}
	}
	for _, c := range append(append([]string{}, s.Firewall.BlockedCountries...), s.Firewall.AllowedCountries...) {
		if len(c) != 2 {
			return fmt.Errorf("invalid country code %q", c)
		}
	}
	for _, p := range s.Scanner.WhitelistPaths {
		if !strings.HasPrefix(p, "/") && strings.Contains(p, "/") {
			return fmt.Errorf("whitelist path must be absolute or a file name: %q", p)
		}
	}
	if s.Firewall.Provider != "iptables" && s.Firewall.Provider != "nftables" {
		return fmt.Errorf("invalid firewall provider %q", s.Firewall.Provider)
	}
	for _, b := range s.WAF.CustomBots {
		if len(b) < 3 || strings.ContainsAny(b, "\n\r\"'\\") {
			return fmt.Errorf("invalid bot name %q", b)
		}
	}
	for _, id := range s.WAF.DisabledRules {
		if id <= 0 || id > 99999999 {
			return fmt.Errorf("invalid rule id %d", id)
		}
	}
	switch s.OSM.Action {
	case "notify", "hold", "suspend":
	default:
		return fmt.Errorf("invalid outgoing spam action %q", s.OSM.Action)
	}
	for _, ip := range s.OSM.WhitelistIPs {
		if !validIPorCIDR(ip) {
			return fmt.Errorf("invalid IP address %q", ip)
		}
	}
	if len(s.DomainRep.SafeBrowsingKey) > 200 || strings.ContainsAny(s.DomainRep.SafeBrowsingKey, " \t\n/?&") {
		return errors.New("invalid Safe Browsing API key")
	}
	for _, ip := range s.WAF.WhitelistIPs {
		if !validIPorCIDR(ip) {
			return fmt.Errorf("invalid IP address %q", ip)
		}
	}
	for _, c := range s.Firewall.IgnoredCountries {
		if len(c) != 2 {
			return fmt.Errorf("invalid country code %q", c)
		}
	}
	for _, h := range s.Firewall.DDNS {
		if !validHostname(h) {
			return fmt.Errorf("invalid DDNS hostname %q", h)
		}
	}
	for _, d := range append(append([]string{}, s.WAF.WhitelistDomains...), s.AutoSuspend.WhitelistDomains...) {
		if !validHostname(d) {
			return fmt.Errorf("invalid domain %q", d)
		}
	}
	for _, u := range s.WAF.LoginURLs {
		if !strings.HasPrefix(u, "/") || strings.ContainsAny(u, " \"'\\\n") {
			return fmt.Errorf("invalid URL path %q (must start with /)", u)
		}
	}
	for _, list := range []string{s.Firewall.TCPIn, s.Firewall.UDPIn, s.Firewall.TCPOut, s.Firewall.UDPOut} {
		if err := validPorts(list); err != nil {
			return err
		}
	}
	if s.Firewall.PortFilter {
		if len(splitPorts(s.Firewall.TCPIn)) == 0 {
			return errors.New("port filter: TCP IN must list at least the SSH port")
		}
		if !portListed(s.Firewall.UDPOut, 53) && !portListed(s.Firewall.TCPOut, 53) {
			return errors.New("port filter: allow outgoing port 53 (DNS), or the server cannot resolve names")
		}
	}
	switch s.Captcha.Provider {
	case "builtin":
	case "turnstile", "recaptcha":
		if s.Captcha.SiteKey == "" || s.Captcha.SecretKey == "" {
			return fmt.Errorf("the %s CAPTCHA needs a site key and a secret key", s.Captcha.Provider)
		}
	default:
		return fmt.Errorf("invalid CAPTCHA provider %q", s.Captcha.Provider)
	}
	if s.Captcha.HTTPPort == s.Captcha.HTTPSPort || s.Captcha.HTTPPort > 65535 || s.Captcha.HTTPSPort > 65535 {
		return errors.New("invalid CAPTCHA ports")
	}
	switch s.AI.Provider {
	case "builtin", "portal":
	default:
		return fmt.Errorf("invalid AI provider %q", s.AI.Provider)
	}
	switch s.AI.Scope {
	case "suspicious", "all":
	default:
		return fmt.Errorf("invalid AI scope %q (suspicious or all)", s.AI.Scope)
	}
	if s.AI.MaxKB > 64 {
		return errors.New("AI scanner: at most 64 KB per file")
	}
	if s.AI.MaxPerHour > 5000 {
		return errors.New("AI scanner: at most 5000 files per hour")
	}
	if s.Scanner.TrimMaxPercent > 50 {
		return errors.New("trim: at most 50% of a file may be removed")
	}
	switch s.Notifications.UserOutdated {
	case "never", "weekly", "monthly":
	default:
		return fmt.Errorf("invalid outdated CMS notification interval %q", s.Notifications.UserOutdated)
	}
	if w := s.Notifications.SlackWebhook; w != "" && !strings.HasPrefix(w, "https://hooks.slack.com/") {
		return errors.New("the Slack webhook must start with https://hooks.slack.com/")
	}
	if s.CMS.AutoUpdateCVSS < 0 || s.CMS.AutoUpdateCVSS > 10 || s.CMS.AutoUpdateDays < 0 {
		return errors.New("invalid auto-update conditions")
	}
	if s.Firewall.DoSThreshold < 20 {
		return errors.New("DoS threshold must be at least 20 connections per minute")
	}
	return nil
}

func lower(list []string) []string {
	out := make([]string, len(list))
	for i, v := range list {
		out[i] = strings.ToLower(v)
	}
	return out
}

func validHostname(h string) bool {
	if len(h) < 3 || len(h) > 253 || !strings.Contains(h, ".") {
		return false
	}
	for _, r := range h {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '.' || r == '*') {
			return false
		}
	}
	return true
}

// Default port filter lists (typical cPanel server).
const (
	DefaultTCPIn  = "20-22,25,53,80,110,143,443,465,587,853,993,995,2077-2078,2079-2080,2082-2083,2086-2087,2095-2096"
	DefaultUDPIn  = "20-21,53,80,443,853"
	DefaultTCPOut = "20-22,25,37,43,53,80,110,113,443,465,587,853,873,993,995,2086-2087,2089,2703"
	DefaultUDPOut = "20-21,53,113,123,853,873,6277,24441"
)

// SplitPorts parses "22, 80,1000-2000" into clean items.
func SplitPorts(s string) []string { return splitPorts(s) }

func splitPorts(s string) []string {
	out := []string{}
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == ';' }) {
		f = strings.ReplaceAll(strings.TrimSpace(f), ":", "-")
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

func validPorts(s string) error {
	for _, p := range splitPorts(s) {
		lo, hi, isRange := strings.Cut(p, "-")
		a, err1 := strconv.Atoi(lo)
		b := a
		var err2 error
		if isRange {
			b, err2 = strconv.Atoi(hi)
		}
		if err1 != nil || err2 != nil || a < 1 || b > 65535 || b < a {
			return fmt.Errorf("invalid port or range %q", p)
		}
	}
	return nil
}

func portListed(s string, port int) bool {
	for _, p := range splitPorts(s) {
		lo, hi, isRange := strings.Cut(p, "-")
		a, _ := strconv.Atoi(lo)
		b := a
		if isRange {
			b, _ = strconv.Atoi(hi)
		}
		if port >= a && port <= b {
			return true
		}
	}
	return false
}

// PortListed reports whether port is in a port list.
func PortListed(s string, port int) bool { return portListed(s, port) }

func validIPorCIDR(s string) bool {
	if net.ParseIP(s) != nil {
		return true
	}
	_, _, err := net.ParseCIDR(s)
	return err == nil
}

// DefaultRBLs are widely used, free-to-query DNS blocklists.
func DefaultRBLs() []string {
	return []string{
		"zen.spamhaus.org", "bl.spamcop.net", "b.barracudacentral.org", "dnsbl.sorbs.net",
		"spam.dnsbl.sorbs.net", "psbl.surriel.com", "bl.mailspike.net", "dnsbl-1.uceprotect.net",
		"dnsbl-2.uceprotect.net", "dnsbl-3.uceprotect.net", "cbl.abuseat.org", "dnsbl.dronebl.org",
		"ix.dnsbl.manitu.net", "truncate.gbudb.net", "db.wpbl.info", "spamrbl.imp.ch",
		"bl.blocklist.de", "all.s5h.net", "dnsbl.spfbl.net", "rbl.interserver.net",
		"spam.pedantic.org", "dnsbl.kempt.net", "ubl.unsubscore.com", "bl.suomispam.net",
		"blacklist.woody.ch", "combined.abuse.ch", "drone.abuse.ch", "korea.services.net",
		"z.mailspike.net", "bl.0spam.org", "relays.nether.net", "backscatter.spameatingmonkey.net",
		"bl.spameatingmonkey.net", "spamsources.fabel.dk", "dnsbl.anticaptcha.net", "rbl.abuse.ro",
	}
}

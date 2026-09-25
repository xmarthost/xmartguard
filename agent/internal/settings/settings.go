// Package settings holds the agent's security policy. It lives on the server
// (/etc/xmartguard/settings.json) so protection keeps working when the portal
// is unreachable; the portal reads and writes it through agent commands.
package settings

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
	UseClamAV        bool     `json:"use_clamav"`
	MaxFileSizeMB    int      `json:"max_file_size_mb"`
	WhitelistUsers   []string `json:"whitelist_users"`
	WhitelistPaths   []string `json:"whitelist_paths"`
	BlacklistNames   []string `json:"blacklist_names"`
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
}

type Reputation struct {
	Enabled       bool     `json:"enabled"`
	IPs           []string `json:"ips"` // empty = all server IPs
	RBLs          []string `json:"rbls"`
	IntervalHours int      `json:"interval_hours"`
}

// IPDB is the portal-wide shared blocklist: servers report attackers they
// ban, the portal aggregates the reports and distributes a list that every
// server drops at the firewall.
type IPDB struct {
	Enabled bool `json:"enabled"` // drop traffic from IPDB-listed addresses
	Report  bool `json:"report"`  // share this server's automatic bans with the IPDB
}

type Notifications struct {
	Email        string `json:"email"`
	OnVirus      bool   `json:"on_virus"`
	OnSuspicious bool   `json:"on_suspicious"`
	OnBinary     bool   `json:"on_binary"`
	OnBan        bool   `json:"on_ban"`
	OnBlacklist  bool   `json:"on_blacklist"`
}

// Settings is the full policy document.
type Settings struct {
	Scanner       Scanner       `json:"scanner"`
	Firewall      Firewall      `json:"firewall"`
	Reputation    Reputation    `json:"reputation"`
	IPDB          IPDB          `json:"ipdb"`
	Notifications Notifications `json:"notifications"`
}

// Defaults are safe: detections are reported, not acted on, until an admin
// opts into quarantine.
func Defaults() Settings {
	return Settings{
		Scanner: Scanner{
			Enabled: true, Realtime: true,
			VirusAction: ActionNotify, SuspiciousAction: ActionNotify, BinaryAction: ActionNotify,
			DailyScan: true, WeeklyScan: true, UseClamAV: true, MaxFileSizeMB: 10,
			WhitelistUsers: []string{}, WhitelistPaths: []string{}, BlacklistNames: []string{},
		},
		Firewall: Firewall{
			Enabled: true, Provider: "iptables", BruteForce: true, BFThreshold: 5, BFWindowMinutes: 10, BanMinutes: 60,
			DoS: false, DoSThreshold: 150, BlockedCountries: []string{}, AllowedCountries: []string{},
		},
		Reputation: Reputation{Enabled: true, IPs: []string{}, RBLs: DefaultRBLs(), IntervalHours: 12},
		IPDB:       IPDB{Enabled: true, Report: true},
		Notifications: Notifications{
			OnVirus: true, OnSuspicious: false, OnBinary: false, OnBan: false, OnBlacklist: true,
		},
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
	if s.Firewall.DoSThreshold < 20 {
		return errors.New("DoS threshold must be at least 20 connections per minute")
	}
	return nil
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

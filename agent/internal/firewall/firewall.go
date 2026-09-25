package firewall

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/settings"
	"github.com/xmarthost/xmartguard/agent/internal/store"
)

// Kinds of stored rules.
const (
	KindAllow     = "allow"
	KindDeny      = "deny"
	KindTempBan   = "tempban"
	KindTempAllow = "tempallow"
	KindIgnore    = "ignore"
)

// Rule is one stored firewall entry.
type Rule struct {
	ID        int64  `json:"id"`
	Kind      string `json:"kind"`
	CIDR      string `json:"cidr"`
	Comment   string `json:"comment"`
	CreatedAt int64  `json:"created_at"`
	ExpiresAt int64  `json:"expires_at"`
}

// Event is a block event shown in Firewall Logs.
type Event struct {
	ID        int64  `json:"id"`
	IP        string `json:"ip"`
	Reason    string `json:"reason"`
	Source    string `json:"source"`
	CreatedAt int64  `json:"created_at"`
	ExpiresAt int64  `json:"expires_at"`
	Status    string `json:"status"`
}

// Manager keeps the database and the kernel ruleset in sync.
type Manager struct {
	DB       *sql.DB
	Settings *settings.Store
	Log      *slog.Logger
	NFT      NFT
	IPT      IPTables
	Geo      *Geo
	IPDB     *IPDB
	// Protected returns IPs that must never be blocked (server + portal IPs).
	Protected func() []string
	// OnBan is called for automatic bans (notifications).
	OnBan func(Event)

	mu        sync.Mutex
	lastError string
}

// Backend returns the provider selected in settings.
func (m *Manager) Backend() Backend {
	if m.Settings.Get().Firewall.Provider == ProviderNFTables {
		return m.NFT
	}
	return m.IPT
}

func (m *Manager) other() Backend {
	if m.Backend().Name() == ProviderNFTables {
		return m.IPT
	}
	return m.NFT
}

// Status describes the firewall for the portal.
type Status struct {
	Available bool              `json:"available"`
	Enabled   bool              `json:"enabled"`
	Provider  string            `json:"provider"`
	Providers map[string]string `json:"providers"` // name -> "" (ok) or why unavailable
	Healthy   bool              `json:"healthy"`
	Error     string            `json:"error"`
}

func (m *Manager) Status() Status {
	b := m.Backend()
	avail := map[string]string{}
	for _, x := range []Backend{m.IPT, m.NFT} {
		if err := x.Available(); err != nil {
			avail[x.Name()] = err.Error()
		} else {
			avail[x.Name()] = ""
		}
	}
	enabled := m.Settings.Get().Firewall.Enabled
	healthy := enabled && b.Available() == nil && b.Healthy()
	m.mu.Lock()
	defer m.mu.Unlock()
	return Status{Available: b.Available() == nil, Enabled: enabled, Provider: b.Name(), Providers: avail, Healthy: healthy, Error: m.lastError}
}

func (m *Manager) rules(kind string) ([]Rule, error) {
	q := `SELECT id, kind, cidr, comment, created_at, expires_at FROM fw_rules WHERE (expires_at = 0 OR expires_at > ?)`
	args := []any{store.Now()}
	if kind != "" {
		q += ` AND kind = ?`
		args = append(args, kind)
	}
	rows, err := m.DB.Query(q+` ORDER BY id DESC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Rule{}
	for rows.Next() {
		var r Rule
		if err := rows.Scan(&r.ID, &r.Kind, &r.CIDR, &r.Comment, &r.CreatedAt, &r.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// List returns active rules of a kind ("" = all).
func (m *Manager) List(kind string) ([]Rule, error) { return m.rules(kind) }

// Build renders the desired ruleset from the database and settings.
func (m *Manager) Build() (Ruleset, error) {
	cfg := m.Settings.Get().Firewall
	all, err := m.rules("")
	if err != nil {
		return Ruleset{}, err
	}
	rs := Ruleset{TempAllow: map[string]time.Duration{}, TempBan: map[string]time.Duration{}, DoS: cfg.DoS, DoSPerMinute: cfg.DoSThreshold, DoSBanSeconds: cfg.BanMinutes * 60}
	now := time.Now().Unix()
	for _, r := range all {
		switch r.Kind {
		case KindAllow:
			rs.Allow = append(rs.Allow, r.CIDR)
		case KindIgnore:
			rs.Ignore = append(rs.Ignore, r.CIDR)
		case KindDeny:
			rs.Deny = append(rs.Deny, r.CIDR)
		case KindTempAllow:
			rs.TempAllow[r.CIDR] = time.Duration(r.ExpiresAt-now) * time.Second
		case KindTempBan:
			rs.TempBan[r.CIDR] = time.Duration(r.ExpiresAt-now) * time.Second
		}
	}
	// Protected addresses are always exempt.
	if m.Protected != nil {
		rs.Ignore = append(rs.Ignore, m.Protected()...)
	}
	if m.Geo != nil {
		rs.CountryBlock = m.Geo.CIDRs(cfg.BlockedCountries)
		rs.CountryAllow = m.Geo.CIDRs(cfg.AllowedCountries)
	}
	if m.IPDB != nil && m.Settings.Get().IPDB.Enabled {
		rs.IPDB = m.ipdbEntries()
	}
	return rs, nil
}

// Apply rebuilds the kernel ruleset (or removes it when disabled).
func (m *Manager) Apply() error {
	var err error
	// Only one provider may hold rules at a time.
	if o := m.other(); o.Available() == nil {
		_ = o.Remove()
	}
	b := m.Backend()
	if !m.Settings.Get().Firewall.Enabled {
		if b.Available() == nil {
			err = b.Remove()
		}
	} else {
		var rs Ruleset
		rs, err = m.Build()
		if err == nil {
			err = b.Apply(rs)
		}
	}
	m.mu.Lock()
	m.lastError = ""
	if err != nil {
		m.lastError = err.Error()
	}
	m.mu.Unlock()
	if err != nil {
		m.Log.Error("firewall apply failed", "err", err)
	}
	return err
}

func (m *Manager) isProtected(addr string) bool {
	if m.Protected == nil {
		return false
	}
	for _, p := range m.Protected() {
		if Contains(addr, p) || Contains(p, addr) {
			return true
		}
	}
	return false
}

// Add stores a rule and applies it. ttl is used for temp kinds.
func (m *Manager) Add(kind, addr, comment string, ttl time.Duration) (Rule, error) {
	c, err := ParseAddr(addr)
	if err != nil {
		return Rule{}, err
	}
	switch kind {
	case KindAllow, KindIgnore:
	case KindDeny, KindTempBan:
		if m.isProtected(c) {
			return Rule{}, fmt.Errorf("%s belongs to this server or the XMart Guard portal and cannot be blocked", c)
		}
	case KindTempAllow:
	default:
		return Rule{}, fmt.Errorf("unknown rule kind %q", kind)
	}
	if (kind == KindTempBan || kind == KindTempAllow) && strings.Contains(c, "/") {
		return Rule{}, errors.New("temporary rules take a single IP address, not a CIDR")
	}
	var expires int64
	if kind == KindTempBan || kind == KindTempAllow {
		if ttl < time.Minute || ttl > 30*24*time.Hour {
			return Rule{}, errors.New("duration must be between 1 minute and 30 days")
		}
		expires = store.Now() + int64(ttl.Seconds())
	}
	comment = strings.TrimSpace(comment)
	if len(comment) > 200 {
		comment = comment[:200]
	}
	now := store.Now()
	_, err = m.DB.Exec(`INSERT INTO fw_rules (kind, cidr, comment, created_at, expires_at) VALUES (?,?,?,?,?)
		ON CONFLICT(kind, cidr) DO UPDATE SET comment = excluded.comment, created_at = excluded.created_at, expires_at = excluded.expires_at`,
		kind, c, comment, now, expires)
	if err != nil {
		return Rule{}, err
	}
	// Allowing an address lifts any block on it.
	if kind == KindAllow || kind == KindTempAllow || kind == KindIgnore {
		_, _ = m.DB.Exec(`DELETE FROM fw_rules WHERE kind IN ('deny','tempban') AND cidr = ?`, c)
	}
	if kind == KindDeny || kind == KindTempBan {
		_, _ = m.DB.Exec(`INSERT INTO fw_events (ip, reason, source, created_at, expires_at, status) VALUES (?,?,?,?,?,?)`,
			c, orDefault(comment, "manually blocked"), "manual", now, expires, "blocked")
	}
	if m.Settings.Get().Firewall.Enabled {
		if err := m.Apply(); err != nil {
			return Rule{}, err
		}
	}
	return Rule{Kind: kind, CIDR: c, Comment: comment, CreatedAt: now, ExpiresAt: expires}, nil
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

// Remove deletes a rule.
func (m *Manager) Remove(kind, addr string) error {
	c, err := ParseAddr(addr)
	if err != nil {
		return err
	}
	res, err := m.DB.Exec(`DELETE FROM fw_rules WHERE kind = ? AND cidr = ?`, kind, c)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%s is not in the %s list", c, kind)
	}
	if kind == KindDeny || kind == KindTempBan {
		_, _ = m.DB.Exec(`UPDATE fw_events SET status = 'unblocked' WHERE ip = ? AND status = 'blocked'`, c)
	}
	if m.Settings.Get().Firewall.Enabled {
		return m.Apply()
	}
	return nil
}

// Unblock removes every block (deny and temp ban) for an address.
func (m *Manager) Unblock(addr string) error {
	c, err := ParseAddr(addr)
	if err != nil {
		return err
	}
	_, _ = m.DB.Exec(`DELETE FROM fw_rules WHERE kind IN ('deny','tempban') AND cidr = ?`, c)
	_, _ = m.DB.Exec(`UPDATE fw_events SET status = 'unblocked' WHERE ip = ? AND status = 'blocked'`, c)
	if m.Settings.Get().Firewall.Enabled {
		return m.Apply()
	}
	return nil
}

// CheckResult explains how the firewall treats an address.
type CheckResult struct {
	IP        string  `json:"ip"`
	Status    string  `json:"status"` // allowed | blocked | temp-blocked | ignored | country-blocked | none
	Matches   []Rule  `json:"matches"`
	Events    []Event `json:"events"`
	Protected bool    `json:"protected"`
}

// Check looks an IP up in all lists.
func (m *Manager) Check(addr string) (CheckResult, error) {
	ip := net.ParseIP(strings.TrimSpace(addr))
	if ip == nil {
		return CheckResult{}, fmt.Errorf("invalid IP address: %q", addr)
	}
	res := CheckResult{IP: ip.String(), Status: "none", Matches: []Rule{}, Events: []Event{}, Protected: m.isProtected(ip.String())}
	all, err := m.rules("")
	if err != nil {
		return res, err
	}
	prio := map[string]int{KindAllow: 5, KindTempAllow: 4, KindIgnore: 3, KindDeny: 2, KindTempBan: 1}
	best := 0
	for _, r := range all {
		if Contains(r.CIDR, res.IP) {
			res.Matches = append(res.Matches, r)
			if prio[r.Kind] > best {
				best = prio[r.Kind]
				res.Status = map[string]string{KindAllow: "allowed", KindTempAllow: "allowed", KindIgnore: "ignored", KindDeny: "blocked", KindTempBan: "temp-blocked"}[r.Kind]
			}
		}
	}
	if best == 0 && m.IPDB != nil && m.Settings.Get().IPDB.Enabled {
		for _, e := range m.ipdbEntries() {
			if Contains(e, res.IP) {
				res.Status = "ipdb-blocked (" + e + ")"
				best = -1
				break
			}
		}
	}
	if best == 0 && m.Geo != nil {
		cfg := m.Settings.Get().Firewall
		if cc := m.Geo.Lookup(res.IP, cfg.BlockedCountries); cc != "" && m.Geo.Lookup(res.IP, cfg.AllowedCountries) == "" {
			res.Status = "country-blocked (" + cc + ")"
		}
	}
	evs, _, _ := m.Events(EventFilter{Query: res.IP, Limit: 20})
	res.Events = evs
	return res, nil
}

// EventFilter narrows Events.
type EventFilter struct {
	Query  string `json:"q"`
	Status string `json:"status"`
	Limit  int    `json:"limit"`
	Offset int    `json:"offset"`
}

// Events lists block events, newest first.
func (m *Manager) Events(f EventFilter) ([]Event, int, error) {
	m.expire()
	where, args := []string{"1=1"}, []any{}
	if f.Query != "" {
		where, args = append(where, "(ip LIKE ? OR reason LIKE ?)"), append(args, "%"+f.Query+"%", "%"+f.Query+"%")
	}
	if f.Status != "" {
		where, args = append(where, "status = ?"), append(args, f.Status)
	}
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 50
	}
	cond := strings.Join(where, " AND ")
	var total int
	if err := m.DB.QueryRow(`SELECT count(*) FROM fw_events WHERE `+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := m.DB.Query(`SELECT id, ip, reason, source, created_at, expires_at, status FROM fw_events WHERE `+cond+` ORDER BY id DESC LIMIT ? OFFSET ?`, append(args, f.Limit, f.Offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ID, &e.IP, &e.Reason, &e.Source, &e.CreatedAt, &e.ExpiresAt, &e.Status); err != nil {
			return nil, 0, err
		}
		out = append(out, e)
	}
	return out, total, rows.Err()
}

// expire marks finished temp bans and drops expired rules.
func (m *Manager) expire() {
	now := store.Now()
	_, _ = m.DB.Exec(`UPDATE fw_events SET status = 'expired' WHERE status = 'blocked' AND expires_at > 0 AND expires_at <= ?`, now)
	_, _ = m.DB.Exec(`DELETE FROM fw_rules WHERE expires_at > 0 AND expires_at <= ?`, now)
}

// AutoBan is used by brute-force and DoS detection.
func (m *Manager) AutoBan(ip, reason, source string) {
	c, err := ParseAddr(ip)
	if err != nil || m.isProtected(c) {
		return
	}
	for _, r := range mustRules(m) {
		if (r.Kind == KindAllow || r.Kind == KindIgnore || r.Kind == KindTempAllow) && Contains(r.CIDR, c) {
			return
		}
		if (r.Kind == KindTempBan || r.Kind == KindDeny) && r.CIDR == c {
			return // already blocked
		}
	}
	cfg := m.Settings.Get().Firewall
	ttl := time.Duration(cfg.BanMinutes) * time.Minute
	now := store.Now()
	exp := now + int64(ttl.Seconds())
	_, _ = m.DB.Exec(`INSERT INTO fw_rules (kind, cidr, comment, created_at, expires_at) VALUES ('tempban',?,?,?,?)
		ON CONFLICT(kind, cidr) DO UPDATE SET expires_at = excluded.expires_at, comment = excluded.comment`, c, reason, now, exp)
	ev := Event{IP: c, Reason: reason, Source: source, CreatedAt: now, ExpiresAt: exp, Status: "blocked"}
	res, err := m.DB.Exec(`INSERT INTO fw_events (ip, reason, source, created_at, expires_at, status) VALUES (?,?,?,?,?,?)`, c, reason, source, now, exp, "blocked")
	if err == nil {
		ev.ID, _ = res.LastInsertId()
	}
	if cfg.Enabled {
		if err := m.Backend().AddTempBan(c, int(ttl.Seconds())); err != nil {
			_ = m.Apply()
		}
	}
	m.Log.Info("auto-ban", "ip", c, "reason", reason)
	if m.OnBan != nil {
		m.OnBan(ev)
	}
}

func mustRules(m *Manager) []Rule {
	r, _ := m.rules("")
	return r
}

// Stats summarises firewall activity for dashboards.
type Stats struct {
	ActiveBlocks   int               `json:"active_blocks"`
	Blocks30d      int               `json:"blocks_30d"`
	BlocksTotal    int               `json:"blocks_total"`
	DroppedPackets map[string]uint64 `json:"dropped_packets"`
}

func (m *Manager) Stats() Stats {
	m.expire()
	var s Stats
	_ = m.DB.QueryRow(`SELECT count(*) FROM fw_rules WHERE kind IN ('deny','tempban')`).Scan(&s.ActiveBlocks)
	_ = m.DB.QueryRow(`SELECT count(*) FROM fw_events WHERE created_at >= ?`, store.Now()-30*86400).Scan(&s.Blocks30d)
	_ = m.DB.QueryRow(`SELECT count(*) FROM fw_events`).Scan(&s.BlocksTotal)
	if m.Settings.Get().Firewall.Enabled {
		s.DroppedPackets = m.Backend().Counters()
	}
	return s
}

// Run applies the ruleset at start and then keeps it maintained: expiring
// rules, recording DoS auto-bans made inside nftables, and refreshing
// country lists daily.
func (m *Manager) Run(ctx context.Context) {
	_ = m.Apply()
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	lastGeo := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		m.expire()
		cfg := m.Settings.Get().Firewall
		if !cfg.Enabled {
			continue
		}
		// Another firewall (e.g. `csf -r`) may have flushed our rules: reload them.
		if !m.Backend().Healthy() {
			m.Log.Warn("firewall rules missing; reloading", "provider", m.Backend().Name())
			_ = m.Apply()
		}
		if cfg.DoS {
			m.syncDoSBans()
		}
		if m.Settings.Get().IPDB.Enabled {
			m.pollIPDBHits()
		}
		if m.Geo != nil && time.Since(lastGeo) > 24*time.Hour && len(cfg.BlockedCountries)+len(cfg.AllowedCountries) > 0 {
			lastGeo = time.Now()
			m.Geo.Refresh(append(cfg.BlockedCountries, cfg.AllowedCountries...), true)
			_ = m.Apply()
		}
	}
}

// syncDoSBans records bans nftables added itself for rate-limit violations.
func (m *Manager) syncDoSBans() {
	known := map[string]bool{}
	for _, r := range mustRules(m) {
		if r.Kind == KindTempBan {
			known[r.CIDR] = true
		}
	}
	cfg := m.Settings.Get().Firewall
	ips, err := m.Backend().TempBanned()
	if err != nil {
		return
	}
	{
		for _, ip := range ips {
			if known[ip] {
				continue
			}
			now := store.Now()
			exp := now + int64(cfg.BanMinutes*60)
			reason := fmt.Sprintf("DoS: more than %d new connections per minute", cfg.DoSThreshold)
			_, _ = m.DB.Exec(`INSERT OR IGNORE INTO fw_rules (kind, cidr, comment, created_at, expires_at) VALUES ('tempban',?,?,?,?)`, ip, reason, now, exp)
			res, err := m.DB.Exec(`INSERT INTO fw_events (ip, reason, source, created_at, expires_at, status) VALUES (?,?,?,?,?,'blocked')`, ip, reason, "dos", now, exp)
			ev := Event{IP: ip, Reason: reason, Source: "dos", CreatedAt: now, ExpiresAt: exp, Status: "blocked"}
			if err == nil {
				ev.ID, _ = res.LastInsertId()
			}
			if m.OnBan != nil {
				m.OnBan(ev)
			}
		}
	}
}

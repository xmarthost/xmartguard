package firewall

import (
	"bufio"
	"database/sql"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/store"
)

// IPDB holds the shared blocklist distributed by the portal. Entries are kept
// in <state>/ipdb.txt so protection survives restarts and portal outages.
type IPDB struct {
	mu      sync.RWMutex
	loaded  bool
	version string
	entries []string          // canonical IPs/CIDRs
	country map[string]string // entry -> ISO country code
	last    map[string]uint64 // last kernel counter per entry
	exact   map[netip.Addr]string
	nets    []netip.Prefix // sorted, most specific first
}

func (l *IPDB) index() {
	l.exact = map[netip.Addr]string{}
	l.nets = nil
	for _, e := range l.entries {
		if p, err := netip.ParsePrefix(e); err == nil {
			l.nets = append(l.nets, p.Masked())
		} else if a, err := netip.ParseAddr(e); err == nil {
			l.exact[a] = e
		}
	}
	sort.Slice(l.nets, func(i, j int) bool { return l.nets[i].Bits() > l.nets[j].Bits() })
}

// Lookup returns the list entry covering ip and its country ("" if none).
func (l *IPDB) Lookup(ip string) (entry, country string) {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return "", ""
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.load()
	if l.exact == nil {
		l.index()
	}
	if e, ok := l.exact[a]; ok {
		return e, l.country[e]
	}
	for _, p := range l.nets {
		if p.Contains(a) {
			return p.String(), l.country[p.String()]
		}
	}
	return "", ""
}

// IPDBPath is the on-disk copy of the list.
func IPDBPath() string { return filepath.Join(store.StateDir(), "ipdb.txt") }

func (l *IPDB) load() {
	if l.loaded {
		return
	}
	l.loaded = true
	l.country = map[string]string{}
	f, err := os.Open(IPDBPath())
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 64*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if v, ok := strings.CutPrefix(line, "# version "); ok {
			l.version = strings.TrimSpace(v)
			continue
		}
		if line == "" || line[0] == '#' {
			continue
		}
		f := strings.Fields(line)
		c, err := ParseAddr(f[0])
		if err != nil {
			continue
		}
		l.entries = append(l.entries, c)
		if len(f) > 1 {
			l.country[c] = strings.ToUpper(f[1])
		}
	}
}

// Snapshot returns the version and a copy of the entries.
func (l *IPDB) Snapshot() (string, []string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.load()
	return l.version, append([]string(nil), l.entries...)
}

// Country returns the country recorded for an entry.
func (l *IPDB) Country(entry string) string {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.load()
	return l.country[entry]
}

// Replace stores a new list. Each item is "IP-or-CIDR [CC]". Invalid or
// too-broad entries are skipped. Returns the number of entries kept.
func (l *IPDB) Replace(version string, items []string) (int, error) {
	seen := map[string]bool{}
	entries := make([]string, 0, len(items))
	country := map[string]string{}
	var b strings.Builder
	fmt.Fprintf(&b, "# XMart Guard IPDB list (managed by the portal; do not edit)\n# version %s\n", version)
	for _, it := range items {
		f := strings.Fields(it)
		if len(f) == 0 {
			continue
		}
		c, err := ParseAddr(f[0])
		if err != nil || seen[c] {
			continue
		}
		seen[c] = true
		entries = append(entries, c)
		cc := ""
		if len(f) > 1 && len(f[1]) == 2 {
			cc = strings.ToUpper(f[1])
			country[c] = cc
		}
		fmt.Fprintf(&b, "%s %s\n", c, cc)
	}
	if err := os.MkdirAll(store.StateDir(), 0o700); err != nil {
		return 0, err
	}
	tmp := IPDBPath() + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o600); err != nil {
		return 0, err
	}
	if err := os.Rename(tmp, IPDBPath()); err != nil {
		return 0, err
	}
	l.mu.Lock()
	l.loaded, l.version, l.entries, l.country = true, version, entries, country
	l.exact = nil
	l.mu.Unlock()
	return len(entries), nil
}

// recordHits turns kernel per-entry counters into hit deltas and stores them.
func (l *IPDB) recordHits(db *sql.DB, counters map[string]uint64) int {
	l.mu.Lock()
	l.load()
	if l.last == nil {
		l.last = map[string]uint64{}
	}
	type hit struct {
		entry, cc string
		n         uint64
	}
	var hits []hit
	for entry, cur := range counters {
		prev, seen := l.last[entry]
		l.last[entry] = cur
		d := cur
		if seen && cur >= prev {
			d = cur - prev
		}
		if d > 0 {
			hits = append(hits, hit{entry, l.country[entry], d})
		}
	}
	l.mu.Unlock()
	if len(hits) == 0 {
		return 0
	}
	now := store.Now()
	day := time.Unix(now, 0).UTC().Format("2006-01-02")
	tx, err := db.Begin()
	if err != nil {
		return 0
	}
	defer tx.Rollback() //nolint:errcheck
	for _, h := range hits {
		_, _ = tx.Exec(`INSERT INTO ipdb_hits (entry, country, hits, pending, first_seen, last_seen) VALUES (?,?,?,?,?,?)
			ON CONFLICT(entry) DO UPDATE SET hits = hits + excluded.hits, pending = pending + excluded.pending,
			last_seen = excluded.last_seen, country = CASE WHEN excluded.country <> '' THEN excluded.country ELSE country END`,
			h.entry, h.cc, h.n, h.n, now, now)
		_, _ = tx.Exec(`INSERT INTO ipdb_country (day, country, hits) VALUES (?,?,?)
			ON CONFLICT(day, country) DO UPDATE SET hits = hits + excluded.hits`, day, h.cc, h.n)
	}
	_ = tx.Commit()
	return len(hits)
}

// IPDBHit is one list entry that dropped traffic on this server.
type IPDBHit struct {
	Entry     string `json:"entry"`
	Country   string `json:"country"`
	Hits      int64  `json:"hits"`
	FirstSeen int64  `json:"first_seen"`
	LastSeen  int64  `json:"last_seen"`
}

// IPDBReport is an automatic ban shared with the portal.
type IPDBReport struct {
	ID     int64  `json:"id"`
	IP     string `json:"ip"`
	Source string `json:"source"`
	Reason string `json:"reason"`
	At     int64  `json:"at"`
}

// IPDBReports returns automatic bans with id > since (oldest first).
func (m *Manager) IPDBReports(since int64, limit int) ([]IPDBReport, error) {
	rows, err := m.DB.Query(`SELECT id, ip, source, reason, created_at FROM fw_events
		WHERE id > ? AND source IN ('bruteforce','dos','waf','scanner') ORDER BY id LIMIT ?`, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []IPDBReport{}
	for rows.Next() {
		var r IPDBReport
		if err := rows.Scan(&r.ID, &r.IP, &r.Source, &r.Reason, &r.At); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// TakePendingHits returns hits not yet sent to the portal and marks them sent.
func (m *Manager) TakePendingHits(limit int) ([]IPDBHit, error) {
	rows, err := m.DB.Query(`SELECT entry, country, pending, first_seen, last_seen FROM ipdb_hits WHERE pending > 0 ORDER BY last_seen DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	out := []IPDBHit{}
	for rows.Next() {
		var h IPDBHit
		if err := rows.Scan(&h.Entry, &h.Country, &h.Hits, &h.FirstSeen, &h.LastSeen); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, h)
	}
	rows.Close()
	for _, h := range out {
		_, _ = m.DB.Exec(`UPDATE ipdb_hits SET pending = max(pending - ?, 0) WHERE entry = ?`, h.Hits, h.Entry)
	}
	return out, nil
}

// IPDBStatus summarises the IPDB for dashboards and the panel plugins.
type IPDBStatus struct {
	Enabled   bool             `json:"enabled"`
	Report    bool             `json:"report"`
	Version   string           `json:"version"`
	Entries   int              `json:"entries"`
	HitsToday int64            `json:"hits_today"`
	HitsTotal int64            `json:"hits_total"`
	Top       []IPDBHit        `json:"top"`
	Recent    []IPDBHit        `json:"recent"`
	Countries map[string]int64 `json:"countries"` // last 30 days
}

func (m *Manager) IPDBStatus() IPDBStatus {
	cfg := m.Settings.Get().IPDB
	v, entries := m.IPDB.Snapshot()
	s := IPDBStatus{Enabled: cfg.Enabled, Report: cfg.Report, Version: v, Entries: len(entries), Countries: map[string]int64{}}
	today := time.Unix(store.Now(), 0).UTC().Format("2006-01-02")
	_ = m.DB.QueryRow(`SELECT coalesce(sum(hits),0) FROM ipdb_country WHERE day = ?`, today).Scan(&s.HitsToday)
	_ = m.DB.QueryRow(`SELECT coalesce(sum(hits),0) FROM ipdb_hits`).Scan(&s.HitsTotal)
	from := time.Unix(store.Now()-30*86400, 0).UTC().Format("2006-01-02")
	if rows, err := m.DB.Query(`SELECT country, sum(hits) FROM ipdb_country WHERE day >= ? GROUP BY country`, from); err == nil {
		for rows.Next() {
			var cc string
			var n int64
			if rows.Scan(&cc, &n) == nil {
				s.Countries[cc] = n
			}
		}
		rows.Close()
	}
	s.Top = m.hitList(`ORDER BY hits DESC LIMIT 20`)
	s.Recent = m.hitList(`ORDER BY last_seen DESC LIMIT 50`)
	return s
}

func (m *Manager) hitList(order string) []IPDBHit {
	out := []IPDBHit{}
	rows, err := m.DB.Query(`SELECT entry, country, hits, first_seen, last_seen FROM ipdb_hits ` + order)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var h IPDBHit
		if rows.Scan(&h.Entry, &h.Country, &h.Hits, &h.FirstSeen, &h.LastSeen) == nil {
			out = append(out, h)
		}
	}
	return out
}

// ApplyIPDB stores a list from the portal and reloads the firewall if needed.
func (m *Manager) ApplyIPDB(version string, items []string) (int, error) {
	n, err := m.IPDB.Replace(version, items)
	if err != nil {
		return 0, err
	}
	cfg := m.Settings.Get()
	if cfg.Firewall.Enabled && cfg.IPDB.Enabled {
		return n, m.Apply()
	}
	return n, nil
}

// ipdbEntries returns the list minus anything covering a protected address.
func (m *Manager) ipdbEntries() []string {
	_, entries := m.IPDB.Snapshot()
	if len(entries) == 0 {
		return nil
	}
	var prot []string
	if m.Protected != nil {
		prot = m.Protected()
	}
	out := make([]string, 0, len(entries))
next:
	for _, e := range entries {
		for _, p := range prot {
			if Contains(e, p) || Contains(p, e) {
				continue next
			}
		}
		out = append(out, e)
	}
	sort.Strings(out)
	return out
}

// pollIPDBHits reads the kernel's per-entry counters.
func (m *Manager) pollIPDBHits() {
	if m.IPDB == nil {
		return
	}
	counters := m.Backend().IPDBCounters()
	if len(counters) > 0 {
		m.IPDB.recordHits(m.DB, counters)
	}
}

// Collapse drops entries already covered by a broader entry in the list, so
// nftables interval sets never see overlapping elements.
func Collapse(list []string) []string {
	type pfx struct {
		p   netip.Prefix
		raw string
	}
	var ps []pfx
	for _, s := range list {
		var p netip.Prefix
		var err error
		if strings.Contains(s, "/") {
			p, err = netip.ParsePrefix(s)
		} else {
			var a netip.Addr
			if a, err = netip.ParseAddr(s); err == nil {
				p = netip.PrefixFrom(a, a.BitLen())
			}
		}
		if err == nil {
			ps = append(ps, pfx{p.Masked(), s})
		}
	}
	// Broadest first, then by address: a prefix can only be covered by an
	// earlier (shorter or equal) one.
	sort.Slice(ps, func(i, j int) bool {
		if ps[i].p.Bits() != ps[j].p.Bits() {
			return ps[i].p.Bits() < ps[j].p.Bits()
		}
		return ps[i].p.Addr().Less(ps[j].p.Addr())
	})
	kept := map[int][]netip.Prefix{} // bits -> kept prefixes
	var bitsSeen []int
	out := make([]string, 0, len(ps))
next:
	for _, x := range ps {
		for _, b := range bitsSeen {
			if b > x.p.Bits() {
				break
			}
			if parent, err := x.p.Addr().Prefix(b); err == nil {
				if _, ok := index(kept[b], parent); ok {
					continue next
				}
			}
		}
		if len(bitsSeen) == 0 || bitsSeen[len(bitsSeen)-1] != x.p.Bits() {
			bitsSeen = append(bitsSeen, x.p.Bits())
		}
		kept[x.p.Bits()] = append(kept[x.p.Bits()], x.p)
		out = append(out, x.raw)
	}
	sort.Strings(out)
	return out
}

// index finds p in a slice sorted by address (as produced by Collapse).
func index(list []netip.Prefix, p netip.Prefix) (int, bool) {
	i := sort.Search(len(list), func(i int) bool { return !list[i].Addr().Less(p.Addr()) })
	return i, i < len(list) && list[i] == p
}

// IPDBLive is the per-server IPDB monitor: sampled connections and timelines.
type IPDBLive struct {
	Events    []ConnEvent      `json:"events"`
	Minutes   []TimePoint      `json:"minutes"`   // last 10 minutes
	Hourly    []TimePoint      `json:"hourly"`    // last 24 hours
	Countries map[string]int64 `json:"countries"` // last 7 days
	Logging   bool             `json:"logging"`
	// Packets is the running total of packets the IPDB rule dropped, read
	// from the firewall counters now; the live chart plots its growth.
	Packets uint64 `json:"packets"`
	Now     int64  `json:"now"`
}

func (m *Manager) IPDBLive(sinceID int64) IPDBLive {
	now := store.Now()
	ev, _, _ := m.ConnEvents(ConnFilter{Kind: "ipdb", Since: sinceID, Limit: 60})
	out := IPDBLive{
		Events:    ev,
		Minutes:   m.DropTimeline("ipdb", now-10*60, 60),
		Hourly:    m.DropTimeline("ipdb", now-24*3600, 3600),
		Countries: map[string]int64{},
		Logging:   m.Settings.Get().Firewall.LogBlocked,
		Packets:   m.Backend().Counters()["xg-ipdb"],
		Now:       now,
	}
	from := time.Unix(now-7*86400, 0).UTC().Format("2006-01-02")
	if rows, err := m.DB.Query(`SELECT country, sum(hits) FROM ipdb_country WHERE day >= ? GROUP BY country`, from); err == nil {
		for rows.Next() {
			var cc string
			var n int64
			if rows.Scan(&cc, &n) == nil {
				out.Countries[cc] = n
			}
		}
		rows.Close()
	}
	return out
}

package waf

import (
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/xmarthost/xmartguard/agent/internal/store"
)

// New rules first only watch: they log what they would block (the request
// passes, nothing counts toward a ban) until an administrator approves them
// in the portal (Learning Center » Rule approvals). A wrong rule then shows
// up in a report instead of as 403s for real visitors.

// NewRules are the rules added in recent releases (id: the release). Each
// new blocking rule goes here; its +1000/+2000 variants follow it.
var NewRules = map[int]string{
	IDShopScrape: "0.21.31",
	IDCartSpam:   "0.21.31",
	IDNoUAPost:   "0.21.31",
}

// FirstReviewedPatch: portal virtual patches from this id on are new and
// watch until approved (the earlier ones ran for many releases).
const FirstReviewedPatch = 7703007

// Monitored returns the rules that only log on this server: new rules the
// portal has not approved, and portal patches it marks for watching. With
// no word from the portal yet every new rule watches.
func Monitored(in *Intel) map[int]bool {
	out := map[int]bool{}
	enforce := map[int]bool{}
	if in != nil {
		for _, id := range in.Enforce {
			enforce[id] = true
		}
		for _, p := range in.Patches {
			if p.Monitor {
				out[p.ID] = true
			}
		}
	}
	for id := range NewRules {
		if !enforce[id] {
			out[id] = true
		}
	}
	return out
}

// MonitoredIDs is Monitored as a sorted list.
func MonitoredIDs(in *Intel) []int {
	var ids []int
	for id := range Monitored(in) {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	return ids
}

var (
	reRuleID      = regexp.MustCompile(`[",]id:(\d+)[,"]`)
	reDisruptive  = regexp.MustCompile(`([",])(?:deny|drop|block|redirect:[^,"]+)([,"])`)
	reStatus      = regexp.MustCompile(`,status:\d+`)
	reMonitorMsg  = regexp.MustCompile(`msg:'xPGuard - `)
	reMonitorPass = regexp.MustCompile(`([",])pass,pass([,"])`)
	reBlockedMsg  = regexp.MustCompile(`(msg:'xPGuard \[watch\] - [^']*?) blocked'`)
)

// applyMonitor turns the disruptive action of the watched rules (and their
// +1000/+2000 variants) into pass: the match is logged as "[watch]" and
// the request goes on.
func applyMonitor(text string, ids map[int]bool) string {
	if len(ids) == 0 {
		return text
	}
	lines := strings.Split(text, "\n")
	for i, l := range lines {
		if !strings.HasPrefix(l, "SecRule ") && !strings.HasPrefix(l, "SecAction ") {
			continue
		}
		m := reRuleID.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		id, _ := strconv.Atoi(m[1])
		if !ids[id] && !ids[id-1000] && !ids[id-2000] {
			continue
		}
		l = reDisruptive.ReplaceAllString(l, "${1}pass${2}")
		l = reStatus.ReplaceAllString(l, "")
		l = reMonitorPass.ReplaceAllString(l, "${1}pass${2}")
		l = reMonitorMsg.ReplaceAllString(l, "msg:'xPGuard [watch] - ")
		l = reBlockedMsg.ReplaceAllString(l, "${1} (would be blocked)'")
		lines[i] = l
	}
	return strings.Join(lines, "\n")
}

// WatchRule is a new rule with what it matched on this server.
type WatchRule struct {
	ID       int          `json:"id"`
	Title    string       `json:"title"`
	Since    string       `json:"since"`
	Watching bool         `json:"watching"`
	Hits     int          `json:"hits"`
	IPs      int          `json:"ips"`
	Hosts    int          `json:"hosts"`
	Examples []WatchEvent `json:"examples"`
}

// WatchEvent is one request a new rule matched.
type WatchEvent struct {
	At     int64  `json:"at"`
	IP     string `json:"ip"`
	Method string `json:"method"`
	Host   string `json:"host"`
	URI    string `json:"uri"`
	Action string `json:"action"`
	Detail string `json:"detail"`
}

// WatchReport lists the new rules and portal patches under review with
// their matches of the last hours (examples from different sites first).
func (m *Manager) WatchReport(in *Intel, hours int) []WatchRule {
	since := store.Now() - int64(min(max(hours, 1), 24*14))*3600
	watching := Monitored(in)
	titles := map[int]string{}
	for _, r := range Catalog {
		titles[r.ID] = r.Title
	}
	var rules []WatchRule
	for id, rel := range NewRules {
		rules = append(rules, WatchRule{ID: id, Title: titles[id], Since: rel, Watching: watching[id]})
	}
	if in != nil {
		for _, p := range in.Patches {
			if p.ID >= FirstReviewedPatch {
				rules = append(rules, WatchRule{ID: p.ID, Title: "Portal patch: " + p.Title, Since: "portal", Watching: p.Monitor})
			}
		}
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	for i := range rules {
		r := &rules[i]
		ids := []any{r.ID, r.ID + 1000, r.ID + 2000, since}
		_ = m.DB.QueryRow(`SELECT count(*), count(DISTINCT ip), count(DISTINCT host) FROM waf_events WHERE rule_id IN (?,?,?) AND at >= ?`, ids...).Scan(&r.Hits, &r.IPs, &r.Hosts)
		rows, err := m.DB.Query(`SELECT at, ip, method, host, uri, action, detail FROM waf_events
			WHERE id IN (SELECT max(id) FROM waf_events WHERE rule_id IN (?,?,?) AND at >= ? GROUP BY host, ip) ORDER BY id DESC LIMIT 15`, ids...)
		if err != nil {
			continue
		}
		for rows.Next() {
			var e WatchEvent
			if rows.Scan(&e.At, &e.IP, &e.Method, &e.Host, &e.URI, &e.Action, &e.Detail) == nil {
				r.Examples = append(r.Examples, e)
			}
		}
		rows.Close()
	}
	return rules
}

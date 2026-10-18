package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/client"
)

// Monthly report: what the protection did in a month, in plain words, for
// the administrator (the whole server) and for each hosting account owner
// (their own websites), with each website's security score and to-dos.

// MonthReport is one month's report.
type MonthReport struct {
	Month       string      `json:"month"` // 2026-09
	User        string      `json:"user,omitempty"`
	Attacks     int         `json:"attacks"`
	Bots        int         `json:"bots"`
	Banned      int         `json:"banned"`
	Malware     int         `json:"malware"`
	Removed     int         `json:"removed"`
	Restored    int         `json:"restored"`
	StillOpen   int         `json:"still_open"`
	Sites       []SiteScore `json:"sites"`
	TopAttacked []string    `json:"top_attacked,omitempty"`
}

// monthBounds is the month of t (local time) as unix seconds.
func monthBounds(t time.Time) (string, int64, int64) {
	start := time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, t.Location())
	return start.Format("2006-01"), start.Unix(), start.AddDate(0, 1, 0).Unix()
}

func (a *Agent) monthReport(user string, month time.Time) MonthReport {
	name, from, to := monthBounds(month)
	r := MonthReport{Month: name, User: user}
	count := func(q string, args ...any) int {
		var n int
		_ = a.DB.QueryRow(q, args...).Scan(&n)
		return n
	}
	uw, ua := "", []any{from, to}
	if user != "" {
		uw, ua = " AND user = ?", []any{from, to, user}
	}
	r.Attacks = count(`SELECT count(*) FROM waf_events WHERE category = 'waf' AND action LIKE 'Access denied%' AND at >= ? AND at < ?`+uw, ua...)
	r.Bots = count(`SELECT count(*) FROM waf_events WHERE category = 'bot' AND action LIKE 'Access denied%' AND at >= ? AND at < ?`+uw, ua...)
	ow, oa := "", []any{from, to}
	if user != "" {
		ow, oa = " AND owner = ?", []any{from, to, user}
	} else {
		r.Banned = count(`SELECT count(*) FROM fw_events WHERE created_at >= ? AND created_at < ?`, from, to)
	}
	r.Malware = count(`SELECT count(*) FROM findings WHERE category != 'symlink' AND created_at >= ? AND created_at < ?`+ow, oa...)
	r.Removed = count(`SELECT count(*) FROM findings WHERE status IN ('quarantined','cleaned','trimmed','disabled','deleted') AND created_at >= ? AND created_at < ?`+ow, oa...)
	r.Restored = count(`SELECT count(*) FROM findings WHERE status IN ('cleared','ai_restored','restored') AND created_at >= ? AND created_at < ?`+ow, oa...)
	if user != "" {
		r.StillOpen = count(`SELECT count(*) FROM findings WHERE status = 'detected' AND category != 'symlink' AND owner = ?`, user)
	} else {
		r.StillOpen = a.Scanner.Stats().OpenFindings
	}
	r.Sites = a.siteScores(user)
	if rows, err := a.DB.Query(`SELECT host, count(*) AS n FROM waf_events WHERE action LIKE 'Access denied%' AND at >= ? AND at < ?`+uw+` AND host != '' GROUP BY host ORDER BY n DESC LIMIT 5`, ua...); err == nil {
		for rows.Next() {
			var h string
			var n int
			if rows.Scan(&h, &n) == nil {
				r.TopAttacked = append(r.TopAttacked, fmt.Sprintf("%s (%d)", h, n))
			}
		}
		rows.Close()
	}
	return r
}

// Text is the report as an email body.
func (r MonthReport) Text() string {
	var b strings.Builder
	t, _ := time.Parse("2006-01", r.Month)
	fmt.Fprintf(&b, "Security report for %s\n\n", t.Format("January 2006"))
	fmt.Fprintf(&b, "  Web attacks blocked:      %d\n", r.Attacks)
	fmt.Fprintf(&b, "  Bad bots blocked:         %d\n", r.Bots)
	if r.User == "" {
		fmt.Fprintf(&b, "  Attacking addresses banned: %d\n", r.Banned)
	}
	fmt.Fprintf(&b, "  Malicious files found:    %d\n", r.Malware)
	fmt.Fprintf(&b, "  Removed or cleaned:       %d\n", r.Removed)
	if r.Restored > 0 {
		fmt.Fprintf(&b, "  Found safe and restored:  %d\n", r.Restored)
	}
	if r.StillOpen > 0 {
		fmt.Fprintf(&b, "\n%d file(s) still need action.\n", r.StillOpen)
	}
	if len(r.TopAttacked) > 0 {
		fmt.Fprintf(&b, "\nMost attacked websites: %s\n", strings.Join(r.TopAttacked, ", "))
	}
	if len(r.Sites) > 0 {
		b.WriteString("\nSecurity score of each website:\n")
		sites := append([]SiteScore(nil), r.Sites...)
		sort.Slice(sites, func(i, j int) bool { return sites[i].Score < sites[j].Score })
		for i, s := range sites {
			if i == 30 {
				fmt.Fprintf(&b, "  … and %d more\n", len(sites)-30)
				break
			}
			fmt.Fprintf(&b, "  %s: %s (%d/100)\n", s.Domain, s.Grade, s.Score)
			for _, t := range s.ToDo {
				fmt.Fprintf(&b, "      - %s\n", t)
			}
		}
	}
	return b.String()
}

// sendMonthlyReports mails last month's reports (run on the 1st).
func (a *Agent) sendMonthlyReports(now time.Time) {
	last := now.AddDate(0, 0, -1)
	admin := a.monthReport("", last)
	a.alertAdmin("monthly security report "+admin.Month, admin.Text())
	users := map[string]bool{}
	for _, s := range admin.Sites {
		if s.Owner != "" {
			users[s.Owner] = true
		}
	}
	for u := range users {
		r := a.monthReport(u, last)
		a.notifyUser(u, "monthly security report "+r.Month, r.Text())
	}
}

func (a *Agent) monthlyHandlers(h map[string]client.Handler) {
	h["report.monthly"] = func(_ context.Context, p json.RawMessage) (any, error) {
		in, err := decode[struct {
			Month string `json:"month"`
			User  string `json:"user"`
		}](p)
		if err != nil {
			return nil, err
		}
		t := time.Now().AddDate(0, -1, 0)
		if in.Month != "" {
			if t, err = time.ParseInLocation("2006-01", in.Month, time.Local); err != nil {
				return nil, errors.New("month must look like 2026-09")
			}
		}
		r := a.monthReport(in.User, t)
		return map[string]any{"report": r, "text": r.Text(), "brand": a.Settings.Get().Notifications.Brand}, nil
	}
}

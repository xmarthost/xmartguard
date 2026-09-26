package core

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/notify"
	"github.com/xmarthost/xmartguard/agent/internal/store"
)

// channels feeds the notifier the extra destinations from settings.
func (a *Agent) channels() notify.Channels {
	n := a.Settings.Get().Notifications
	return notify.Channels{Extra: n.ExtraEmail, From: n.From, SlackWebhook: n.SlackWebhook, TelegramToken: n.TelegramToken, TelegramChat: n.TelegramChat}
}

// CPanelUsersDir holds cPanel's per-account files (CONTACTEMAIL=...).
var CPanelUsersDir = "/var/cpanel/users"

// userEmail returns a hosting account's contact address ("" if unknown).
func userEmail(user string) string {
	if user == "" || strings.ContainsAny(user, "/.") {
		return ""
	}
	f, err := os.Open(filepath.Join(CPanelUsersDir, user))
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "CONTACTEMAIL="); ok && strings.Contains(v, "@") {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// notifyUser emails a hosting account's owner, unless excluded.
func (a *Agent) notifyUser(user, subject, line string) {
	n := a.Settings.Get().Notifications
	if slices.Contains(n.ExcludeUsers, user) {
		return
	}
	if to := userEmail(user); to != "" {
		a.Mailer.Enqueue(to, subject, line)
	}
}

// reportLoop sends the daily report and the users' outdated-CMS digests.
func (a *Agent) reportLoop(ctx context.Context) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		now := time.Now()
		if now.Hour() == 8 {
			day := now.Format("2006-01-02")
			n := a.Settings.Get().Notifications
			if n.DailyReport && n.Email != "" && store.GetKV(a.DB, "daily_report") != day {
				_ = store.SetKV(a.DB, "daily_report", day)
				a.sendDailyReport(n.Email)
			}
			due := (n.UserOutdated == "weekly" && now.Weekday() == time.Monday) || (n.UserOutdated == "monthly" && now.Day() == 1)
			if due && store.GetKV(a.DB, "outdated_digest") != day {
				_ = store.SetKV(a.DB, "outdated_digest", day)
				a.sendOutdatedDigests()
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (a *Agent) sendDailyReport(to string) {
	since := store.Now() - 86400
	count := func(q string) int {
		var n int
		_ = a.DB.QueryRow(q, since).Scan(&n)
		return n
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Security report for the last 24 hours\n\n")
	fmt.Fprintf(&b, "  Malware detections:      %d\n", count(`SELECT count(*) FROM findings WHERE created_at >= ?`))
	fmt.Fprintf(&b, "  Addresses banned:        %d\n", count(`SELECT count(*) FROM fw_events WHERE created_at >= ?`))
	fmt.Fprintf(&b, "  Connections dropped:     %d\n", count(`SELECT coalesce(sum(packets),0) FROM drop_stats WHERE minute >= ?`))
	fmt.Fprintf(&b, "  Web attacks blocked:     %d\n", count(`SELECT count(*) FROM waf_events WHERE category IN ('waf','bot') AND at >= ?`))
	fmt.Fprintf(&b, "  Outgoing spam alerts:    %d\n", count(`SELECT count(*) FROM osm_events WHERE at >= ?`))
	fmt.Fprintf(&b, "  Process / cron alerts:   %d\n", count(`SELECT count(*) FROM monitor_events WHERE at >= ?`))
	if open := a.Scanner.Stats().OpenFindings; open > 0 {
		fmt.Fprintf(&b, "\n%d infected file(s) still need action.\n", open)
	}
	a.Mailer.Enqueue(to, "daily security report", b.String())
}

func (a *Agent) sendOutdatedDigests() {
	rows, err := a.DB.Query(`SELECT user, domain, type, version, latest, outdated_plugins, outdated_themes FROM cms_sites WHERE user != ''`)
	if err != nil {
		return
	}
	per := map[string][]string{}
	for rows.Next() {
		var user, domain, cms, ver, latest string
		var op, ot int
		if rows.Scan(&user, &domain, &cms, &ver, &latest, &op, &ot) != nil {
			continue
		}
		var parts []string
		if latest != "" && ver != latest {
			parts = append(parts, fmt.Sprintf("%s %s (latest %s)", cms, ver, latest))
		}
		if op > 0 {
			parts = append(parts, fmt.Sprintf("%d outdated plugin(s)", op))
		}
		if ot > 0 {
			parts = append(parts, fmt.Sprintf("%d outdated theme(s)", ot))
		}
		if len(parts) > 0 {
			per[user] = append(per[user], fmt.Sprintf("  %s: %s", domain, strings.Join(parts, ", ")))
		}
	}
	rows.Close()
	for user, lines := range per {
		a.notifyUser(user, "outdated website software", "These websites in your account run outdated software. Please update them:\n"+strings.Join(lines, "\n"))
	}
}

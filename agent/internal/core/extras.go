package core

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/mail"
	"github.com/xmarthost/xmartguard/agent/internal/reputation"
	"github.com/xmarthost/xmartguard/agent/internal/scanner"
	"github.com/xmarthost/xmartguard/agent/internal/store"
)

// UserDomainsPath lists cPanel domains and their owners.
var UserDomainsPath = "/etc/userdomains"

// mailOwner maps a sender address (or login) to its cPanel account.
func (a *Agent) mailOwner(sender string) string {
	_, dom, ok := strings.Cut(strings.ToLower(sender), "@")
	if !ok {
		return ""
	}
	return reputation.HostedDomains(UserDomainsPath)[dom]
}

func (a *Agent) onOSMEvent(e mail.Event) {
	n := a.Settings.Get().Notifications
	if n.Email != "" && n.OnVirus {
		a.Mailer.Enqueue(n.Email, "outgoing spam detected",
			fmt.Sprintf("%s sent %d messages (%s)\n  source: %s\n  account: %s\n  action: %s\n  %s\n", e.Sender, e.Count, e.Interval, e.Source, e.User, e.Action, e.Remarks))
	}
}

// ------------------------------------------------------------------ auto suspension

// maybeSuspend suspends a cPanel account after repeated malware detections.
func (a *Agent) maybeSuspend(f scanner.Finding) {
	cfg := a.Settings.Get().AutoSuspend
	if !cfg.Enabled || f.Category != scanner.CatVirus || f.Owner == "" || f.Owner == "root" {
		return
	}
	for _, u := range cfg.ExcludeUsers {
		if u == f.Owner {
			return
		}
	}
	var n int
	_ = a.DB.QueryRow(`SELECT count(*) FROM findings WHERE owner = ? AND category = 'virus' AND created_at >= ?`,
		f.Owner, store.Now()-int64(cfg.WindowHours)*3600).Scan(&n)
	if n < cfg.Detections {
		return
	}
	var active int
	_ = a.DB.QueryRow(`SELECT count(*) FROM suspensions WHERE user = ? AND status = 'suspended'`, f.Owner).Scan(&active)
	if active > 0 {
		return
	}
	reason := fmt.Sprintf("XMart Guard: %d malware detections in %d hours", n, cfg.WindowHours)
	status := "suspended"
	if err := runScript("/scripts/suspendacct", f.Owner, reason); err != nil {
		status = "failed"
		reason += " (suspend failed: " + err.Error() + ")"
	}
	_, _ = a.DB.Exec(`INSERT INTO suspensions (at, user, reason, status) VALUES (?,?,?,?)`, store.Now(), f.Owner, reason, status)
	a.Log.Warn("automatic account suspension", "user", f.Owner, "status", status)
	if nc := a.Settings.Get().Notifications; nc.Email != "" {
		a.Mailer.Enqueue(nc.Email, "account suspended", fmt.Sprintf("cPanel account %s: %s (%s)\n", f.Owner, reason, status))
	}
}

func runScript(path string, args ...string) error {
	if _, err := os.Stat(path); err != nil {
		return errors.New("cPanel is not installed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Suspension is an automatic suspension record.
type Suspension struct {
	ID       int64  `json:"id"`
	At       int64  `json:"at"`
	User     string `json:"user"`
	Reason   string `json:"reason"`
	Status   string `json:"status"`
	LiftedAt int64  `json:"lifted_at"`
}

func (a *Agent) suspensions() []Suspension {
	out := []Suspension{}
	rows, err := a.DB.Query(`SELECT id, at, user, reason, status, lifted_at FROM suspensions ORDER BY id DESC LIMIT 200`)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var s Suspension
		if rows.Scan(&s.ID, &s.At, &s.User, &s.Reason, &s.Status, &s.LiftedAt) == nil {
			out = append(out, s)
		}
	}
	return out
}

func (a *Agent) liftSuspension(id int64) error {
	var user, status string
	if err := a.DB.QueryRow(`SELECT user, status FROM suspensions WHERE id = ?`, id).Scan(&user, &status); err != nil {
		return errors.New("suspension not found")
	}
	if status != "suspended" {
		return errors.New("account is not suspended")
	}
	if err := runScript("/scripts/unsuspendacct", user); err != nil {
		return err
	}
	_, err := a.DB.Exec(`UPDATE suspensions SET status = 'lifted', lifted_at = ? WHERE id = ?`, store.Now(), id)
	return err
}

// ------------------------------------------------------------------ domain reputation

func (a *Agent) domainRepLoop(ctx context.Context) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(3 * time.Minute):
	}
	for {
		cfg := a.Settings.Get().DomainRep
		last, _ := strconv.ParseInt(store.GetKV(a.DB, "last_domainrep"), 10, 64)
		if cfg.Enabled && time.Now().Unix()-last >= int64(cfg.IntervalHours)*3600 {
			a.checkDomains(ctx)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(15 * time.Minute):
		}
	}
}

func (a *Agent) checkDomains(ctx context.Context) error {
	domains := reputation.HostedDomains(UserDomainsPath)
	before := map[string]bool{}
	if _, rows, _, err := reputation.LoadDomains(a.DB, "", 500, 0); err == nil {
		for _, r := range rows {
			if r.Status == "listed" {
				before[r.Domain] = true
			}
		}
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	res, err := reputation.CheckDomains(cctx, a.DB, net.DefaultResolver, domains, a.Settings.Get().DomainRep.SafeBrowsingKey)
	_ = store.SetKV(a.DB, "last_domainrep", strconv.FormatInt(time.Now().Unix(), 10))
	n := a.Settings.Get().Notifications
	for _, r := range res {
		if r.Status == "listed" && !before[r.Domain] && n.Email != "" && n.OnBlacklist {
			a.Mailer.Enqueue(n.Email, "domain blacklisted", fmt.Sprintf("%s (account %s) is listed: %s\n", r.Domain, r.User, strings.Join(r.Reasons, "; ")))
		}
	}
	return err
}

// ------------------------------------------------------------------ dashboard

type periodCount struct {
	Current  int64 `json:"current"`
	Previous int64 `json:"previous"`
	Overall  int64 `json:"overall"`
}

func (a *Agent) countWindow(q string, days int) periodCount {
	now := store.Now()
	span := int64(days) * 86400
	var c periodCount
	_ = a.DB.QueryRow(q, now-span, now+1).Scan(&c.Current)
	_ = a.DB.QueryRow(q, now-2*span, now-span).Scan(&c.Previous)
	_ = a.DB.QueryRow(q, 0, now+1).Scan(&c.Overall)
	return c
}

type dayPoint struct {
	Day string `json:"day"`
	N   int64  `json:"n"`
}

func (a *Agent) daily(q string, days int) []dayPoint {
	now := time.Now().UTC()
	start := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC).AddDate(0, 0, -(days - 1))
	got := map[string]int64{}
	if rows, err := a.DB.Query(q, start.Unix()); err == nil {
		for rows.Next() {
			var d string
			var n int64
			if rows.Scan(&d, &n) == nil {
				got[d] = n
			}
		}
		rows.Close()
	}
	out := make([]dayPoint, 0, days)
	for i := 0; i < days; i++ {
		d := start.AddDate(0, 0, i).Format("2006-01-02")
		out = append(out, dayPoint{d, got[d]})
	}
	return out
}

// Dashboard is the cPGuard-style server overview.
func (a *Agent) Dashboard(days int) map[string]any {
	if days != 7 && days != 30 && days != 90 {
		days = 30
	}
	threats := a.countWindow(`SELECT count(*) FROM findings WHERE created_at >= ? AND created_at < ?`, days)
	web := a.countWindow(`SELECT count(*) FROM waf_events WHERE category IN ('waf','bot') AND at >= ? AND at < ?`, days)
	conns := a.countWindow(`SELECT coalesce(sum(packets),0) FROM drop_stats WHERE minute >= ? AND minute < ?`, days)

	dayExpr := func(col string) string { return `strftime('%Y-%m-%d', ` + col + `, 'unixepoch')` }
	attacks := a.daily(`SELECT `+dayExpr("minute")+` AS d, sum(packets) FROM drop_stats WHERE minute >= ? GROUP BY d`, days)
	webDaily := a.daily(`SELECT `+dayExpr("at")+` AS d, count(*) FROM waf_events WHERE category IN ('waf','bot') AND at >= ? GROUP BY d`, days)
	infections := map[string][]dayPoint{}
	for _, cat := range []string{scanner.CatVirus, scanner.CatSuspicious, scanner.CatBinary} {
		infections[cat] = a.daily(`SELECT `+dayExpr("created_at")+` AS d, count(*) FROM findings WHERE category = '`+cat+`' AND created_at >= ? GROUP BY d`, days)
	}

	cmsCounts := a.CMS.Counts()
	var cmsIssues int64
	_ = a.DB.QueryRow(`SELECT coalesce(sum(core_issues + db_issues + outdated_plugins + outdated_themes),0) FROM cms_sites`).Scan(&cmsIssues)
	ipsListed := 0
	for _, ip := range a.repIPs() {
		if r := reputation.Load(a.DB, ip); r != nil && r.ListedOn > 0 {
			ipsListed++
		}
	}
	domSum, _, _, _ := reputation.LoadDomains(a.DB, "", 1, 0)

	var alerts []map[string]string
	add := func(level, text, link string) {
		alerts = append(alerts, map[string]string{"level": level, "text": text, "link": link})
	}
	if domSum.Flagged > 0 {
		add("danger", fmt.Sprintf("%d blacklisted domain(s) found", domSum.Flagged), "domain-reputation")
	}
	if ipsListed > 0 {
		add("danger", fmt.Sprintf("%d server IP(s) on DNS blocklists", ipsListed), "ip-reputation")
	}
	if open := a.Scanner.Stats().OpenFindings; open > 0 {
		add("danger", fmt.Sprintf("%d infected file(s) need action", open), "scanner-logs")
	}
	if cmsCounts.DBInfected > 0 {
		add("danger", fmt.Sprintf("%d database infection(s)", cmsCounts.DBInfected), "db-scanner")
	}
	var critical int
	_ = a.DB.QueryRow(`SELECT count(*) FROM cms_sites WHERE risk = 'critical'`).Scan(&critical)
	if critical > 0 {
		add("warning", fmt.Sprintf("%d website(s) at critical risk", critical), "cms")
	}
	if st := a.Firewall.Status(); st.Enabled && !st.Healthy {
		add("warning", "Firewall rules are not loaded: "+st.Error, "firewall")
	}
	if ws := a.WAF.Status(); ws.Enabled && !ws.Available {
		add("info", "ModSecurity is not installed; the WAF is inactive", "waf-logs")
	}
	var osmRecent int
	_ = a.DB.QueryRow(`SELECT count(*) FROM osm_events WHERE at >= ?`, store.Now()-86400).Scan(&osmRecent)
	if osmRecent > 0 {
		add("warning", fmt.Sprintf("%d outgoing spam alert(s) in the last 24 hours", osmRecent), "osm")
	}
	if alerts == nil {
		alerts = []map[string]string{}
	}
	return map[string]any{
		"days":                days,
		"threats":             threats,
		"web_attacks":         web,
		"blocked_connections": conns,
		"attacks_daily":       attacks,
		"web_daily":           webDaily,
		"infections_daily":    infections,
		"summary": map[string]any{
			"outdated_cms":        cmsCounts.Outdated,
			"cms_issues":          cmsIssues,
			"ips_blacklisted":     ipsListed,
			"domains_blacklisted": domSum.Flagged,
			"db_infections":       cmsCounts.DBInfected,
		},
		"alerts": alerts,
	}
}

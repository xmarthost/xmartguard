package core

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/ai"
	"github.com/xmarthost/xmartguard/agent/internal/cms"
	"github.com/xmarthost/xmartguard/agent/internal/mail"
	"github.com/xmarthost/xmartguard/agent/internal/monitor"
	"github.com/xmarthost/xmartguard/agent/internal/reputation"
	"github.com/xmarthost/xmartguard/agent/internal/scanner"
	"github.com/xmarthost/xmartguard/agent/internal/store"
	"github.com/xmarthost/xmartguard/agent/internal/wpcore"
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
	a.suspendAccount(f.Owner, fmt.Sprintf("XMart Guard: %d malware detections in %d hours", n, cfg.WindowHours))
}

// suspendAccount suspends a cPanel account and notifies the admin and,
// when enabled, the account owner.
func (a *Agent) suspendAccount(user, reason string) {
	status := "suspended"
	if err := runScript("/scripts/suspendacct", user, reason); err != nil {
		status = "failed"
		reason += " (suspend failed: " + err.Error() + ")"
	}
	_, _ = a.DB.Exec(`INSERT INTO suspensions (at, user, reason, status) VALUES (?,?,?,?)`, store.Now(), user, reason, status)
	a.Log.Warn("automatic account suspension", "user", user, "status", status)
	if nc := a.Settings.Get().Notifications; nc.Email != "" {
		a.Mailer.Enqueue(nc.Email, "account suspended", fmt.Sprintf("cPanel account %s: %s (%s)\n", user, reason, status))
	}
	if status == "suspended" && a.Settings.Get().Notifications.UserSuspension {
		a.notifyUser(user, "your hosting account was suspended",
			"Your hosting account was suspended automatically for security reasons:\n  "+reason+"\nPlease contact your hosting provider.")
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
		if r.Status == "listed" && !before[r.Domain] {
			a.maybeSuspendDomain(r.Domain, r.User, strings.Join(r.Reasons, "; "))
		}
	}
	return err
}

// maybeSuspendDomain suspends the account of a newly blacklisted domain
// ("Suspend on domain blacklist"), unless the domain or user is excluded.
func (a *Agent) maybeSuspendDomain(domain, user, reasons string) {
	cfg := a.Settings.Get().AutoSuspend
	if !cfg.OnDomainBlacklist || user == "" || user == "root" || slices.Contains(cfg.ExcludeUsers, user) {
		return
	}
	for _, w := range cfg.WhitelistDomains {
		if domain == w || strings.HasSuffix(domain, "."+w) {
			return
		}
	}
	var n int
	_ = a.DB.QueryRow(`SELECT count(*) FROM suspensions WHERE user = ? AND status = 'suspended'`, user).Scan(&n)
	if n > 0 {
		return
	}
	a.suspendAccount(user, fmt.Sprintf("XMart Guard: domain %s is blacklisted (%s)", domain, reasons))
}

// onCMSAutoAction reports automatic plugin/theme updates and deactivations.
func (a *Agent) onCMSAutoAction(s cms.Site, actions []string) {
	text := fmt.Sprintf("%s (%s):\n  %s\n", s.Domain, s.Path, strings.Join(actions, "\n  "))
	if n := a.Settings.Get().Notifications; n.Email != "" {
		a.Mailer.Enqueue(n.Email, "automatic CMS patches", text)
	}
	if a.Settings.Get().Notifications.UserPatches {
		a.notifyUser(s.User, "security updates applied to your website",
			"XMart Guard applied these security changes to your website:\n"+text)
	}
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
	web := a.countWindow(`SELECT count(*) FROM waf_events WHERE category IN ('waf','bot') AND action LIKE 'Access denied%' AND at >= ? AND at < ?`, days)
	conns := a.countWindow(`SELECT coalesce(sum(packets),0) FROM drop_stats WHERE minute >= ? AND minute < ?`, days)

	dayExpr := func(col string) string { return `strftime('%Y-%m-%d', ` + col + `, 'unixepoch')` }
	attacks := a.daily(`SELECT `+dayExpr("minute")+` AS d, sum(packets) FROM drop_stats WHERE minute >= ? GROUP BY d`, days)
	webDaily := a.daily(`SELECT `+dayExpr("at")+` AS d, count(*) FROM waf_events WHERE category IN ('waf','bot') AND action LIKE 'Access denied%' AND at >= ? GROUP BY d`, days)
	infections := map[string][]dayPoint{}
	for _, cat := range []string{scanner.CatVirus, scanner.CatSuspicious, scanner.CatBinary, scanner.CatSymlink} {
		infections[cat] = a.daily(`SELECT `+dayExpr("created_at")+` AS d, count(*) FROM findings WHERE category = '`+cat+`' AND created_at >= ? GROUP BY d`, days)
	}

	cmsCounts := a.CMS.Counts()
	var cmsIssues int64
	_ = a.DB.QueryRow(`SELECT coalesce(sum(core_issues + db_issues + outdated_plugins + outdated_themes),0) FROM cms_sites`).Scan(&cmsIssues)
	ipsListed := 0
	var listedIPs []string
	for _, ip := range a.repIPs() {
		if r := reputation.Load(a.DB, ip); r != nil && r.ListedOn > 0 {
			ipsListed++
			listedIPs = append(listedIPs, fmt.Sprintf("%s — listed on %d blocklist(s)", ip, r.ListedOn))
		}
	}
	domSum, _, _, _ := reputation.LoadDomains(a.DB, "", 1, 0)

	type alert struct {
		Level   string   `json:"level"`
		Text    string   `json:"text"`
		Link    string   `json:"link"`
		Details []string `json:"details"`
	}
	alerts := []alert{}
	add := func(level, text, link string, details ...string) {
		if len(details) > 10 {
			details = append(details[:10], fmt.Sprintf("… and %d more", len(details)-10))
		}
		alerts = append(alerts, alert{level, text, link, details})
	}
	if domSum.Flagged > 0 {
		var names []string
		for _, d := range domSum.Listed {
			names = append(names, d.Domain+" — "+strings.Join(d.Reasons, ", "))
		}
		add("danger", fmt.Sprintf("%d Blacklisted Domain%s found", domSum.Flagged, plural(domSum.Flagged)), "domain-reputation", names...)
	}
	if ipsListed > 0 {
		add("danger", fmt.Sprintf("%d server IP%s on DNS blocklists", ipsListed, plural(ipsListed)), "ip-reputation", listedIPs...)
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
	for _, h := range a.ServiceHealth() {
		if !h.OK {
			add(h.Level, h.Name+" is not running: "+h.Problem, h.Link)
		}
	}
	var osmRecent int
	_ = a.DB.QueryRow(`SELECT count(*) FROM osm_events WHERE at >= ?`, store.Now()-86400).Scan(&osmRecent)
	if osmRecent > 0 {
		add("warning", fmt.Sprintf("%d outgoing spam alert(s) in the last 24 hours", osmRecent), "osm")
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
		"alerts":   alerts,
		"services": a.ServiceHealth(),
	}
}

// Service is the state of one protection component, shown on the dashboard.
type Service struct {
	Name    string `json:"name"`
	OK      bool   `json:"ok"`
	Off     bool   `json:"off"` // switched off in Settings
	Level   string `json:"level"`
	Problem string `json:"problem"`
	Link    string `json:"link"`
}

// ServiceHealth checks that each enabled protection is actually working, so
// a stopped realtime scanner or an empty IPDB shows up as an alert.
func (a *Agent) ServiceHealth() []Service {
	cfg := a.Settings.Get()
	running := func(d time.Duration) bool { return !a.started.IsZero() && time.Since(a.started) > d }
	out := []Service{}
	add := func(name, link string, enabled bool, level, problem string) {
		out = append(out, Service{Name: name, OK: !enabled || problem == "", Off: !enabled, Level: level, Problem: problem, Link: link})
	}

	rtOn := cfg.Scanner.Enabled && cfg.Scanner.Realtime
	rtProblem := ""
	if rtOn && a.Realtime != nil {
		if active, err := a.Realtime.Health(); !active && running(time.Minute) {
			rtProblem = "inotify watching is not active"
			if err != "" {
				rtProblem += " (" + err + ")"
			}
		} else if active && a.Realtime.Watches() == 0 {
			rtProblem = "no website folders are being watched"
		}
	}
	add("Realtime scanner", "scanner-logs", rtOn, "danger", rtProblem)

	fw := a.Firewall.Status()
	fwProblem := ""
	if fw.Enabled && !fw.Healthy {
		fwProblem = "firewall rules are not loaded"
		if fw.Error != "" {
			fwProblem += ": " + fw.Error
		}
	}
	add("Firewall", "firewall", fw.Enabled, "danger", fwProblem)

	ipdb := a.Firewall.IPDB
	ipdbOn := cfg.IPDB.Enabled && fw.Enabled
	ipdbProblem := ""
	if ipdbOn {
		if _, entries := ipdb.Snapshot(); len(entries) == 0 && running(15*time.Minute) {
			ipdbProblem = "no blocklist received from the portal yet"
		} else if !fw.Healthy && running(time.Minute) {
			ipdbProblem = "the firewall is not loaded, so the IPDB is not enforced"
		}
	}
	add("IPDB", "ipdb", ipdbOn, "warning", ipdbProblem)

	ws := a.WAF.Status()
	wafProblem := ""
	if ws.Enabled {
		switch {
		case !ws.Available:
			wafProblem = "ModSecurity is not installed"
		case ws.Error != "":
			wafProblem = ws.Error
		}
	}
	add("Web application firewall", "waf-logs", ws.Enabled, "warning", wafProblem)
	return out
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func (a *Agent) onMonitorEvent(e monitor.Event) {
	n := a.Settings.Get().Notifications
	if n.Email != "" && n.OnVirus {
		a.Mailer.Enqueue(n.Email, e.Kind+" alert",
			fmt.Sprintf("[%s] %s\n  user: %s\n  %s\n  action: %s\n", e.Kind, e.Reason, e.User, e.Subject, e.Action))
	}
}

// retentionLoop deletes logs and quarantined files older than the
// configured retention ("Keep logs for").
func (a *Agent) retentionLoop(ctx context.Context) {
	t := time.NewTicker(6 * time.Hour)
	defer t.Stop()
	for {
		a.pruneOld()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (a *Agent) pruneOld() {
	days := a.Settings.Get().Scanner.KeepDays
	if days <= 0 {
		return
	}
	cut := store.Now() - int64(days)*86400
	// Quarantined files past retention are deleted for good.
	rows, err := a.DB.Query(`SELECT id FROM findings WHERE status = 'quarantined' AND updated_at < ?`, cut)
	if err == nil {
		var ids []int64
		for rows.Next() {
			var id int64
			if rows.Scan(&id) == nil {
				ids = append(ids, id)
			}
		}
		rows.Close()
		for _, id := range ids {
			if err := a.Scanner.Delete(id); err != nil {
				a.Log.Warn("retention: delete quarantined file", "id", id, "err", err)
			}
		}
	}
	for _, q := range []string{
		`DELETE FROM findings WHERE status IN ('deleted','restored','ignored','ai_restored') AND updated_at < ?`,
		`DELETE FROM fw_events WHERE status != 'blocked' AND created_at < ?`,
		`DELETE FROM waf_events WHERE at < ?`,
		`DELETE FROM osm_events WHERE at < ?`,
		`DELETE FROM monitor_events WHERE at < ?`,
		`DELETE FROM scans WHERE status NOT IN ('queued','running') AND started_at < ?`,
	} {
		_, _ = a.DB.Exec(q, cut)
	}
}

// maybeRepairCore replaces an infected WordPress core file with the official
// file of the site's WordPress version (verified against the official MD5)
// and reports whether it did. The infected copy stays in quarantine.
func (a *Agent) maybeRepairCore(f scanner.Finding) bool {
	sc := a.Settings.Get().Scanner
	if !(sc.WPCoreRepair || sc.AutoClean) || (f.Category != scanner.CatVirus && f.Category != scanner.CatSuspicious) ||
		(f.Status != "detected" && f.Status != "quarantined" && f.Status != "disabled") {
		return false
	}
	if root, _ := wpcore.FindRoot(f.Path); root == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	body, version, rel, err := wpcore.Official(ctx, a.wpSource(), f.Path)
	if err != nil {
		if !errors.Is(err, wpcore.ErrNotCore) {
			a.Log.Warn("WordPress core repair not possible", "file", f.Path, "err", err)
		}
		return false
	}
	if err := a.Scanner.ReplaceWithOfficial(f.ID, body); err != nil {
		a.Log.Warn("WordPress core repair failed", "file", f.Path, "err", err)
		return false
	}
	a.Log.Info("infected WordPress core file replaced with the official file", "file", f.Path, "version", version, "rel", rel)
	if n := a.Settings.Get().Notifications; n.Email != "" && n.OnVirus {
		a.Mailer.Enqueue(n.Email, "WordPress core file repaired",
			fmt.Sprintf("[%s] %s\n  file: %s\n  action: replaced with the official WordPress %s file; the infected copy is kept in quarantine.\n", f.Category, f.Signature, f.Path, version))
	}
	return true
}

// wpSource fetches official WordPress checksums and files through the
// portal (cached for the whole fleet), then from wordpress.org directly.
func (a *Agent) wpSource() wpcore.Source {
	if a.WPSource != nil {
		return a.WPSource
	}
	direct := wpcore.NewDirect()
	if a.AI.Portal == nil {
		return direct
	}
	return wpcore.Chain{portalWP{a.AI.Portal}, direct}
}

// pluginSource fetches official plugin checksums (portal, then WordPress.org).
func (a *Agent) pluginSource() wpcore.PluginSource {
	if a.WPPlugins != nil {
		return a.WPPlugins
	}
	direct := wpcore.DirectPlugins{D: wpcore.NewDirect()}
	if a.AI.Portal == nil {
		return direct
	}
	return wpcore.PluginChain{portalWP{a.AI.Portal}, direct}
}

func (s portalWP) PluginChecksums(ctx context.Context, slug, version string) ([]byte, error) {
	var r struct {
		Missing   bool            `json:"missing"`
		Checksums json.RawMessage `json:"checksums"`
	}
	if err := s.p.Post(ctx, "/api/agent/wp-plugin/checksums", map[string]string{"slug": slug, "version": version}, &r); err != nil {
		return nil, err
	}
	if r.Missing {
		return nil, wpcore.ErrNoChecksums
	}
	return r.Checksums, nil
}

type portalWP struct{ p *ai.PortalAI }

func (s portalWP) Checksums(ctx context.Context, version string) (map[string]string, error) {
	var r struct {
		Checksums map[string]string `json:"checksums"`
	}
	err := s.p.Post(ctx, "/api/agent/wp-core/checksums", map[string]string{"version": version}, &r)
	return r.Checksums, err
}

func (s portalWP) File(ctx context.Context, version, rel string) ([]byte, error) {
	var r struct {
		Content string `json:"content"`
	}
	if err := s.p.Post(ctx, "/api/agent/wp-core/file", map[string]string{"version": version, "path": rel}, &r); err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(r.Content)
}

// wpCoreLoop keeps the list of official WordPress files current (new
// releases, betas and release candidates, collected by the portal).
func (a *Agent) wpCoreLoop(ctx context.Context) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(90 * time.Second):
	}
	for {
		if a.AI.Portal != nil {
			if err := a.syncWPCore(ctx); err != nil {
				a.Log.Debug("WordPress core list sync failed", "err", err)
			}
			if err := a.syncSignatures(ctx); err != nil {
				a.Log.Debug("signature feed sync failed", "err", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(6 * time.Hour):
		}
	}
}

func (a *Agent) syncWPCore(ctx context.Context) error {
	set := wpcore.Default()
	var r struct {
		ETag      string `json:"etag"`
		Unchanged bool   `json:"unchanged"`
		Data      string `json:"data"`
		Versions  int    `json:"versions"`
	}
	if err := a.AI.Portal.Post(ctx, "/api/agent/wp-core/set", map[string]string{"etag": set.ETag()}, &r); err != nil {
		return err
	}
	if r.Unchanged || r.Data == "" {
		return nil
	}
	raw, err := base64.StdEncoding.DecodeString(r.Data)
	if err != nil {
		return err
	}
	if err := set.Update(raw, r.ETag); err != nil {
		return err
	}
	a.Log.Info("WordPress core file list updated", "versions", r.Versions, "files", set.Count())
	return nil
}

// syncSignatures installs the public malware signatures the portal
// collected: MD5 hashes (hash DB), hex patterns and YARA rule files (each
// file is compiled first; one that does not compile is skipped).
func (a *Agent) syncSignatures(ctx context.Context) error {
	if !a.Settings.Get().Scanner.Feeds {
		return a.removeSignatures()
	}
	etag := store.GetKV(a.DB, "sig_etag")
	var r struct {
		ETag      string              `json:"etag"`
		Unchanged bool                `json:"unchanged"`
		MD5       [][]json.RawMessage `json:"md5"`
		Hex       [][2]string         `json:"hex"`
		YARA      []struct {
			Name string `json:"name"`
			Text string `json:"text"`
		} `json:"yara"`
	}
	if err := a.AI.Portal.Post(ctx, "/api/agent/signatures", map[string]string{"etag": etag}, &r); err != nil {
		return err
	}
	if r.Unchanged || r.ETag == "" {
		return nil
	}
	var md5s, hexes strings.Builder
	md5s.WriteString("# public feeds (Linux Malware Detect)\n")
	for _, e := range r.MD5 {
		var sum, name string
		var size int64
		if len(e) != 3 || json.Unmarshal(e[0], &sum) != nil || json.Unmarshal(e[1], &size) != nil || json.Unmarshal(e[2], &name) != nil {
			continue
		}
		if len(sum) != 32 || size <= 0 || strings.ContainsAny(name, " \n") {
			continue
		}
		fmt.Fprintf(&md5s, "%d %s LMD.%s\n", size, sum, name)
	}
	for _, e := range r.Hex {
		if strings.ContainsAny(e[0]+e[1], " \n") {
			continue
		}
		fmt.Fprintf(&hexes, "%s %s\n", e[0], e[1])
	}
	if err := os.MkdirAll(filepath.Dir(scanner.FeedHashPath()), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(scanner.FeedHashPath(), []byte(md5s.String()), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(scanner.FeedHexPath(), []byte(hexes.String()), 0o600); err != nil {
		return err
	}
	dir := scanner.FeedYARADir()
	_ = os.RemoveAll(dir + ".new")
	if err := os.MkdirAll(dir+".new", 0o700); err != nil {
		return err
	}
	kept := 0
	for _, y := range r.YARA {
		name := strings.Map(func(c rune) rune {
			if c == '-' || c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
				return c
			}
			return '-'
		}, y.Name)
		p := filepath.Join(dir+".new", name+".yar")
		if os.WriteFile(p, []byte(y.Text), 0o600) != nil {
			continue
		}
		if err := scanner.ValidYARA(p); err != nil {
			a.Log.Warn("YARA feed skipped: it does not compile", "name", y.Name, "err", err)
			os.Remove(p)
			continue
		}
		kept++
	}
	_ = os.RemoveAll(dir)
	if err := os.Rename(dir+".new", dir); err != nil {
		return err
	}
	scanner.ReloadFeeds()
	_ = store.SetKV(a.DB, "sig_etag", r.ETag)
	a.Log.Info("malware signature feeds updated", "md5", len(r.MD5), "hex", len(r.Hex), "yara_files", kept)
	return nil
}

func (a *Agent) removeSignatures() error {
	if store.GetKV(a.DB, "sig_etag") == "" {
		return nil
	}
	os.Remove(scanner.FeedHashPath())
	os.Remove(scanner.FeedHexPath())
	os.RemoveAll(scanner.FeedYARADir())
	scanner.ReloadFeeds()
	return store.SetKV(a.DB, "sig_etag", "")
}

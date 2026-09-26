// Package core wires the agent's modules together and exposes them to the
// portal as typed commands. There is no generic shell command: every action
// the portal can trigger is listed in Handlers.
package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/ai"
	"github.com/xmarthost/xmartguard/agent/internal/captcha"
	"github.com/xmarthost/xmartguard/agent/internal/client"
	"github.com/xmarthost/xmartguard/agent/internal/cms"
	"github.com/xmarthost/xmartguard/agent/internal/config"
	"github.com/xmarthost/xmartguard/agent/internal/firewall"
	"github.com/xmarthost/xmartguard/agent/internal/mail"
	"github.com/xmarthost/xmartguard/agent/internal/monitor"
	"github.com/xmarthost/xmartguard/agent/internal/notify"
	"github.com/xmarthost/xmartguard/agent/internal/reputation"
	"github.com/xmarthost/xmartguard/agent/internal/scanner"
	"github.com/xmarthost/xmartguard/agent/internal/settings"
	"github.com/xmarthost/xmartguard/agent/internal/store"
	"github.com/xmarthost/xmartguard/agent/internal/sysinfo"
	"github.com/xmarthost/xmartguard/agent/internal/updater"
	"github.com/xmarthost/xmartguard/agent/internal/version"
	"github.com/xmarthost/xmartguard/agent/internal/waf"
)

// Agent holds every module.
type Agent struct {
	Cfg      *config.Config
	Log      *slog.Logger
	DB       *sql.DB
	Settings *settings.Store
	Scanner  *scanner.Scanner
	Realtime *scanner.Realtime
	Firewall *firewall.Manager
	WAF      *waf.Manager
	CMS      *cms.Manager
	OSM      *mail.Monitor
	Captcha  *captcha.Server
	AI       *ai.Analyzer
	Monitor  *monitor.Monitor
	Mailer   *notify.Mailer
	Session  *client.Session

	// ExitForUpdate is called after a successful self-update.
	ExitForUpdate func()

	protMu    sync.Mutex
	protected []string
	protAt    time.Time
}

// New opens the local store and builds all modules.
func New(cfg *config.Config, log *slog.Logger) (*Agent, error) {
	db, err := store.Open()
	if err != nil {
		return nil, err
	}
	st, err := settings.Load()
	if err != nil {
		return nil, err
	}
	host, _ := os.Hostname()
	a := &Agent{Cfg: cfg, Log: log, DB: db, Settings: st, Mailer: &notify.Mailer{Hostname: host, Log: log}}
	a.Scanner = scanner.New(db, st, log)
	a.Scanner.OnFinding = a.onFinding
	a.Realtime = &scanner.Realtime{S: a.Scanner}
	a.Firewall = &firewall.Manager{
		DB: db, Settings: st, Log: log, NFT: firewall.FindNFT(), IPT: firewall.FindIPTables(),
		Geo:       &firewall.Geo{Dir: filepath.Join(store.StateDir(), "geo"), Log: log},
		IPDB:      &firewall.IPDB{},
		Protected: a.protectedIPs,
	}
	a.Firewall.OnBan = a.onBan
	a.Firewall.EssentialTCPOut = portalPorts(cfg.ServerURL)
	a.Mailer.Channels = a.channels
	a.Mailer.Admin = func() string { return a.Settings.Get().Notifications.Email }
	a.AI = &ai.Analyzer{DB: db, Settings: st, Log: log, OnVerdict: a.onAIVerdict}
	a.Monitor = &monitor.Monitor{DB: db, Settings: st, Log: log, OnEvent: a.onMonitorEvent,
		Users: func() map[string]string {
			out := map[string]string{}
			for _, u := range scanner.Users() {
				out[u.Name] = u.Home
			}
			return out
		}}
	a.Captcha = &captcha.Server{Settings: st, Log: log, Solved: func(ip string) error {
		return a.Firewall.CaptchaSolved(ip, time.Duration(a.Settings.Get().Captcha.AllowMinutes)*time.Minute)
	}}
	a.WAF = &waf.Manager{DB: db, Settings: st, Log: log, RulesDir: config.Dir() + "/waf",
		AgentBin: selfPath(), Firewall: a.Firewall}
	a.CMS = &cms.Manager{DB: db, Settings: st, Log: log, Versions: cms.NewVersions(db),
		Accounts: func() []cms.Account {
			var out []cms.Account
			for _, u := range scanner.Users() {
				out = append(out, cms.Account{Name: u.Name, Home: u.Home})
			}
			return out
		},
		Docroots:     func() map[string]string { return cms.CPanelDocroots("/var/cpanel/userdata") },
		OnFinding:    a.onDBFinding,
		Vulns:        cms.NewVulnDB(db),
		OnAutoAction: a.onCMSAutoAction,
	}
	a.OSM = &mail.Monitor{DB: db, Settings: st, Log: log, Owner: a.mailOwner, OnEvent: a.onOSMEvent}
	return a, nil
}

// Start launches the background workers.
func (a *Agent) Start(ctx context.Context) {
	go a.Realtime.Run(ctx)
	go a.Firewall.Run(ctx)
	go a.Firewall.RunBruteForce(ctx)
	go a.Firewall.RunConnLog(ctx)
	go a.Scanner.Scheduler(ctx,
		func(kind string) int64 { n, _ := strconv.ParseInt(store.GetKV(a.DB, "last_"+kind), 10, 64); return n },
		func(kind string) { _ = store.SetKV(a.DB, "last_"+kind, strconv.FormatInt(time.Now().Unix(), 10)) })
	go a.reputationLoop(ctx)
	go a.WAF.Run(ctx)
	go a.CMS.Run(ctx)
	go a.OSM.Run(ctx)
	go a.domainRepLoop(ctx)
	go a.Captcha.Run(ctx)
	go a.AI.Run(ctx)
	go a.Monitor.Run(ctx)
	go a.retentionLoop(ctx)
	go a.reportLoop(ctx)
}

// portalPorts returns the TCP port the agent uses to reach the portal.
func portalPorts(serverURL string) []int {
	u, err := url.Parse(serverURL)
	if err != nil {
		return []int{443}
	}
	if p, err := strconv.Atoi(u.Port()); err == nil {
		return []int{p}
	}
	if u.Scheme == "http" {
		return []int{80}
	}
	return []int{443}
}

func (a *Agent) onDBFinding(s cms.Site, f cms.DBFinding) {
	n := a.Settings.Get().Notifications
	if n.Email != "" && n.OnVirus {
		a.Mailer.Enqueue(n.Email, "database infection found",
			fmt.Sprintf("[%s] %s\n  site: %s (%s)\n  table: %s  row: %s\n", f.Signature, s.Domain, s.Path, s.User, f.Table, f.Row))
	}
}

// selfPath is the agent binary, for scripts the WAF and panel invoke.
func selfPath() string {
	if p, err := os.Executable(); err == nil {
		if r, err := filepath.EvalSymlinks(p); err == nil {
			return r
		}
		return p
	}
	return "/opt/xmartguard/bin/xmartguard-agent"
}

// protectedIPs are never blocked: this server's addresses, loopback and the portal.
func (a *Agent) protectedIPs() []string {
	a.protMu.Lock()
	defer a.protMu.Unlock()
	if time.Since(a.protAt) < 10*time.Minute && a.protected != nil {
		return a.protected
	}
	ips := append([]string{"127.0.0.1", "::1"}, sysinfo.IPs()...)
	if u, err := url.Parse(a.Cfg.ServerURL); err == nil {
		if addrs, err := net.LookupHost(u.Hostname()); err == nil {
			ips = append(ips, addrs...)
		}
	}
	a.protected, a.protAt = ips, time.Now()
	return ips
}

func (a *Agent) onFinding(f scanner.Finding) {
	a.maybeSuspend(f)
	a.maybeAutoClean(f)
	if f.Category == scanner.CatSuspicious {
		if p, _, err := a.Scanner.ContentPath(f.ID); err == nil {
			a.AI.Enqueue(ai.Job{FindingID: f.ID, Path: p, SHA256: f.SHA256, Signature: f.Signature})
		}
	}
	n := a.Settings.Get().Notifications
	if n.Email == "" {
		return
	}
	if n.UserInfected && (f.Category == scanner.CatVirus || f.Category == scanner.CatSymlink) && f.Owner != "" {
		a.notifyUser(f.Owner, "malware found in your account",
			fmt.Sprintf("A malicious file was found in your hosting account:\n  %s\n  detection: %s\n  action taken: %s\n", f.Path, f.Signature, f.Status))
	}
	if (f.Category == scanner.CatVirus && n.OnVirus) || (f.Category == scanner.CatSuspicious && n.OnSuspicious) || (f.Category == scanner.CatBinary && n.OnBinary) {
		a.Mailer.Enqueue(n.Email, "malware detected",
			fmt.Sprintf("[%s] %s\n  file: %s\n  owner: %s\n  status: %s\n", f.Category, f.Signature, f.Path, f.Owner, f.Status))
	}
}

func (a *Agent) onBan(e firewall.Event) {
	n := a.Settings.Get().Notifications
	if n.Email != "" && n.OnBan {
		a.Mailer.Enqueue(n.Email, "IP blocked", fmt.Sprintf("%s blocked: %s", e.IP, e.Reason))
	}
}

// SecuritySummary is attached to every metrics sample for dashboards.
func (a *Agent) SecuritySummary() any {
	sc := a.Scanner.Stats()
	sc.RealtimeWatch = a.Realtime.Watches()
	fw := a.Firewall.Stats()
	listed := 0
	for _, ip := range a.repIPs() {
		if r := reputation.Load(a.DB, ip); r != nil && r.ListedOn > 0 {
			listed++
		}
	}
	return map[string]any{"scanner": sc, "firewall": fw, "waf": a.WAF.Stats(), "blacklisted_ips": listed}
}

// ------------------------------------------------------------------ reputation

func (a *Agent) repIPs() []string {
	cfg := a.Settings.Get().Reputation
	if len(cfg.IPs) > 0 {
		return cfg.IPs
	}
	var out []string
	for _, ip := range sysinfo.IPs() {
		p := net.ParseIP(ip)
		if p != nil && p.To4() != nil && !p.IsPrivate() && !p.IsLoopback() {
			out = append(out, ip)
		}
	}
	return out
}

func (a *Agent) checkReputation(ctx context.Context, ips []string) map[string]reputation.Report {
	cfg := a.Settings.Get()
	out := map[string]reputation.Report{}
	for _, ip := range ips {
		rep := reputation.Check(ctx, net.DefaultResolver, ip, cfg.Reputation.RBLs)
		prev := reputation.Load(a.DB, ip)
		_ = reputation.Save(a.DB, rep)
		out[ip] = rep
		if rep.ListedOn > 0 && (prev == nil || prev.ListedOn == 0) && cfg.Notifications.Email != "" && cfg.Notifications.OnBlacklist {
			var names []string
			for _, l := range rep.Results {
				if l.Listed {
					names = append(names, l.RBL)
				}
			}
			a.Mailer.Enqueue(cfg.Notifications.Email, "IP blacklisted", fmt.Sprintf("%s is listed on: %s", ip, strings.Join(names, ", ")))
		}
	}
	return out
}

func (a *Agent) reputationLoop(ctx context.Context) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(2 * time.Minute):
	}
	for {
		cfg := a.Settings.Get().Reputation
		if cfg.Enabled {
			last, _ := strconv.ParseInt(store.GetKV(a.DB, "last_rbl"), 10, 64)
			if time.Now().Unix()-last >= int64(cfg.IntervalHours)*3600 {
				a.checkReputation(ctx, a.repIPs())
				_ = store.SetKV(a.DB, "last_rbl", strconv.FormatInt(time.Now().Unix(), 10))
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(15 * time.Minute):
		}
	}
}

// ------------------------------------------------------------------ commands

func decode[T any](p json.RawMessage) (T, error) {
	var v T
	if len(p) == 0 || string(p) == "null" {
		return v, nil
	}
	if err := json.Unmarshal(p, &v); err != nil {
		return v, fmt.Errorf("invalid parameters: %w", err)
	}
	return v, nil
}

// Handlers returns the command table used by the portal session.
func (a *Agent) Handlers() map[string]client.Handler {
	h := map[string]client.Handler{}

	h["stats.get"] = func(context.Context, json.RawMessage) (any, error) {
		return map[string]any{
			"summary":  a.SecuritySummary(),
			"daily":    a.Scanner.DailyCounts(30),
			"clamav":   scanner.ClamAvailable(),
			"firewall": a.Firewall.Status(),
			"version":  version.Version,
		}, nil
	}

	// ---- scanner
	h["scan.start"] = func(_ context.Context, p json.RawMessage) (any, error) {
		in, err := decode[struct {
			Kind      string `json:"kind"`
			Path      string `json:"path"`
			Initiator string `json:"initiator"`
		}](p)
		if err != nil {
			return nil, err
		}
		if !a.Settings.Get().Scanner.Enabled {
			return nil, errors.New("the virus scanner is disabled in settings")
		}
		id, err := a.Scanner.Start(in.Kind, in.Path, in.Initiator)
		return map[string]any{"id": id}, err
	}
	h["scan.stop"] = func(_ context.Context, p json.RawMessage) (any, error) {
		in, err := decode[struct{ ID int64 }](p)
		if err != nil {
			return nil, err
		}
		return map[string]any{"ok": true}, a.Scanner.Stop(in.ID)
	}
	h["scan.delete"] = func(_ context.Context, p json.RawMessage) (any, error) {
		in, err := decode[struct{ ID int64 }](p)
		if err != nil {
			return nil, err
		}
		return map[string]any{"ok": true}, a.Scanner.DeleteScan(in.ID)
	}
	h["scan.list"] = func(context.Context, json.RawMessage) (any, error) {
		scans, err := a.Scanner.ListScans(100)
		return map[string]any{"scans": scans}, err
	}
	h["scanner.paths"] = func(context.Context, json.RawMessage) (any, error) {
		return map[string]any{"users": scanner.Users()}, nil
	}
	h["findings.list"] = func(_ context.Context, p json.RawMessage) (any, error) {
		f, err := decode[scanner.FindingFilter](p)
		if err != nil {
			return nil, err
		}
		list, total, err := a.Scanner.ListFindings(f)
		return map[string]any{"findings": list, "total": total}, err
	}
	h["finding.action"] = func(_ context.Context, p json.RawMessage) (any, error) {
		in, err := decode[struct {
			IDs    []int64 `json:"ids"`
			Action string  `json:"action"`
		}](p)
		if err != nil {
			return nil, err
		}
		if len(in.IDs) == 0 || len(in.IDs) > 500 {
			return nil, errors.New("select between 1 and 500 findings")
		}
		done, failed := 0, map[int64]string{}
		for _, id := range in.IDs {
			var err error
			switch in.Action {
			case "quarantine":
				err = a.Scanner.Quarantine(id)
			case "restore":
				err = a.Scanner.Restore(id)
			case "disable":
				err = a.Scanner.Disable(id)
			case "delete":
				err = a.Scanner.Delete(id)
			case "ignore":
				var path string
				path, err = a.Scanner.Ignore(id)
				if err == nil {
					cur := a.Settings.Get().Scanner.WhitelistPaths
					patch, _ := json.Marshal(map[string]any{"scanner": map[string]any{"whitelist_paths": append(cur, path)}})
					_, err = a.Settings.Patch(patch)
				}
			default:
				return nil, fmt.Errorf("unknown action %q", in.Action)
			}
			if err != nil {
				failed[id] = err.Error()
			} else {
				done++
			}
		}
		return map[string]any{"done": done, "failed": failed}, nil
	}

	// ---- settings
	h["settings.get"] = func(context.Context, json.RawMessage) (any, error) {
		return map[string]any{
			"settings": masked(a.Settings.Get()),
			"meta": map[string]any{
				"clamav":       scanner.ClamAvailable(),
				"firewall":     a.Firewall.Status(),
				"users":        scanner.Users(),
				"server_ips":   sysinfo.IPs(),
				"default_rbls": settings.DefaultRBLs(),
			},
		}, nil
	}
	h["settings.set"] = func(ctx context.Context, p json.RawMessage) (any, error) {
		before, beforeIPDB := a.Settings.Get().Firewall, a.Settings.Get().IPDB
		beforeWAF, beforeCaptcha := a.Settings.Get().WAF, a.Settings.Get().Captcha
		p = keepSecrets(p, a.Settings.Get())
		next, err := a.Settings.Patch(p)
		if err != nil {
			return nil, err
		}
		if strings.Join(before.DDNS, ",") != strings.Join(next.Firewall.DDNS, ",") {
			a.Firewall.RefreshDDNS(ctx)
		}
		if fwChanged(before, next.Firewall) || beforeIPDB != next.IPDB || beforeCaptcha != next.Captcha {
			if err := a.Firewall.Apply(); err != nil {
				return nil, fmt.Errorf("settings saved, but the firewall could not be applied: %w", err)
			}
		}
		if wafChanged(beforeWAF, next.WAF) {
			if err := a.WAF.Apply(); err != nil {
				return map[string]any{"settings": next, "warning": err.Error()}, nil
			}
		}
		return map[string]any{"settings": masked(next)}, nil
	}

	// ---- firewall
	h["fw.list"] = func(_ context.Context, p json.RawMessage) (any, error) {
		in, err := decode[struct{ Kind string }](p)
		if err != nil {
			return nil, err
		}
		rules, err := a.Firewall.List(in.Kind)
		return map[string]any{"rules": rules}, err
	}
	h["fw.add"] = func(_ context.Context, p json.RawMessage) (any, error) {
		in, err := decode[struct {
			Kind    string `json:"kind"`
			Addr    string `json:"addr"`
			Comment string `json:"comment"`
			Minutes int    `json:"minutes"`
		}](p)
		if err != nil {
			return nil, err
		}
		r, err := a.Firewall.Add(in.Kind, in.Addr, in.Comment, time.Duration(in.Minutes)*time.Minute)
		return map[string]any{"rule": r}, err
	}
	h["fw.remove"] = func(_ context.Context, p json.RawMessage) (any, error) {
		in, err := decode[struct{ Kind, Addr string }](p)
		if err != nil {
			return nil, err
		}
		return map[string]any{"ok": true}, a.Firewall.Remove(in.Kind, in.Addr)
	}
	h["fw.unblock"] = func(_ context.Context, p json.RawMessage) (any, error) {
		in, err := decode[struct{ Addr string }](p)
		if err != nil {
			return nil, err
		}
		return map[string]any{"ok": true}, a.Firewall.Unblock(in.Addr)
	}
	h["fw.check"] = func(_ context.Context, p json.RawMessage) (any, error) {
		in, err := decode[struct{ IP string }](p)
		if err != nil {
			return nil, err
		}
		return a.Firewall.Check(in.IP)
	}
	h["fw.events"] = func(_ context.Context, p json.RawMessage) (any, error) {
		f, err := decode[firewall.EventFilter](p)
		if err != nil {
			return nil, err
		}
		evs, total, err := a.Firewall.Events(f)
		return map[string]any{"events": evs, "total": total}, err
	}
	h["fw.apply"] = func(context.Context, json.RawMessage) (any, error) {
		return a.Firewall.Status(), a.Firewall.Apply()
	}
	// fw.meta describes options the firewall page needs.
	h["fw.meta"] = func(context.Context, json.RawMessage) (any, error) {
		return map[string]any{
			"jails":     firewall.Jails(),
			"ddns":      a.Firewall.DDNSStatus(),
			"ssh_ports": firewall.SSHPorts(),
			"portal":    a.Firewall.EssentialTCPOut,
			"captcha":   captcha.Wanted(a.Settings.Get()),
		}, nil
	}
	// ai.check judges one finding now (the "Check with AI" button).
	h["ai.check"] = func(ctx context.Context, p json.RawMessage) (any, error) {
		in, err := decode[struct {
			ID int64 `json:"id"`
		}](p)
		if err != nil {
			return nil, err
		}
		f, err := a.Scanner.Get(in.ID)
		if err != nil {
			return nil, err
		}
		path, _, err := a.Scanner.ContentPath(in.ID)
		if err != nil {
			return nil, err
		}
		if f.Status == "deleted" {
			return nil, errors.New("the file was deleted")
		}
		v, err := a.AI.Analyze(ctx, ai.Job{FindingID: f.ID, Path: path, SHA256: f.SHA256, Signature: f.Signature})
		if err != nil {
			return nil, err
		}
		return v, nil
	}
	h["monitor.events"] = func(_ context.Context, p json.RawMessage) (any, error) {
		in, err := decode[struct {
			Kind   string `json:"kind"`
			Limit  int    `json:"limit"`
			Offset int    `json:"offset"`
		}](p)
		if err != nil {
			return nil, err
		}
		evs, total, err := a.Monitor.Events(in.Kind, in.Limit, in.Offset)
		return map[string]any{"events": evs, "total": total, "status": a.Monitor.Status()}, err
	}
	h["monitor.rootkit"] = func(ctx context.Context, _ json.RawMessage) (any, error) {
		n, err := a.Monitor.RunRootkit(ctx)
		return map[string]any{"warnings": n}, err
	}
	h["fw.event_delete"] = func(_ context.Context, p json.RawMessage) (any, error) {
		in, err := decode[struct {
			ID int64 `json:"id"`
		}](p)
		if err != nil {
			return nil, err
		}
		return map[string]any{"ok": true}, a.Firewall.DeleteEvent(in.ID)
	}

	// ---- IPDB (called by the portal's sync loop, not by users)
	h["ipdb.sync"] = func(_ context.Context, p json.RawMessage) (any, error) {
		in, err := decode[struct {
			Since int64 `json:"since"`
		}](p)
		if err != nil {
			return nil, err
		}
		cfg := a.Settings.Get().IPDB
		reports := []firewall.IPDBReport{}
		if cfg.Report {
			if reports, err = a.Firewall.IPDBReports(in.Since, 1000); err != nil {
				return nil, err
			}
		}
		hits, err := a.Firewall.TakePendingHits(2000)
		if err != nil {
			return nil, err
		}
		v, _ := a.Firewall.IPDB.Snapshot()
		return map[string]any{"enabled": cfg.Enabled, "report": cfg.Report, "version": v, "reports": reports, "hits": hits}, nil
	}
	h["ipdb.apply"] = func(_ context.Context, p json.RawMessage) (any, error) {
		in, err := decode[struct {
			Version string   `json:"version"`
			Entries []string `json:"entries"`
		}](p)
		if err != nil {
			return nil, err
		}
		if in.Version == "" {
			return nil, errors.New("version is required")
		}
		n, err := a.Firewall.ApplyIPDB(in.Version, in.Entries)
		return map[string]any{"entries": n, "version": in.Version}, err
	}
	h["ipdb.status"] = func(context.Context, json.RawMessage) (any, error) {
		return a.Firewall.IPDBStatus(), nil
	}
	h["ipdb.live"] = func(_ context.Context, p json.RawMessage) (any, error) {
		in, err := decode[struct {
			SinceID int64 `json:"since_id"`
		}](p)
		if err != nil {
			return nil, err
		}
		return a.Firewall.IPDBLive(in.SinceID), nil
	}
	h["fw.connections"] = func(_ context.Context, p json.RawMessage) (any, error) {
		f, err := decode[firewall.ConnFilter](p)
		if err != nil {
			return nil, err
		}
		evs, total, err := a.Firewall.ConnEvents(f)
		return map[string]any{"events": evs, "total": total}, err
	}

	// ---- WAF
	h["waf.status"] = func(context.Context, json.RawMessage) (any, error) {
		return map[string]any{"status": a.WAF.Status(), "rules": a.WAF.RuleCatalog(), "stats": a.WAF.Stats()}, nil
	}
	h["waf.events"] = func(_ context.Context, p json.RawMessage) (any, error) {
		f, err := decode[waf.EventFilter](p)
		if err != nil {
			return nil, err
		}
		evs, total, err := a.WAF.Events(f)
		return map[string]any{"events": evs, "total": total}, err
	}
	h["waf.apply"] = func(context.Context, json.RawMessage) (any, error) {
		return a.WAF.Status(), a.WAF.Apply()
	}

	// ---- CMS + database scanner
	h["cms.status"] = func(context.Context, json.RawMessage) (any, error) {
		return map[string]any{"status": a.CMS.Status(), "counts": a.CMS.Counts()}, nil
	}
	h["cms.sites"] = func(_ context.Context, p json.RawMessage) (any, error) {
		f, err := decode[cms.SiteFilter](p)
		if err != nil {
			return nil, err
		}
		sites, total, err := a.CMS.Sites(f)
		return map[string]any{"sites": sites, "total": total}, err
	}
	h["cms.scan"] = func(context.Context, json.RawMessage) (any, error) {
		if !a.Settings.Get().CMS.Enabled {
			return nil, errors.New("CMS monitoring is disabled in settings")
		}
		return map[string]any{"ok": true}, a.CMS.Start()
	}
	h["cms.update"] = func(ctx context.Context, p json.RawMessage) (any, error) {
		in, err := decode[struct {
			Path string `json:"path"`
			What string `json:"what"`
			Slug string `json:"slug"`
		}](p)
		if err != nil {
			return nil, err
		}
		out, err := a.CMS.Update(ctx, in.Path, in.What, in.Slug)
		if err == nil {
			_ = a.CMS.Start() // refresh the inventory
		}
		return map[string]any{"output": out}, err
	}
	h["db.findings"] = func(_ context.Context, p json.RawMessage) (any, error) {
		in, err := decode[struct {
			Status string `json:"status"`
			Q      string `json:"q"`
			Limit  int    `json:"limit"`
			Offset int    `json:"offset"`
		}](p)
		if err != nil {
			return nil, err
		}
		rows, total, err := a.CMS.DBFindings(in.Status, in.Q, in.Limit, in.Offset)
		return map[string]any{"findings": rows, "total": total}, err
	}
	h["db.archive"] = func(_ context.Context, p json.RawMessage) (any, error) {
		in, err := decode[struct {
			IDs []int64 `json:"ids"`
		}](p)
		if err != nil {
			return nil, err
		}
		n, err := a.CMS.ArchiveDBFindings(in.IDs)
		return map[string]any{"done": n}, err
	}

	// ---- outgoing spam monitor
	h["osm.events"] = func(_ context.Context, p json.RawMessage) (any, error) {
		f, err := decode[mail.EventFilter](p)
		if err != nil {
			return nil, err
		}
		evs, total, err := a.OSM.Events(f)
		return map[string]any{"events": evs, "total": total}, err
	}
	h["osm.transaction"] = func(_ context.Context, p json.RawMessage) (any, error) {
		in, err := decode[struct {
			MsgID string `json:"msg_id"`
		}](p)
		if err != nil {
			return nil, err
		}
		lines, err := mail.Transaction(in.MsgID)
		return map[string]any{"lines": lines}, err
	}
	h["osm.delete"] = func(_ context.Context, p json.RawMessage) (any, error) {
		in, err := decode[struct {
			IDs []int64 `json:"ids"`
		}](p)
		if err != nil {
			return nil, err
		}
		n, err := a.OSM.Delete(in.IDs)
		return map[string]any{"done": n}, err
	}
	h["osm.release"] = func(_ context.Context, p json.RawMessage) (any, error) {
		in, err := decode[struct {
			User string `json:"user"`
		}](p)
		if err != nil {
			return nil, err
		}
		return map[string]any{"ok": true}, a.OSM.Release(in.User)
	}

	// ---- domain reputation
	h["domainrep.get"] = func(_ context.Context, p json.RawMessage) (any, error) {
		in, err := decode[struct {
			Q      string `json:"q"`
			Limit  int    `json:"limit"`
			Offset int    `json:"offset"`
		}](p)
		if err != nil {
			return nil, err
		}
		sum, rows, total, err := reputation.LoadDomains(a.DB, in.Q, in.Limit, in.Offset)
		return map[string]any{"summary": sum, "domains": rows, "total": total}, err
	}
	h["domainrep.check"] = func(ctx context.Context, _ json.RawMessage) (any, error) {
		err := a.checkDomains(ctx)
		sum, _, _, _ := reputation.LoadDomains(a.DB, "", 1, 0)
		if err != nil {
			return map[string]any{"summary": sum, "warning": err.Error()}, nil
		}
		return map[string]any{"summary": sum}, nil
	}

	// ---- automatic suspension
	h["suspend.list"] = func(context.Context, json.RawMessage) (any, error) {
		return map[string]any{"suspensions": a.suspensions()}, nil
	}
	h["suspend.lift"] = func(_ context.Context, p json.RawMessage) (any, error) {
		in, err := decode[struct {
			ID int64 `json:"id"`
		}](p)
		if err != nil {
			return nil, err
		}
		return map[string]any{"ok": true}, a.liftSuspension(in.ID)
	}

	// ---- dashboard
	h["dashboard.get"] = func(_ context.Context, p json.RawMessage) (any, error) {
		in, err := decode[struct {
			Days int `json:"days"`
		}](p)
		if err != nil {
			return nil, err
		}
		return a.Dashboard(in.Days), nil
	}

	// ---- reputation
	h["reputation.get"] = func(context.Context, json.RawMessage) (any, error) {
		ips := a.repIPs()
		reports := map[string]*reputation.Report{}
		for _, ip := range ips {
			reports[ip] = reputation.Load(a.DB, ip)
		}
		return map[string]any{"ips": ips, "reports": reports, "rbls": a.Settings.Get().Reputation.RBLs}, nil
	}
	h["reputation.check"] = func(ctx context.Context, p json.RawMessage) (any, error) {
		in, err := decode[struct{ IP string }](p)
		if err != nil {
			return nil, err
		}
		ips := a.repIPs()
		if in.IP != "" {
			if net.ParseIP(in.IP) == nil {
				return nil, fmt.Errorf("invalid IP %q", in.IP)
			}
			ips = []string{in.IP}
		}
		return map[string]any{"reports": a.checkReputation(ctx, ips)}, nil
	}

	// ---- self update
	h["agent.update"] = func(ctx context.Context, p json.RawMessage) (any, error) {
		in, err := decode[struct {
			SHA256 string `json:"sha256"`
		}](p)
		if err != nil {
			return nil, err
		}
		v, err := updater.Update(ctx, client.HTTPClient(a.Cfg.InsecureTLS), a.Cfg.ServerURL, in.SHA256)
		if err != nil {
			return nil, err
		}
		a.Log.Info("agent updated; restarting", "new_version", v)
		if a.ExitForUpdate != nil {
			go func() { time.Sleep(2 * time.Second); a.ExitForUpdate() }()
		}
		return map[string]any{"version": v}, nil
	}
	return h
}

const secretMask = "********"

// masked hides API keys from portal users.
// secretFields are settings values never sent back to the portal in full.
var secretFields = [][2]string{
	{"domain_reputation", "safe_browsing_key"},
	{"ai", "api_key"},
	{"captcha", "secret_key"},
	{"notifications", "telegram_token"},
	{"notifications", "slack_webhook"},
}

func maskValue(k string) string {
	if k == "" {
		return ""
	}
	tail := k
	if len(k) > 4 {
		tail = k[len(k)-4:]
	}
	return secretMask + tail
}

func masked(s settings.Settings) settings.Settings {
	s.DomainRep.SafeBrowsingKey = maskValue(s.DomainRep.SafeBrowsingKey)
	s.AI.APIKey = maskValue(s.AI.APIKey)
	s.Captcha.SecretKey = maskValue(s.Captcha.SecretKey)
	s.Notifications.TelegramToken = maskValue(s.Notifications.TelegramToken)
	s.Notifications.SlackWebhook = maskValue(s.Notifications.SlackWebhook)
	return s
}

// keepSecrets drops masked values sent back by the portal so the stored
// secrets are kept.
func keepSecrets(p json.RawMessage, _ settings.Settings) json.RawMessage {
	var doc map[string]json.RawMessage
	if json.Unmarshal(p, &doc) != nil {
		return p
	}
	changed := false
	for _, f := range secretFields {
		raw, ok := doc[f[0]]
		if !ok {
			continue
		}
		var sec map[string]json.RawMessage
		if json.Unmarshal(raw, &sec) != nil {
			continue
		}
		var v string
		if k, ok := sec[f[1]]; ok && json.Unmarshal(k, &v) == nil && strings.HasPrefix(v, secretMask) {
			delete(sec, f[1])
			doc[f[0]], _ = json.Marshal(sec)
			changed = true
		}
	}
	if !changed {
		return p
	}
	out, _ := json.Marshal(doc)
	return out
}

func wafChanged(a, b settings.WAF) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) != string(y)
}

func fwChanged(a, b settings.Firewall) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) != string(y)
}

// onAIVerdict applies the virus action to a suspicious file the AI scanner
// is confident is malicious, when the admin allowed it to act.
func (a *Agent) onAIVerdict(j ai.Job, v ai.Verdict) {
	st := a.Settings.Get()
	a.Log.Info("AI verdict", "path", j.Path, "verdict", v.Verdict, "confidence", v.Confidence, "model", v.Model)
	if v.Verdict != ai.Malicious || v.Confidence < 80 || !st.AI.Act {
		return
	}
	f, err := a.Scanner.Get(j.FindingID)
	if err != nil || f.Status != "detected" {
		return
	}
	switch st.Scanner.VirusAction {
	case settings.ActionQuarantine:
		err = a.Scanner.Quarantine(f.ID)
	case settings.ActionDisable:
		err = a.Scanner.Disable(f.ID)
	default:
		return
	}
	if err != nil {
		a.Log.Warn("AI action failed", "path", f.Path, "err", err)
		return
	}
	if n := st.Notifications; n.Email != "" && n.OnVirus {
		a.Mailer.Enqueue(n.Email, "AI scanner confirmed malware",
			fmt.Sprintf("[AI %d%%] %s\n  file: %s\n  reason: %s\n  action: %s\n", v.Confidence, f.Signature, f.Path, v.Reason, st.Scanner.VirusAction))
	}
}

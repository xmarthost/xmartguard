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
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/xmarthost/xmartguard/agent/internal/ai"
	"github.com/xmarthost/xmartguard/agent/internal/captcha"
	"github.com/xmarthost/xmartguard/agent/internal/client"
	"github.com/xmarthost/xmartguard/agent/internal/cms"
	"github.com/xmarthost/xmartguard/agent/internal/config"
	"github.com/xmarthost/xmartguard/agent/internal/firewall"
	"github.com/xmarthost/xmartguard/agent/internal/hostfw"
	"github.com/xmarthost/xmartguard/agent/internal/identity"
	"github.com/xmarthost/xmartguard/agent/internal/mail"
	"github.com/xmarthost/xmartguard/agent/internal/monitor"
	"github.com/xmarthost/xmartguard/agent/internal/notify"
	"github.com/xmarthost/xmartguard/agent/internal/reputation"
	"github.com/xmarthost/xmartguard/agent/internal/scanner"
	"github.com/xmarthost/xmartguard/agent/internal/settings"
	"github.com/xmarthost/xmartguard/agent/internal/store"
	"github.com/xmarthost/xmartguard/agent/internal/sysinfo"
	"github.com/xmarthost/xmartguard/agent/internal/tor"
	"github.com/xmarthost/xmartguard/agent/internal/trusted"
	"github.com/xmarthost/xmartguard/agent/internal/updater"
	"github.com/xmarthost/xmartguard/agent/internal/version"
	"github.com/xmarthost/xmartguard/agent/internal/waf"
	"github.com/xmarthost/xmartguard/agent/internal/wpcore"
)

// Agent holds every module.
type Agent struct {
	Cfg      *config.Config
	central  central
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
	started  time.Time // when Start ran (zero in tests)

	// WPSource and WPPlugins override where official WordPress files and
	// plugin checksums come from (tests).
	WPSource  wpcore.Source
	WPPlugins wpcore.PluginSource

	// ExitForUpdate is called after a successful self-update.
	ExitForUpdate func()

	protMu    sync.Mutex
	protected []string
	protAt    time.Time

	// HostFW keeps the portal allowed in CSF, firewalld, UFW, APF, cPHulk
	// and Imunify360 (nil in tests).
	HostFW *hostfw.Host
	// Trusted holds search engine, monitor, CDN and payment addresses.
	Trusted   *trusted.Store
	Tor       *tor.List
	clam      clamState
	hostMu    sync.Mutex
	hostTrust []hostfw.Result
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
	a.Scanner.OnClean = func(path string, _ os.FileInfo) { a.AI.EnqueueNew(path) }
	a.Scanner.Cleared = func(sha string) bool { return ai.IsCleared(db, sha) }
	plugins := &wpcore.Plugins{CacheDir: filepath.Join(store.StateDir(), "cms", "plugin-checksums")}
	var pluginsOnce sync.Once
	a.Scanner.KnownGoodPath = func(path string, sum [16]byte) bool {
		// The portal connection is set up after the scanner.
		pluginsOnce.Do(func() { plugins.Source = a.pluginSource() })
		return plugins.Known(path, sum)
	}
	a.Realtime = &scanner.Realtime{S: a.Scanner}
	a.HostFW = hostfw.New(filepath.Join(store.StateDir(), "host-trust.json"))
	a.Firewall = &firewall.Manager{
		DB: db, Settings: st, Log: log, NFT: firewall.FindNFT(), IPT: firewall.FindIPTables(),
		Geo:       &firewall.Geo{Dir: filepath.Join(store.StateDir(), "geo"), Log: log},
		IPDB:      &firewall.IPDB{},
		Protected: a.protectedIPs,
	}
	a.Firewall.FleetName = a.fleetName
	a.Trusted = trusted.New(filepath.Join(store.StateDir(), "trusted-services.json"))
	a.Tor = tor.New(filepath.Join(store.StateDir(), "tor-exits.json"))
	a.Trusted.SetCustom(st.Get().Firewall.TrustedCustom)
	a.Firewall.Trusted = a.trustedCIDRs
	a.Firewall.TrustedMatch = func(ip string) string {
		fw := a.Settings.Get().Firewall
		if !fw.TrustedServices {
			return ""
		}
		return a.Trusted.Match(ip, fw.TrustedDisabled)
	}
	a.Firewall.OnBan = a.onBan
	a.Firewall.EssentialTCPOut = portalPorts(cfg.ServerURL)
	a.Mailer.Channels = a.channels
	a.Mailer.Admin = func() string { return a.Settings.Get().Notifications.Email }
	a.AI = &ai.Analyzer{DB: db, Settings: st, Log: log, OnVerdict: a.onAIVerdict}
	if cfg != nil && cfg.ServerURL != "" {
		a.AI.Portal = &ai.PortalAI{URL: cfg.ServerURL, ServerID: cfg.ServerID, Sign: func(msg []byte) string {
			id, err := identity.Load(config.KeyPath())
			if err != nil {
				return ""
			}
			return id.SignB64(msg)
		}}
		// Country lists come from the portal's GeoIP database, so a
		// whitelisted or blocked country matches the country shown.
		a.Firewall.Geo.Portal = func(cc string) ([]string, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			var r struct {
				CIDRs []string `json:"cidrs"`
			}
			if err := a.AI.Portal.Post(ctx, "/api/agent/geo/zone", map[string]string{"cc": strings.ToUpper(cc)}, &r); err != nil {
				return nil, err
			}
			out := make([]string, 0, len(r.CIDRs))
			for _, c := range r.CIDRs {
				if p, err := netip.ParsePrefix(strings.TrimSpace(c)); err == nil {
					out = append(out, p.Masked().String())
				}
			}
			return out, nil
		}
	}
	a.Monitor = &monitor.Monitor{DB: db, Settings: st, Log: log, OnEvent: a.onMonitorEvent,
		Users: func() map[string]string {
			out := map[string]string{}
			for _, u := range scanner.Users() {
				out[u.Name] = u.Home
			}
			return out
		}}
	gateSecret := loadGateSecret(db)
	a.Captcha = &captcha.Server{Settings: st, Log: log, GateSecret: gateSecret, ServerID: cfg.ServerID, Solved: func(ip string) error {
		return a.Firewall.CaptchaSolved(ip, time.Duration(a.Settings.Get().Captcha.AllowMinutes)*time.Minute)
	}}
	a.WAF = &waf.Manager{DB: db, Settings: st, Log: log, RulesDir: config.Dir() + "/waf",
		AgentBin: selfPath(), Firewall: a.Firewall, BlockedIPs: a.Firewall.BlockedAddrs, TrustedIPs: a.wafTrustedCIDRs, VerifiedBots: a.wafVerifiedBots,
		IPDBIPs: a.Firewall.IPDBEntries, TorIPs: a.Tor.Addrs, RBLExempt: a.rblExempt, Intel: a.wafIntel,
		Gate: func() *waf.Gate {
			cur := a.Settings.Get()
			// While the portal's CAPTCHA page is on, it serves the login
			// pages too (see centralWAF).
			if !captcha.GateWanted(cur) || (cur.Captcha.Central && cur.Captcha.CentralURL != "") {
				return nil
			}
			return &waf.Gate{Tokens: captcha.GateTokens(gateSecret, time.Now()), HTTPPort: cur.Captcha.HTTPPort, HTTPSPort: cur.Captcha.HTTPSPort}
		}}
	a.WAF.Central = a.centralWAF
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
	a.started = time.Now()
	// Installs from before the xPGuard name move to the new program path and
	// service name once the agent has settled.
	go func() {
		select {
		case <-ctx.Done():
		case <-time.After(90 * time.Second):
			a.maybeMoveUnit(selfPath())
		}
	}()
	go a.Realtime.Run(ctx)
	go a.Firewall.Run(ctx)
	go a.Firewall.RunBruteForce(ctx)
	go a.Firewall.RunConnLog(ctx)
	go a.Scanner.Scheduler(ctx,
		func(kind string) int64 { n, _ := strconv.ParseInt(store.GetKV(a.DB, "last_"+kind), 10, 64); return n },
		func(kind string) { _ = store.SetKV(a.DB, "last_"+kind, strconv.FormatInt(time.Now().Unix(), 10)) })
	go a.reputationLoop(ctx)
	a.loadRuleSets()
	go a.WAF.Run(ctx)
	go a.wafSyncLoop(ctx)
	go a.CMS.Run(ctx)
	go a.OSM.Run(ctx)
	go a.domainRepLoop(ctx)
	go a.Captcha.Run(ctx)
	go a.AI.Run(ctx)
	go a.AI.RunSync(ctx)
	go a.wpCoreLoop(ctx)
	go a.Monitor.Run(ctx)
	go a.retentionLoop(ctx)
	go a.reportLoop(ctx)
	go a.hostTrustLoop(ctx)
	go a.proxyListLoop(ctx)
	go a.torLoop(ctx)
	go a.wafLearnLoop(ctx)
	go a.intelLoop(ctx)
	go a.centralLoop(ctx)
	// Put back system files that older rules quarantined (root's temp
	// files, SpamAssassin's compiled rules).
	go func() {
		if n := a.Scanner.RestoreSystemFiles(); n > 0 {
			a.Log.Info("restored system files quarantined by older rules", "count", n)
		}
	}()
	go a.trustedLoop(ctx)
	go a.clamLoop(ctx)
	go a.gateLoop(ctx)
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
	if n.OnVirus {
		a.alertAdmin("database infection found",
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
	return NewBinPath
}

// FleetServer is another server of this account running xPGuard.
type FleetServer struct {
	IP   string `json:"ip"`
	Host string `json:"host"`
}

const kvFleet = "fleet_servers"

// fleet are the account's servers, as the portal last sent them.
func (a *Agent) fleet() []FleetServer {
	var out []FleetServer
	_ = json.Unmarshal([]byte(store.GetKV(a.DB, kvFleet)), &out)
	return out
}

// fleetName names the xPGuard server an address belongs to ("" = none).
func (a *Agent) fleetName(ip string) string {
	for _, f := range a.fleet() {
		if f.IP == ip {
			return orText(f.Host, f.IP)
		}
	}
	return ""
}

// setFleet stores the portal's server list; a change reloads the firewall
// so the new servers are never blocked.
func (a *Agent) setFleet(list []FleetServer) (bool, error) {
	clean := []FleetServer{}
	seen := map[string]bool{}
	for _, f := range list {
		ip := net.ParseIP(strings.TrimSpace(f.IP))
		if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || seen[ip.String()] || len(clean) >= 5000 {
			continue
		}
		seen[ip.String()] = true
		h := strings.TrimSpace(f.Host)
		if len(h) > 253 {
			h = h[:253]
		}
		clean = append(clean, FleetServer{IP: ip.String(), Host: h})
	}
	sort.Slice(clean, func(i, j int) bool { return clean[i].IP < clean[j].IP })
	b, _ := json.Marshal(clean)
	if string(b) == store.GetKV(a.DB, kvFleet) {
		return false, nil
	}
	if err := store.SetKV(a.DB, kvFleet, string(b)); err != nil {
		return false, err
	}
	a.protMu.Lock()
	a.protected = nil
	a.protMu.Unlock()
	if a.Settings.Get().Firewall.Enabled {
		return true, a.Firewall.Apply()
	}
	return true, nil
}

// protectedIPs are never blocked: this server's addresses, loopback, the
// portal and the account's other xPGuard servers.
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
	// The other xPGuard servers of this account (sent by the portal).
	for _, f := range a.fleet() {
		ips = append(ips, f.IP)
	}
	a.protected, a.protAt = ips, time.Now()
	return ips
}

func (a *Agent) onFinding(f scanner.Finding) {
	a.maybeSuspend(f)
	// The scanner's own action (quarantine/disable) is already applied.
	// Repairing a WordPress core file downloads the official file, so it
	// runs in the background and never holds up realtime scanning.
	if root, _ := wpcore.FindRoot(f.Path); root != "" {
		go a.afterFinding(f, true)
		return
	}
	a.afterFinding(f, false)
}

func (a *Agent) afterFinding(f scanner.Finding, wordpress bool) {
	if wordpress && a.maybeRepairCore(f) {
		return // the official file is back in place
	}
	// Suspicious files get the AI's opinion. With the portal AI, detected
	// malware is sent too: the AI locates injected code (for Trim) and its
	// verdicts teach every linked server.
	if f.Category == scanner.CatSuspicious || (f.Category == scanner.CatVirus && a.Settings.Get().AI.Provider == "portal" && f.Signature != scanner.LearnedLabel) {
		if p, _, err := a.Scanner.ContentPath(f.ID); err == nil {
			a.AI.Enqueue(ai.Job{FindingID: f.ID, Path: p, SHA256: f.SHA256, Signature: f.Signature})
		}
	}
	n := a.Settings.Get().Notifications
	if n.UserInfected && (f.Category == scanner.CatVirus || f.Category == scanner.CatSymlink) && f.Owner != "" {
		a.notifyUser(f.Owner, "malware found in your account",
			fmt.Sprintf("A malicious file was found in your hosting account:\n  %s\n  detection: %s\n  action taken: %s\n", f.Path, f.Signature, f.Status))
	}
	if (f.Category == scanner.CatVirus && n.OnVirus) || (f.Category == scanner.CatSuspicious && n.OnSuspicious) || (f.Category == scanner.CatBinary && n.OnBinary) {
		a.alertAdmin("malware detected",
			fmt.Sprintf("[%s] %s\n  file: %s\n  owner: %s\n  status: %s\n", f.Category, f.Signature, f.Path, f.Owner, f.Status))
	}
}

func (a *Agent) onBan(e firewall.Event) {
	n := a.Settings.Get().Notifications
	if n.OnBan {
		a.alertAdmin("IP blocked", fmt.Sprintf("%s blocked: %s", e.IP, e.Reason))
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
	return map[string]any{"scanner": sc, "firewall": fw, "waf": a.WAF.Stats(), "blacklisted_ips": listed, "card": a.serverCard(),
		"problems": a.serviceProblems()}
}

// serverCard holds the numbers of the portal's server list card: all-time
// virus and web attacks, the IPDB hourly blocks of the last 24 hours (the
// sparkline), blacklisted domains and the number of hosted domains.
func (a *Agent) serverCard() map[string]any {
	var virus, web int64
	_ = a.DB.QueryRow(`SELECT count(*) FROM findings`).Scan(&virus)
	_ = a.DB.QueryRow(`SELECT count(*) FROM waf_events WHERE category IN ('waf','bot') AND action LIKE 'Access denied%'`).Scan(&web)
	now := store.Now()
	from := now - now%3600 - 23*3600
	hourly := make([]int64, 24)
	if rows, err := a.DB.Query(`SELECT (minute - ?) / 3600 AS h, sum(packets) FROM drop_stats WHERE kind = 'ipdb' AND minute >= ? GROUP BY h`, from, from); err == nil {
		for rows.Next() {
			var h, n int64
			if rows.Scan(&h, &n) == nil && h >= 0 && h < 24 {
				hourly[h] = n
			}
		}
		rows.Close()
	}
	domSum, _, _, _ := reputation.LoadDomains(a.DB, "", 1, 0)
	domains := len(cms.CPanelDocroots("/var/cpanel/userdata"))
	if domains == 0 {
		domains = domSum.Total
	}
	return map[string]any{
		"virus_attacks": virus, "web_attacks": web, "ipdb_hourly": hourly,
		"domains_blacklisted": domSum.Flagged, "domains": domains,
		// Daily counts of the last 14 days for the cards' small charts.
		"virus_daily": a.dailyCounts(`SELECT (created_at - ?) / 86400, count(*) FROM findings WHERE created_at >= ? GROUP BY 1`, 14),
		"web_daily":   a.dailyCounts(`SELECT (at - ?) / 86400, count(*) FROM waf_events WHERE at >= ? AND category IN ('waf','bot') AND action LIKE 'Access denied%' GROUP BY 1`, 14),
	}
}

// dailyCounts runs a "day index, count" query over the last n days (oldest
// first); q takes the start time twice.
func (a *Agent) dailyCounts(q string, n int) []int64 {
	now := store.Now()
	from := now - now%86400 - int64(n-1)*86400
	out := make([]int64, n)
	rows, err := a.DB.Query(q, from, from)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var d, c int64
		if rows.Scan(&d, &c) == nil && d >= 0 && d < int64(n) {
			out[d] = c
		}
	}
	return out
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
		if rep.ListedOn > 0 && (prev == nil || prev.ListedOn == 0) && cfg.Notifications.OnBlacklist {
			var names []string
			for _, l := range rep.Results {
				if l.Listed {
					names = append(names, l.RBL)
				}
			}
			a.alertAdmin("IP blacklisted", fmt.Sprintf("%s is listed on: %s", ip, strings.Join(names, ", ")))
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
	// scan.report: the summary shown above a scan's detections (like a
	// cPGuard report): files, detections, CMS and database state, duration.
	h["scan.report"] = func(_ context.Context, p json.RawMessage) (any, error) {
		in, err := decode[struct {
			ID int64 `json:"id"`
		}](p)
		if err != nil {
			return nil, err
		}
		sc, err := a.Scanner.GetScan(in.ID)
		if err != nil {
			return nil, fmt.Errorf("scan #%d not found", in.ID)
		}
		return a.scanReport(sc), nil
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
				err = a.restoreFinding(id)
			case "disable":
				err = a.Scanner.Disable(id)
			case "delete":
				err = a.Scanner.Delete(id)
			case "trim":
				err = a.trimFinding(id)
			case "clear":
				// A false positive: restore the file and never flag this
				// content again (on every server, through the portal).
				err = a.clearFinding(id)
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
		beforeScan := a.Settings.Get().Scanner
		p = keepSecrets(p, a.Settings.Get())
		next, err := a.Settings.Patch(p)
		if err != nil {
			return nil, err
		}
		a.Trusted.SetCustom(next.Firewall.TrustedCustom)
		if strings.Join(before.DDNS, ",") != strings.Join(next.Firewall.DDNS, ",") {
			a.Firewall.RefreshDDNS(ctx)
		}
		gateChanged := beforeCaptcha != next.Captcha || beforeWAF.Enabled != next.WAF.Enabled ||
			strings.Join(beforeWAF.LoginURLs, ",") != strings.Join(next.WAF.LoginURLs, ",")
		if fwChanged(before, next.Firewall) || beforeIPDB != next.IPDB || gateChanged {
			if err := a.Firewall.Apply(); err != nil {
				return nil, fmt.Errorf("settings saved, but the firewall could not be applied: %w", err)
			}
		}
		// Trusted services changed: the WAF's trusted list follows.
		if wafChanged(beforeWAF, next.WAF) || a.WAF.TrustedListChanged() || gateChanged {
			if err := a.WAF.Apply(); err != nil {
				return map[string]any{"settings": masked(next), "warning": err.Error()}, nil
			}
		}
		if beforeScan.ClamAV != next.Scanner.ClamAV || beforeScan.ClamAVURLs != next.Scanner.ClamAVURLs {
			go a.reloadClam(context.Background(), true)
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
			firewall.AllowOpts
		}](p)
		if err != nil {
			return nil, err
		}
		if in.Kind == firewall.KindAllow {
			r, err := a.Firewall.AddAllow(in.Addr, in.Comment, in.AllowOpts)
			return map[string]any{"rule": r}, err
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
	// fleet.set: the portal's list of this account's servers, whitelisted
	// on every server automatically.
	h["fleet.set"] = func(_ context.Context, p json.RawMessage) (any, error) {
		in, err := decode[struct {
			Servers []FleetServer `json:"servers"`
		}](p)
		if err != nil {
			return nil, err
		}
		changed, err := a.setFleet(in.Servers)
		return map[string]any{"changed": changed, "servers": len(a.fleet())}, err
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
			// Other firewalls on the server and the portal entries in them.
			"host_firewalls": a.hostTrustResults(),
			"csf":            a.Firewall.CSF(),
			// The account's xPGuard servers, whitelisted automatically.
			"fleet": a.fleet(),
		}, nil
	}
	// domains.list: websites hosted on the server (cPanel /etc/userdomains).
	h["domains.list"] = func(context.Context, json.RawMessage) (any, error) {
		d := reputation.HostedDomains(UserDomainsPath)
		out := make([]map[string]string, 0, len(d))
		for dom, user := range d {
			out = append(out, map[string]string{"domain": dom, "user": user})
		}
		sort.Slice(out, func(i, j int) bool { return out[i]["domain"] < out[j]["domain"] })
		return map[string]any{"domains": out}, nil
	}
	h["clamav.status"] = func(context.Context, json.RawMessage) (any, error) {
		return a.clamStatus(), nil
	}
	h["clamav.reload"] = func(ctx context.Context, _ json.RawMessage) (any, error) {
		a.reloadClam(ctx, true)
		return a.clamStatus(), nil
	}
	a.centralHandlers(h)
	a.intelHandlers(h)
	h["trusted.status"] = func(context.Context, json.RawMessage) (any, error) {
		fw := a.Settings.Get().Firewall
		return map[string]any{"enabled": fw.TrustedServices, "services": a.Trusted.Status(fw.TrustedDisabled)}, nil
	}
	// trusted.apply is the fleet-wide list from the portal (Overview »
	// Trusted Services): pushed to every online server when saved.
	h["trusted.apply"] = func(ctx context.Context, p json.RawMessage) (any, error) {
		in, err := decode[trustedConfig](p)
		if err != nil {
			return nil, err
		}
		if err := a.applyTrustedConfig(ctx, in); err != nil {
			return nil, err
		}
		fw := a.Settings.Get().Firewall
		return map[string]any{"enabled": fw.TrustedServices, "services": a.Trusted.Status(fw.TrustedDisabled)}, nil
	}
	h["trusted.refresh"] = func(ctx context.Context, _ json.RawMessage) (any, error) {
		a.refreshTrusted(ctx)
		fw := a.Settings.Get().Firewall
		return map[string]any{"enabled": fw.TrustedServices, "services": a.Trusted.Status(fw.TrustedDisabled)}, nil
	}
	h["exim.rbls"] = func(context.Context, json.RawMessage) (any, error) {
		return map[string]any{"rbls": mail.EximRBLStatus()}, nil
	}
	h["fw.host_sync"] = func(context.Context, json.RawMessage) (any, error) {
		return a.syncHostTrust(), nil
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
		j := ai.Job{FindingID: f.ID, Path: path, SHA256: f.SHA256, Signature: f.Signature}
		v, err := a.AI.Analyze(ctx, j)
		if err != nil {
			return nil, err
		}
		// Act on it now, as the background checks do: a confident "clean"
		// puts the file back at once, a confident "malicious" applies the
		// virus action or trims injected code.
		a.onAIVerdict(j, v)
		after, _ := a.Scanner.Get(in.ID)
		return struct {
			ai.Verdict
			Status string `json:"status"`
		}{v, after.Status}, nil
	}
	// finding.content shows a detected file (from quarantine when it was
	// moved there) with the lines the AI marked as injected.
	h["finding.content"] = func(_ context.Context, p json.RawMessage) (any, error) {
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
		raw, truncated, err := a.Scanner.Content(in.ID, 512<<10)
		if err != nil {
			return nil, err
		}
		out := map[string]any{"finding": f, "truncated": truncated, "binary": !utf8.Valid(raw) && strings.ContainsRune(string(raw), 0)}
		if out["binary"] == true {
			out["content"] = ""
		} else {
			out["content"] = strings.ToValidUTF8(string(raw), "\uFFFD")
		}
		if v, ok := ai.Cached(a.DB, f.SHA256); ok {
			out["ai"] = v
		}
		return out, nil
	}
	h["ai.sync"] = func(ctx context.Context, _ json.RawMessage) (any, error) {
		n, err := a.AI.Sync(ctx)
		return map[string]any{"verdicts": n}, err
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
	h["monitor.cron_enable"] = func(_ context.Context, p json.RawMessage) (any, error) {
		in, err := decode[struct {
			ID int64 `json:"id"`
		}](p)
		if err != nil {
			return nil, err
		}
		var user, line, action string
		if err := a.DB.QueryRow(`SELECT user, subject, action FROM monitor_events WHERE id = ? AND kind = 'cron'`, in.ID).Scan(&user, &line, &action); err != nil {
			return nil, errors.New("cron alert not found")
		}
		if action != "disabled" {
			return nil, errors.New("this cron job was not disabled by xPGuard")
		}
		if err := a.Monitor.EnableCron(user, line); err != nil {
			return nil, err
		}
		_, _ = a.DB.Exec(`UPDATE monitor_events SET action = 're-enabled' WHERE id = ?`, in.ID)
		return map[string]any{"ok": true}, nil
	}
	h["notify.test"] = func(context.Context, json.RawMessage) (any, error) {
		return a.testNotifications(), nil
	}
	h["monitor.rootkit"] = func(ctx context.Context, _ json.RawMessage) (any, error) {
		n, err := a.Monitor.RunRootkit(ctx)
		return map[string]any{"warnings": n}, err
	}
	h["waf.event_delete"] = func(_ context.Context, p json.RawMessage) (any, error) {
		in, err := decode[struct {
			IDs []int64 `json:"ids"`
		}](p)
		if err != nil {
			return nil, err
		}
		if len(in.IDs) == 0 || len(in.IDs) > 1000 {
			return nil, errors.New("select between 1 and 1000 log entries")
		}
		n, err := a.WAF.DeleteEvents(in.IDs)
		return map[string]any{"deleted": n}, err
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
		return map[string]any{"status": a.WAF.Status(), "rules": a.WAF.RuleCatalog(), "packages": a.WAF.PackageStates(), "stats": a.WAF.Stats(),
			"tor": a.Tor.Status(), "ipdb_addresses": len(a.Firewall.IPDBEntries()),
			"auto_exclusions": a.WAF.AutoExclusions(), "cpanel_off": waf.CPanelModsecOff()}, nil
	}
	// waf.auto_exclusion accepts, rejects or forgets a learned false positive.
	h["waf.auto_exclusion"] = func(_ context.Context, p json.RawMessage) (any, error) {
		in, err := decode[struct {
			Key    string `json:"key"`
			Action string `json:"action"`
		}](p)
		if err != nil {
			return nil, err
		}
		if err := a.WAF.SetAutoExclusion(in.Key, in.Action); err != nil {
			return nil, err
		}
		res := map[string]any{"auto_exclusions": a.WAF.AutoExclusions()}
		if err := a.WAF.Apply(); err != nil {
			res["warning"] = err.Error()
		}
		return res, nil
	}
	// waf.sync pulls the portal's WAF Rule Sets now and applies them.
	// waf.vendor_rules: where Malware.Expert replaces xPGuard's rules, its
	// packages and the rules of it that triggered here.
	h["waf.vendor_rules"] = func(context.Context, json.RawMessage) (any, error) {
		return a.WAF.VendorRules(), nil
	}
	// waf.vendor_rule switches one vendor rule off (false positive) or on.
	h["waf.vendor_rule"] = func(_ context.Context, p json.RawMessage) (any, error) {
		in, err := decode[struct {
			ID      int  `json:"id"`
			Enabled bool `json:"enabled"`
		}](p)
		if err != nil {
			return nil, err
		}
		if in.ID <= 0 || in.ID > 99999999 {
			return nil, errors.New("invalid rule id")
		}
		cur := a.Settings.Get().WAF.DisabledRules
		next := []int{}
		for _, id := range cur {
			if id != in.ID {
				next = append(next, id)
			}
		}
		if !in.Enabled {
			next = append(next, in.ID)
		}
		raw, _ := json.Marshal(map[string]any{"waf": map[string]any{"disabled_rules": next}})
		if _, err := a.Settings.Patch(raw); err != nil {
			return nil, err
		}
		res := map[string]any{"vendor": a.WAF.VendorRules()}
		if err := a.WAF.Apply(); err != nil {
			res["warning"] = err.Error()
		}
		return res, nil
	}
	h["waf.sync"] = func(ctx context.Context, _ json.RawMessage) (any, error) {
		res, err := a.syncWAF(ctx, true)
		if err != nil {
			return nil, err
		}
		go a.reportWAF(context.Background(), res)
		return res, nil
	}
	h["waf.events"] = func(_ context.Context, p json.RawMessage) (any, error) {
		f, err := decode[waf.EventFilter](p)
		if err != nil {
			return nil, err
		}
		evs, total, err := a.WAF.Events(f)
		return map[string]any{"events": evs, "total": total}, err
	}
	// waf.rule switches one xPGuard WAF rule on or off.
	h["waf.rule"] = func(_ context.Context, p json.RawMessage) (any, error) {
		in, err := decode[struct {
			ID      int  `json:"id"`
			Enabled bool `json:"enabled"`
		}](p)
		if err != nil {
			return nil, err
		}
		patch, err := waf.ToggleRule(a.Settings.Get().WAF, in.ID, in.Enabled)
		if err != nil {
			return nil, err
		}
		raw, _ := json.Marshal(map[string]any{"waf": patch})
		if _, err := a.Settings.Patch(raw); err != nil {
			return nil, err
		}
		res := map[string]any{"rules": a.WAF.RuleCatalog()}
		if err := a.WAF.Apply(); err != nil {
			res["warning"] = err.Error()
		}
		return res, nil
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
	// ---- portal address change (e.g. a new domain for the portal)
	h["portal.move"] = func(ctx context.Context, p json.RawMessage) (any, error) {
		in, err := decode[struct {
			URL string `json:"url"`
		}](p)
		if err != nil {
			return nil, err
		}
		next, err := checkPortalURL(ctx, client.HTTPClient(a.Cfg.InsecureTLS), in.URL)
		if err != nil {
			return nil, err
		}
		if next == a.Cfg.ServerURL {
			return map[string]any{"url": next, "changed": false}, nil
		}
		prev := a.Cfg.ServerURL
		a.Cfg.ServerURL = next
		if err := a.Cfg.Save(); err != nil {
			a.Cfg.ServerURL = prev
			return nil, err
		}
		a.Log.Info("portal address changed; restarting", "from", prev, "to", next)
		if a.ExitForUpdate != nil {
			go func() { time.Sleep(2 * time.Second); a.ExitForUpdate() }()
		}
		return map[string]any{"url": next, "changed": true}, nil
	}
	return h
}

// checkPortalURL accepts a new portal address only when it answers as a
// portal (GET /api/health returns {"ok":true}), so a wrong address can never
// cut the server off.
func checkPortalURL(ctx context.Context, hc *http.Client, raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.RawQuery != "" {
		return "", fmt.Errorf("invalid portal address %q", raw)
	}
	next := strings.TrimRight(u.Scheme+"://"+u.Host+u.Path, "/")
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, next+"/api/health", nil)
	if err != nil {
		return "", err
	}
	res, err := hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("the new portal address does not answer: %w", err)
	}
	defer res.Body.Close()
	var body struct {
		OK bool `json:"ok"`
	}
	if res.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(res.Body, 4096)).Decode(&body) != nil || !body.OK {
		return "", fmt.Errorf("%s does not answer as an xPGuard portal (HTTP %d)", next, res.StatusCode)
	}
	return next, nil
}

const secretMask = "********"

// masked hides API keys from portal users.
// secretFields are settings values never sent back to the portal in full.
var secretFields = [][2]string{
	{"domain_reputation", "safe_browsing_key"},
	{"captcha", "secret_key"},
	{"notifications", "telegram_token"},
	{"notifications", "slack_webhook"},
	{"notifications", "smtp_password"},
	{"scanner", "clamav_urls"},
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
	s.Captcha.SecretKey = maskValue(s.Captcha.SecretKey)
	s.Notifications.TelegramToken = maskValue(s.Notifications.TelegramToken)
	s.Notifications.SlackWebhook = maskValue(s.Notifications.SlackWebhook)
	s.Notifications.SMTPPassword = maskValue(s.Notifications.SMTPPassword)
	s.Scanner.ClamAVURLs = maskValue(s.Scanner.ClamAVURLs)
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

// onAIVerdict acts on a verdict: trims injected code when allowed, applies
// the virus action to files the AI is confident are malicious (when the
// admin allowed it), and records malware the signatures missed ("all files"
// mode).
func (a *Agent) onAIVerdict(j ai.Job, v ai.Verdict) {
	st := a.Settings.Get()
	a.Log.Info("AI verdict", "path", j.Path, "verdict", v.Verdict, "confidence", v.Confidence, "model", v.Model, "source", v.Source)
	if v.Verdict == ai.Clean && j.FindingID != 0 {
		a.clearFalsePositive(j, v)
		return
	}
	if v.Verdict != ai.Malicious || v.Confidence < 80 {
		return
	}
	if j.FindingID == 0 {
		// A file the signatures passed: record it so it shows in the logs.
		info, err := os.Lstat(j.Path)
		if err != nil || !info.Mode().IsRegular() {
			return
		}
		cat := scanner.CatSuspicious
		if st.AI.Act {
			cat = scanner.CatVirus
		}
		f, err := a.Scanner.Record(0, "ai", j.Path, info, scanner.Detection{Category: cat, Signature: "XG.AI.Malicious"})
		if err != nil {
			return
		}
		j.FindingID = f.ID
	}
	f, err := a.Scanner.Get(j.FindingID)
	if err != nil {
		return
	}
	if st.Scanner.Trim && v.Injected && len(v.Cut) > 0 && (f.Status == "detected" || f.Status == "quarantined" || f.Status == "disabled") {
		if err := a.Scanner.Trim(f.ID, v.Cut, st.Scanner.TrimMaxPercent); err != nil {
			a.Log.Info("trim not possible", "path", f.Path, "err", err)
		} else {
			a.Log.Info("injected code trimmed", "path", f.Path, "lines", len(v.Cut))
			if n := st.Notifications; n.OnVirus {
				a.alertAdmin("injected code removed",
					fmt.Sprintf("[AI %d%%] %s\n  file: %s\n  reason: %s\n  action: the injected code was trimmed; the site keeps running.\n  The original file is kept in quarantine.\n", v.Confidence, f.Signature, f.Path, v.Reason))
			}
			return
		}
	}
	if !st.AI.Act || f.Status != "detected" {
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
	if n := st.Notifications; n.OnVirus {
		a.alertAdmin("AI scanner confirmed malware",
			fmt.Sprintf("[AI %d%%] %s\n  file: %s\n  reason: %s\n  action: %s\n", v.Confidence, f.Signature, f.Path, v.Reason, st.Scanner.VirusAction))
	}
}

// clearFalsePositive restores a file the AI is sure is clean (a false
// positive) from quarantine. The verdict already went to the portal, so the
// same content is not flagged again on any server and the fleet model learns
// from it.
func (a *Agent) clearFalsePositive(j ai.Job, v ai.Verdict) {
	st := a.Settings.Get()
	if !st.AI.RestoreClean || v.Confidence < ai.ClearMinConfidence || (v.Source != "ai" && v.Source != "fleet") {
		return
	}
	f, err := a.Scanner.Get(j.FindingID)
	if err != nil || (f.Status != "quarantined" && f.Status != "disabled" && f.Status != "detected") {
		return
	}
	if err := a.Scanner.ClearAs(f.ID, scanner.StatusAIRestored); err != nil {
		a.Log.Warn("could not restore a file the AI found clean", "path", f.Path, "err", err)
		return
	}
	a.Log.Info("false positive cleared by the AI scanner", "path", f.Path, "signature", f.Signature, "confidence", v.Confidence)
	if n := st.Notifications; n.OnVirus && f.Status != "detected" {
		a.alertAdmin("false positive restored",
			fmt.Sprintf("[AI %d%% clean] %s\n  file: %s\n  reason: %s\n  action: restored from %s; the scanner will not flag this content again.\n", v.Confidence, f.Signature, f.Path, v.Reason, f.Status))
	}
}

// restoreFinding puts a file back and remembers its content as restored by
// an administrator, so later scans on this server do not flag the same,
// unchanged file again.
func (a *Agent) restoreFinding(id int64) error {
	f, err := a.Scanner.Get(id)
	if err != nil {
		return err
	}
	if err := a.Scanner.Restore(id); err != nil {
		return err
	}
	if f.SHA256 != "" {
		ai.Save(a.DB, ai.Verdict{SHA256: f.SHA256, Verdict: ai.Clean, Confidence: 100, Reason: "Restored from quarantine by an administrator.",
			Model: "admin", Source: ai.SourceAdmin, At: store.Now(), Size: f.Size})
	}
	return nil
}

// clearFinding marks a detection as a false positive by hand.
func (a *Agent) clearFinding(id int64) error {
	f, err := a.Scanner.Get(id)
	if err != nil {
		return err
	}
	if err := a.Scanner.Clear(id); err != nil {
		return err
	}
	if f.SHA256 != "" {
		ai.Save(a.DB, ai.Verdict{SHA256: f.SHA256, Verdict: ai.Clean, Confidence: 100, Reason: "Marked as a false positive by an administrator.",
			Model: "admin", Source: "ai", At: store.Now(), Size: f.Size})
	}
	return nil
}

// trimFinding removes the injected code the AI located in a finding's file
// (the "Trim" button and command).
func (a *Agent) trimFinding(id int64) error {
	f, err := a.Scanner.Get(id)
	if err != nil {
		return err
	}
	v, ok := ai.Cached(a.DB, f.SHA256)
	if !ok || v.Verdict != ai.Malicious || !v.Injected || len(v.Cut) == 0 {
		return errors.New("the AI has not located injected code in this file (check it with the AI first)")
	}
	return a.Scanner.Trim(id, v.Cut, a.Settings.Get().Scanner.TrimMaxPercent)
}

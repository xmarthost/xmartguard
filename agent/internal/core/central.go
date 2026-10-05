package core

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/captcha"
	"github.com/xmarthost/xmartguard/agent/internal/client"
	"github.com/xmarthost/xmartguard/agent/internal/firewall"
	"github.com/xmarthost/xmartguard/agent/internal/reputation"
	"github.com/xmarthost/xmartguard/agent/internal/store"
	"github.com/xmarthost/xmartguard/agent/internal/waf"
)

// Central CAPTCHA: suspicious visitors of the protected login pages are
// sent to the portal's CAPTCHA page (captcha.xpguard.org). The portal checks
// the CAPTCHA (Cloudflare Turnstile) and tells this agent the address passed
// (captcha.pass); the WAF then lets it through for the configured time.
//
// Suspicious are addresses on the IPDB, addresses banned here in the last
// 7 days and addresses the WAF blocked 3 or more times in the last 24 hours.

// centralConfig is the fleet-wide setting from the portal (Overview »
// CAPTCHA page).
type centralConfig struct {
	Version int64  `json:"version"`
	Enabled bool   `json:"enabled"`
	URL     string `json:"url"`
	Minutes int    `json:"minutes"`
}

const (
	kvCentralVersion = "central_captcha_version"
	kvCentralPass    = "central_captcha_pass" // JSON {ip: until unix}
)

// central holds the pass list and serialises WAF reloads for it.
type central struct {
	mu      sync.Mutex // pass list
	applyMu sync.Mutex // one WAF reload at a time
	gen     int64      // pass list changes
	applied int64      // last change a reload included
}

// centralWAF is the waf.Manager hook: nil when the central CAPTCHA is off
// or the login-page CAPTCHA already asks every visitor.
func (a *Agent) centralWAF() *waf.Central {
	cur := a.Settings.Get()
	c := cur.Captcha
	if !c.Central || c.CentralURL == "" || a.Cfg == nil || a.Cfg.ServerID == "" {
		return nil
	}
	// The login-page CAPTCHA for everyone uses the portal's page too.
	all := captcha.GateWanted(cur)
	w := &waf.Central{URL: c.CentralURL, ServerID: a.Cfg.ServerID, All: all, Pass: a.centralPassList()}
	if !all {
		w.Suspects = a.centralSuspects()
	}
	return w
}

// centralSuspects lists the addresses sent to the CAPTCHA.
func (a *Agent) centralSuspects() []string {
	set := map[string]bool{}
	if a.Firewall != nil && a.Settings.Get().IPDB.Enabled {
		for _, e := range a.Firewall.IPDBEntries() {
			set[e] = true
		}
	}
	now := store.Now()
	if rows, err := a.DB.Query(`SELECT DISTINCT ip FROM fw_events WHERE created_at >= ?`, now-7*86400); err == nil {
		for rows.Next() {
			var ip string
			if rows.Scan(&ip) == nil {
				set[ip] = true
			}
		}
		rows.Close()
	}
	if rows, err := a.DB.Query(`SELECT ip FROM waf_events WHERE at >= ? AND action LIKE 'Access denied%'
		AND NOT (rule_id BETWEEN 7700900 AND 7700909) GROUP BY ip HAVING count(*) >= 3`, now-86400); err == nil {
		for rows.Next() {
			var ip string
			if rows.Scan(&ip) == nil {
				set[ip] = true
			}
		}
		rows.Close()
	}
	// Tor exit nodes when their visitors are to solve the CAPTCHA.
	if a.Tor != nil && a.torMode() == "captcha" {
		for _, ip := range a.Tor.Addrs() {
			set[ip] = true
		}
	}
	// Never the server itself, the portal, allowed addresses or trusted services.
	skip := map[string]bool{}
	if a.Firewall != nil {
		for _, kind := range []string{firewall.KindAllow, firewall.KindIgnore, firewall.KindTempAllow} {
			if rs, err := a.Firewall.List(kind); err == nil {
				for _, r := range rs {
					if !r.Inbound() {
						continue
					}
					skip[r.CIDR] = true
				}
			}
		}
	}
	var out []string
	for ip := range set {
		if skip[ip] || net.ParseIP(ip) == nil && !strings.Contains(ip, "/") {
			continue
		}
		if a.Firewall != nil && a.Firewall.IsProtected(ip) {
			continue
		}
		out = append(out, ip)
	}
	sort.Strings(out)
	return out
}

// centralPassMap reads the pass list, dropping expired entries.
func (a *Agent) centralPassMap() map[string]int64 {
	m := map[string]int64{}
	_ = json.Unmarshal([]byte(store.GetKV(a.DB, kvCentralPass)), &m)
	now := time.Now().Unix()
	for ip, until := range m {
		if until <= now {
			delete(m, ip)
		}
	}
	return m
}

func (a *Agent) centralPassList() []string {
	a.central.mu.Lock()
	defer a.central.mu.Unlock()
	var out []string
	for ip := range a.centralPassMap() {
		out = append(out, ip)
	}
	sort.Strings(out)
	return out
}

// centralPass lets ip through the CAPTCHA for the configured time and
// reloads the WAF (one reload covers every pass added before it starts).
func (a *Agent) centralPass(ip string) error {
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid address %q", ip)
	}
	minutes := a.Settings.Get().Captcha.CentralMinutes
	a.central.mu.Lock()
	m := a.centralPassMap()
	m[net.ParseIP(ip).String()] = time.Now().Add(time.Duration(minutes) * time.Minute).Unix()
	b, _ := json.Marshal(m)
	err := store.SetKV(a.DB, kvCentralPass, string(b))
	a.central.gen++
	mine := a.central.gen
	a.central.mu.Unlock()
	if err != nil {
		return err
	}
	a.central.applyMu.Lock()
	defer a.central.applyMu.Unlock()
	if a.central.applied >= mine {
		return nil // a reload that started after this pass already ran
	}
	a.central.mu.Lock()
	upTo := a.central.gen
	a.central.mu.Unlock()
	if err := a.WAF.Apply(); err != nil {
		return err
	}
	a.central.applied = upTo
	return nil
}

// centralLiftBan lets a visitor that solved the portal's page through the
// firewall when it was sent there by a temporary ban or the IPDB (the
// firewall's CAPTCHA redirect): as solving the server's own page did.
// Permanent blocks stay.
func (a *Agent) centralLiftBan(ip string) {
	if a.Firewall == nil {
		return
	}
	banned := false
	if rs, err := a.Firewall.List(firewall.KindTempBan); err == nil {
		for _, r := range rs {
			if firewall.Contains(r.CIDR, ip) {
				banned = true
			}
		}
	}
	if !banned && a.Firewall.IPDB != nil && a.Settings.Get().IPDB.Enabled {
		if e, _ := a.Firewall.IPDB.Lookup(ip); e != "" {
			banned = true
		}
	}
	if !banned {
		return
	}
	// The portal's page says how long a solved check counts.
	c := a.Settings.Get().Captcha
	minutes := c.AllowMinutes
	if c.CentralMinutes > 0 {
		minutes = c.CentralMinutes
	}
	if err := a.Firewall.CaptchaSolved(ip, time.Duration(minutes)*time.Minute); err != nil {
		a.Log.Info("CAPTCHA solved but the address stays blocked", "ip", ip, "err", err)
	}
}

// hostedHere reports whether host (with or without www. and a port) is a
// website on the list of this server's domains. Without a list, nothing is.
func hostedHere(host string, domains map[string]string) bool {
	h := waf.NormHost(host)
	if h == "" || len(domains) == 0 {
		return false
	}
	if _, ok := domains[h]; ok {
		return true
	}
	_, ok := domains[strings.TrimPrefix(h, "www.")]
	return ok
}

// lookupIP and localAddrs are replaced in tests.
var (
	lookupIP = func(ctx context.Context, host string) ([]net.IP, error) {
		return net.DefaultResolver.LookupIP(ctx, "ip", host)
	}
	localAddrs = func() []net.IP {
		var out []net.IP
		addrs, _ := net.InterfaceAddrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				out = append(out, n.IP)
			}
		}
		return out
	}
)

// siteHere reports whether host is a website on this server, for a
// visitor ip that solved the portal's CAPTCHA. With cPanel's domain list
// that list decides. Without one (other panels), the WAF must have sent ip
// to the CAPTCHA for host recently, or host must point at this server: so
// the CAPTCHA domain never sends anyone on to a site that is not hosted
// here (an open redirect that phishing mails could use).
func (a *Agent) siteHere(ip, host string) bool {
	if d := reputation.HostedDomains(UserDomainsPath); len(d) > 0 {
		return hostedHere(host, d)
	}
	h := waf.NormHost(host)
	if h == "" {
		return false
	}
	if ip != "" && waf.SentToCaptcha(ip, h) {
		return true
	}
	if net.ParseIP(h) != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := lookupIP(ctx, h)
	if err != nil {
		return false
	}
	local := localAddrs()
	for _, x := range ips {
		for _, l := range local {
			if x.Equal(l) && !x.IsLoopback() {
				return true
			}
		}
	}
	return false
}

// applyCentralConfig makes the portal's setting this server's setting.
func (a *Agent) applyCentralConfig(ctx context.Context, c centralConfig) error {
	u, err := url.Parse(c.URL)
	if c.Enabled && (err != nil || u.Scheme != "https" || u.Host == "") {
		return fmt.Errorf("invalid CAPTCHA page address %q", c.URL)
	}
	patch, _ := json.Marshal(map[string]any{"captcha": map[string]any{
		"central": c.Enabled, "central_url": c.URL, "central_minutes": c.Minutes}})
	if _, err := a.Handlers()["settings.set"](ctx, patch); err != nil {
		return err
	}
	_ = store.SetKV(a.DB, kvCentralVersion, strconv.FormatInt(c.Version, 10))
	return nil
}

// pullCentralConfig fetches the portal's setting when it changed (servers
// that were offline when it was saved catch up here).
func (a *Agent) pullCentralConfig(ctx context.Context) {
	if a.AI == nil || a.AI.Portal == nil {
		return
	}
	cur, _ := strconv.ParseInt(store.GetKV(a.DB, kvCentralVersion), 10, 64)
	var r struct {
		Unchanged bool           `json:"unchanged"`
		Config    *centralConfig `json:"config"`
	}
	if err := a.AI.Portal.Post(ctx, "/api/agent/captcha/config", map[string]any{"version": cur}, &r); err != nil {
		a.Log.Debug("central CAPTCHA config not fetched", "err", err)
		return
	}
	if r.Unchanged || r.Config == nil {
		return
	}
	if err := a.applyCentralConfig(ctx, *r.Config); err != nil {
		a.Log.Warn("could not apply the portal's CAPTCHA page setting", "err", err)
	}
}

// centralLoop keeps the suspect list current: the WAF reloads when it
// changed (checked every 10 minutes), and the setting is re-fetched.
func (a *Agent) centralLoop(ctx context.Context) {
	for {
		a.pullCentralConfig(ctx)
		if a.WAF.CentralChanged() {
			a.central.applyMu.Lock()
			if err := a.WAF.Apply(); err != nil {
				a.Log.Warn("CAPTCHA list refresh failed", "err", err)
			}
			a.central.applyMu.Unlock()
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(10 * time.Minute):
		}
	}
}

// centralHandlers are the portal's commands for the central CAPTCHA.
func (a *Agent) centralHandlers(h map[string]client.Handler) {
	h["captcha.central"] = func(ctx context.Context, p json.RawMessage) (any, error) {
		in, err := decode[centralConfig](p)
		if err != nil {
			return nil, err
		}
		if err := a.applyCentralConfig(ctx, in); err != nil {
			return nil, err
		}
		return map[string]any{"ok": true}, nil
	}
	// captcha.host: may the CAPTCHA page name host (a website here that sent
	// ip to it)? Asked before the page shows a site's name.
	h["captcha.host"] = func(_ context.Context, p json.RawMessage) (any, error) {
		in, err := decode[struct {
			IP   string `json:"ip"`
			Host string `json:"host"`
		}](p)
		if err != nil {
			return nil, err
		}
		return map[string]any{"hosted": a.siteHere(in.IP, in.Host)}, nil
	}
	// captcha.pass: a visitor solved the CAPTCHA page for ip on host.
	h["captcha.pass"] = func(_ context.Context, p json.RawMessage) (any, error) {
		in, err := decode[struct {
			IP   string `json:"ip"`
			Host string `json:"host"`
		}](p)
		if err != nil {
			return nil, err
		}
		if !a.siteHere(in.IP, in.Host) {
			return nil, fmt.Errorf("%s is not a website on this server", in.Host)
		}
		if err := a.centralPass(in.IP); err != nil {
			return nil, err
		}
		a.centralLiftBan(in.IP)
		return map[string]any{"ok": true, "minutes": a.Settings.Get().Captcha.CentralMinutes}, nil
	}
}

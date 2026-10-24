package core

import (
	"context"
	"encoding/json"
	"errors"
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
	// Mode "site": the check is shown on the websites' own addresses.
	Mode string `json:"mode"`
	// IPDBCaptcha: visitors on the IPDB get the check on websites instead of
	// a dropped connection (settings ipdb.captcha), set for the whole fleet
	// on the portal's CAPTCHA page; absent: each server keeps its own.
	IPDBCaptcha *bool `json:"ipdb_captcha,omitempty"`
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
	if captcha.SiteWanted(cur) {
		w.Site, w.Slots, w.HTTPSPort = true, a.sitePasses.Slots(time.Now()), c.HTTPSPort
	}
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
		AND NOT (rule_id BETWEEN 7700900 AND 7700919) GROUP BY ip HAVING count(*) >= 3`, now-86400); err == nil {
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
		for _, kind := range []string{firewall.KindAllow, firewall.KindIgnore, firewall.KindTempAllow, firewall.KindCaptchaPass} {
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
	// Whitelisted countries are a full whitelist: never sent to the check.
	if a.Firewall != nil {
		out = a.Firewall.WithoutWhitelistedCountries(out)
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
func (a *Agent) centralPass(ips ...string) error { return a.centralPassFor(0, ips...) }

// centralPassFor lets the addresses in for the given minutes, at most the
// configured time (0: the configured time). The portal asks for less when
// the check was the proof-of-work fallback, which a script can solve.
func (a *Agent) centralPassFor(minutes int, ips ...string) error {
	for _, ip := range ips {
		if net.ParseIP(ip) == nil {
			return fmt.Errorf("invalid address %q", ip)
		}
	}
	if conf := a.Settings.Get().Captcha.CentralMinutes; minutes <= 0 || minutes > conf {
		minutes = conf
	}
	a.central.mu.Lock()
	m := a.centralPassMap()
	for _, ip := range ips {
		m[net.ParseIP(ip).String()] = time.Now().Add(time.Duration(minutes) * time.Minute).Unix()
	}
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
	// Wait out the reload gap before taking the passes to write: the ones
	// that arrive meanwhile go out with this reload. Waiting inside the
	// reload instead left each of them a full gap behind the one before,
	// past the portal's 90 seconds ("could not confirm the check").
	if w := a.WAF.PassReloadWait(); w > 0 {
		time.Sleep(w)
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

// onPassCookie withdraws a pass-cookie value of the check on the website's
// address that a suspect sent without having been given it (one solved
// check shared with other addresses): the WAF is applied without it.
func (a *Agent) onPassCookie(ip string, slot int) {
	if !a.sitePasses.Used(ip, slot, time.Now()) {
		return
	}
	a.Log.Warn("CAPTCHA pass cookie sent from an address it was not given to: value withdrawn", "ip", ip, "slot", slot)
	a.sitePasses.ApplyWithdrawn(func() { // one apply for withdrawals close together
		if err := a.WAF.Apply(); err != nil {
			a.Log.Warn("WAF re-apply after withdrawing a CAPTCHA pass failed", "err", err)
		}
	})
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
	mode := ""
	if c.Mode == "site" {
		mode = "site"
	}
	p := map[string]any{"captcha": map[string]any{
		"central": c.Enabled, "central_url": c.URL, "central_minutes": c.Minutes, "central_mode": mode}}
	if c.IPDBCaptcha != nil {
		p["ipdb"] = map[string]any{"captcha": *c.IPDBCaptcha}
	}
	patch, _ := json.Marshal(p)
	if _, err := a.setSettings(ctx, patch, ""); err != nil {
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
			if err := a.WAF.ApplyBackground(); err != nil {
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
			// Also: the address the visitor solved the check from. Mobile
			// networks (CGNAT) reach different sites from different
			// addresses: without it the next request to the site can come
			// from an address that is still sent to the check, again and
			// again.
			Also string `json:"also"`
			// Minutes: a shorter pass than configured (0: as configured).
			Minutes int `json:"minutes"`
		}](p)
		if err != nil {
			return nil, err
		}
		if !a.siteHere(in.IP, in.Host) {
			return nil, fmt.Errorf("%s is not a website on this server", in.Host)
		}
		// Banned for attacking after an earlier solved check, or
		// blacklisted: solving again does not let it in.
		if a.Firewall != nil {
			if err := a.Firewall.PassRefused(in.IP); err != nil {
				return nil, err
			}
		}
		ips := []string{in.IP}
		if in.Also != "" && in.Also != in.IP && net.ParseIP(in.Also) != nil {
			ips = append(ips, in.Also)
		}
		// Solved again while already let in: the reload for the first
		// pass has not reached the visitor yet (see RefreshPasses).
		again := false
		if ip := net.ParseIP(in.IP); ip != nil {
			a.central.mu.Lock()
			_, again = a.centralPassMap()[ip.String()]
			a.central.mu.Unlock()
		}
		if err := a.centralPassFor(in.Minutes, ips...); err != nil {
			return nil, err
		}
		if again {
			if err := a.WAF.RefreshPasses(); err != nil {
				a.Log.Warn("reload for a repeated CAPTCHA pass failed", "err", err)
			}
		}
		for _, ip := range ips {
			a.centralLiftBan(ip)
		}
		minutes := a.Settings.Get().Captcha.CentralMinutes
		if in.Minutes > 0 && in.Minutes < minutes {
			minutes = in.Minutes
		}
		return map[string]any{"ok": true, "minutes": minutes}, nil
	}
	// captcha.ticket: the visitor solved the portal's check shown on the
	// website's own address. The page there trades the ticket for the pass
	// cookie: no web server reload, so the visitor is back at once.
	h["captcha.ticket"] = func(_ context.Context, p json.RawMessage) (any, error) {
		in, err := decode[struct {
			IP    string `json:"ip"`
			Host  string `json:"host"`
			Nonce string `json:"nonce"`
		}](p)
		if err != nil {
			return nil, err
		}
		if !captcha.SiteWanted(a.Settings.Get()) {
			return nil, errors.New("the check is not shown on the websites' own addresses on this server")
		}
		if !a.siteHere(in.IP, in.Host) {
			return nil, fmt.Errorf("%s is not a website on this server", in.Host)
		}
		if a.Firewall != nil {
			if err := a.Firewall.PassRefused(in.IP); err != nil {
				return nil, err
			}
		}
		if !a.Captcha.AddTicket(in.Nonce, in.IP) {
			return nil, errors.New("invalid ticket")
		}
		return map[string]any{"ok": true}, nil
	}
}

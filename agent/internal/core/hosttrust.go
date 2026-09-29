package core

import (
	"context"
	"encoding/json"
	"net"
	"net/url"
	"strconv"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/hostfw"
	"github.com/xmarthost/xmartguard/agent/internal/store"
)

// portalAddrs are the addresses the agent reaches the portal at.
func (a *Agent) portalAddrs() []string {
	u, err := url.Parse(a.Cfg.ServerURL)
	if err != nil || u.Hostname() == "" {
		return nil
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil {
		return []string{ip.String()}
	}
	addrs, err := net.LookupHost(u.Hostname())
	if err != nil {
		return nil
	}
	return addrs
}

// syncHostTrust allows the portal in every other firewall on the server.
func (a *Agent) syncHostTrust() []hostfw.Result {
	if a.HostFW == nil {
		return nil
	}
	addrs := a.portalAddrs()
	if len(addrs) == 0 {
		return a.hostTrustResults() // DNS failure: keep what is there
	}
	res := a.HostFW.Sync(addrs)
	for _, r := range res {
		if r.Error != "" {
			a.Log.Warn("could not allow the portal in a host firewall", "firewall", r.Tool, "err", r.Error)
		}
	}
	a.hostMu.Lock()
	a.hostTrust = res
	a.hostMu.Unlock()
	return res
}

func (a *Agent) hostTrustResults() []hostfw.Result {
	a.hostMu.Lock()
	defer a.hostMu.Unlock()
	return a.hostTrust
}

// hostTrustLoop runs at start and hourly (the portal's address may change,
// a firewall may be installed later).
func (a *Agent) hostTrustLoop(ctx context.Context) {
	for {
		a.syncHostTrust()
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Hour):
		}
	}
}

// proxyListLoop refreshes the WAF's proxy IP check list every two hours
// when the firewall's blocked addresses changed (applying the WAF reloads
// the web server, so it is not done on every ban).
func (a *Agent) proxyListLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Hour):
		}
		if a.WAF.BlockedListChanged() {
			if err := a.WAF.Apply(); err != nil {
				a.Log.Warn("WAF proxy IP list refresh failed", "err", err)
			}
		}
	}
}

// trustedCIDRs are the enabled trusted services' addresses.
func (a *Agent) trustedCIDRs() []string {
	fw := a.Settings.Get().Firewall
	if !fw.TrustedServices || a.Trusted == nil {
		return nil
	}
	return a.Trusted.CIDRs(fw.TrustedDisabled)
}

// refreshTrusted downloads the official lists and reloads what uses them.
func (a *Agent) refreshTrusted(ctx context.Context) {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if a.Trusted.Refresh(cctx) && a.Settings.Get().Firewall.Enabled {
		if err := a.Firewall.Apply(); err != nil {
			a.Log.Warn("firewall reload after trusted services refresh failed", "err", err)
		}
	}
	if a.WAF.TrustedListChanged() {
		if err := a.WAF.Apply(); err != nil {
			a.Log.Warn("WAF reload after trusted services refresh failed", "err", err)
		}
	}
}

// trustedLoop refreshes the trusted services daily.
func (a *Agent) trustedLoop(ctx context.Context) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(2 * time.Minute):
	}
	last := time.Time{}
	for {
		a.pullTrustedConfig(ctx)
		if time.Since(last) > 24*time.Hour {
			a.refreshTrusted(ctx)
			last = time.Now()
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(30 * time.Minute):
		}
	}
}

// trustedConfig is the fleet-wide trusted services list made in the portal
// (Overview » Trusted Services).
type trustedConfig struct {
	Version  int64    `json:"version"`
	Enabled  bool     `json:"enabled"`
	Disabled []string `json:"disabled"`
	Custom   []string `json:"custom"`
}

// wafTrustedCIDRs are the trusted addresses the WAF's bot rules skip: not
// CDNs (every visitor of a proxied site comes from them) nor AI crawlers
// (they follow "Block AI crawlers").
func (a *Agent) wafTrustedCIDRs() []string {
	fw := a.Settings.Get().Firewall
	if !fw.TrustedServices || a.Trusted == nil {
		return nil
	}
	return a.Trusted.WAFCIDRs(fw.TrustedDisabled)
}

// applyTrustedConfig makes the portal's list this server's list, through
// the same path as a settings change (firewall and WAF follow).
func (a *Agent) applyTrustedConfig(ctx context.Context, c trustedConfig) error {
	if c.Disabled == nil {
		c.Disabled = []string{}
	}
	if c.Custom == nil {
		c.Custom = []string{}
	}
	patch, _ := json.Marshal(map[string]any{"firewall": map[string]any{
		"trusted_services": c.Enabled, "trusted_disabled": c.Disabled, "trusted_custom": c.Custom}})
	if _, err := a.Handlers()["settings.set"](ctx, patch); err != nil {
		return err
	}
	_ = store.SetKV(a.DB, "trusted_version", strconv.FormatInt(c.Version, 10))
	return nil
}

// pullTrustedConfig fetches the portal's list when it changed (servers that
// were offline when it was saved catch up here).
func (a *Agent) pullTrustedConfig(ctx context.Context) {
	if a.AI == nil || a.AI.Portal == nil {
		return
	}
	cur, _ := strconv.ParseInt(store.GetKV(a.DB, "trusted_version"), 10, 64)
	var r struct {
		Unchanged bool           `json:"unchanged"`
		Config    *trustedConfig `json:"config"`
	}
	if err := a.AI.Portal.Post(ctx, "/api/agent/trusted/config", map[string]any{"version": cur}, &r); err != nil {
		a.Log.Debug("trusted services config not fetched", "err", err)
		return
	}
	if r.Unchanged || r.Config == nil {
		return
	}
	if err := a.applyTrustedConfig(ctx, *r.Config); err != nil {
		a.Log.Warn("could not apply the portal's trusted services", "err", err)
	}
}

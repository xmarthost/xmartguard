package core

import (
	"context"
	"net"
	"net/url"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/hostfw"
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
	for {
		a.refreshTrusted(ctx)
		select {
		case <-ctx.Done():
			return
		case <-time.After(24 * time.Hour):
		}
	}
}

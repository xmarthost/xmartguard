package core

import (
	"context"
	"strings"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/firewall"
	"github.com/xmarthost/xmartguard/agent/internal/waf"
)

// rblExempt are addresses the IPDB POST block and the Tor rules never
// block: allowed, ignored and temporarily allowed addresses (a solved
// firewall CAPTCHA) and those that solved the portal's CAPTCHA page.
func (a *Agent) rblExempt() []string {
	var out []string
	if a.Firewall != nil {
		for _, kind := range []string{firewall.KindAllow, firewall.KindIgnore, firewall.KindTempAllow} {
			if rs, err := a.Firewall.List(kind); err == nil {
				for _, r := range rs {
					if !r.Inbound() {
						continue
					}
					out = append(out, r.CIDR)
				}
			}
		}
	}
	return append(out, a.centralPassList()...)
}

// torMode is the Tor rule in use (see waf.TorMode).
func (a *Agent) torMode() string {
	cur := a.Settings.Get()
	return waf.TorMode(cur.WAF.TorAction, cur.WAF.Enabled && cur.Captcha.Central && cur.Captcha.CentralURL != "")
}

// torLoop keeps the Tor exit list current while a Tor rule is on: it is
// downloaded every 6 hours (after a failure, again after an hour) and the
// WAF reloads when the list changed.
func (a *Agent) torLoop(ctx context.Context) {
	var lastTry time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Minute):
		}
		w := a.Settings.Get().WAF
		if !w.Enabled || w.TorAction == "off" || !a.Tor.Due(6*time.Hour) || time.Since(lastTry) < time.Hour {
			continue
		}
		lastTry = time.Now()
		cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		_, err := a.Tor.Refresh(cctx)
		cancel()
		if err != nil {
			a.Log.Warn("Tor exit list download failed", "err", err)
			continue
		}
		lastTry = time.Time{}
		if a.WAF.BlockedListChanged() || a.WAF.CentralChanged() {
			a.central.applyMu.Lock()
			if err := a.WAF.Apply(); err != nil {
				a.Log.Warn("WAF reload after the Tor list update failed", "err", err)
			}
			a.central.applyMu.Unlock()
		}
	}
}

// wafLearnLoop learns WAF false positives hourly and follows cPanel's
// per-website ModSecurity switches (checked every two minutes); the rules
// are reloaded when either changed.
func (a *Agent) wafLearnLoop(ctx context.Context) {
	lastOff := strings.Join(waf.CPanelModsecOff(), ",")
	var lastLearn time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Minute):
		}
		reload := false
		if off := strings.Join(waf.CPanelModsecOff(), ","); off != lastOff {
			lastOff = off
			reload = true
		}
		if time.Since(lastLearn) >= time.Hour {
			lastLearn = time.Now()
			changed, err := a.WAF.Learn(time.Now().Unix())
			if err != nil {
				a.Log.Warn("WAF false-positive learning failed", "err", err)
			}
			reload = reload || changed
		}
		if reload {
			a.central.applyMu.Lock()
			if err := a.WAF.Apply(); err != nil {
				a.Log.Warn("WAF reload failed", "err", err)
			}
			a.central.applyMu.Unlock()
		}
	}
}

package core

import (
	"context"
	"sync"
	"time"
)

// Real SEO and AI crawlers (Semrush, CCBot, Amazonbot, …) are blocked by the bot lists until
// their address is verified: each address the bot rules block is checked
// once a day by reverse DNS, and a real crawler joins the trusted services
// (the WAF reloads its list in the background). Fakes stay blocked.

var (
	crawlerMu   sync.Mutex
	crawlerSeen = map[string]time.Time{}
	crawlerSem  = make(chan struct{}, 2)
)

// crawlerMax bounds the addresses remembered (a bot wave rotating IPv6
// addresses would otherwise grow the map without limit).
const crawlerMax = 20000

func (a *Agent) onBotBlocked(ip, matched string) {
	if a.Trusted == nil || !a.Settings.Get().Firewall.TrustedServices {
		return
	}
	now := time.Now()
	crawlerMu.Lock()
	if t, ok := crawlerSeen[ip]; ok && now.Sub(t) < 24*time.Hour {
		crawlerMu.Unlock()
		return
	}
	if len(crawlerSeen) >= crawlerMax {
		for k, t := range crawlerSeen {
			if now.Sub(t) >= 24*time.Hour {
				delete(crawlerSeen, k)
			}
		}
		// Still full: forget arbitrary addresses (they are only checked
		// again on their next block).
		for k := range crawlerSeen {
			if len(crawlerSeen) < crawlerMax {
				break
			}
			delete(crawlerSeen, k)
		}
	}
	select {
	case crawlerSem <- struct{}{}:
	default:
		// Busy: not marked seen, so the address is checked on a later
		// block (not skipped for a day).
		crawlerMu.Unlock()
		return
	}
	crawlerSeen[ip] = now
	crawlerMu.Unlock()
	go func() {
		defer func() { <-crawlerSem }()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if id := a.Trusted.VerifyCrawler(ctx, ip, matched); id != "" {
			a.Log.Info("verified crawler trusted", "ip", ip, "service", id)
			if a.WAF.TrustedListChanged() {
				if err := a.WAF.ApplyBackground(); err != nil {
					a.Log.Warn("WAF reload after a verified crawler failed", "err", err)
				}
			}
		}
	}()
}

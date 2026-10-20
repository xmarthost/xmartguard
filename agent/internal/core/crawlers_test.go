package core

import (
	"fmt"
	"testing"
	"time"
)

// Audit A1 F14: an address blocked while both checks are busy is checked
// on its next block (not skipped for a day), and the remembered addresses
// stay bounded.
func TestCrawlerCheckBusyAndBounded(t *testing.T) {
	a := newTestAgent(t, `{"firewall":{"enabled":false,"trusted_services":true}}`)
	if a.Trusted == nil || !a.Settings.Get().Firewall.TrustedServices {
		t.Skip("trusted services not set up in the test agent")
	}
	// Both check slots taken: nothing reaches the network.
	crawlerSem <- struct{}{}
	crawlerSem <- struct{}{}
	defer func() { <-crawlerSem; <-crawlerSem }()
	crawlerMu.Lock()
	crawlerSeen = map[string]time.Time{}
	crawlerMu.Unlock()
	a.onBotBlocked("192.0.2.10", "SemrushBot")
	crawlerMu.Lock()
	_, seen := crawlerSeen["192.0.2.10"]
	crawlerMu.Unlock()
	if seen {
		t.Fatal("address marked checked while the checks were busy")
	}
	crawlerMu.Lock()
	for i := 0; i < crawlerMax+50; i++ {
		crawlerSeen[fmt.Sprintf("2001:db8::%x", i)] = time.Now()
	}
	crawlerMu.Unlock()
	a.onBotBlocked("192.0.2.11", "SemrushBot")
	crawlerMu.Lock()
	n := len(crawlerSeen)
	crawlerSeen = map[string]time.Time{}
	crawlerMu.Unlock()
	if n >= crawlerMax {
		t.Fatalf("%d addresses remembered", n)
	}
}

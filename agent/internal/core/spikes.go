package core

import (
	"context"
	"fmt"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/waf"
)

// wafSpikeLoop alerts when a WAF rule suddenly blocks far more than usual
// (once per rule in 6 hours). Nothing is switched off by itself: a new
// attack wave looks the same as a wrong rule, and only a person can tell.
func (a *Agent) wafSpikeLoop(ctx context.Context) {
	tick := time.NewTicker(15 * time.Minute)
	defer tick.Stop()
	sent := map[int]time.Time{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		if a.WAF == nil {
			continue
		}
		for _, s := range a.WAF.Spikes() {
			if time.Since(sent[s.RuleID]) < 6*time.Hour {
				continue
			}
			sent[s.RuleID] = time.Now()
			a.Log.Warn("WAF rule spike", "rule", s.RuleID, "last_hour", s.LastHour, "usual", s.Usual)
			a.alertAdmin(fmt.Sprintf("WAF rule %d blocks %dx more than usual", s.RuleID, int(float64(s.LastHour)/max(s.Usual, 1))), spikeText(s))
		}
	}
}

func spikeText(s waf.Spike) string {
	return fmt.Sprintf("Rule %d (%s) blocked %d requests on %d website(s) in the last hour; usually about %.0f an hour.\n"+
		"Either an attack wave or a rule blocking real visitors. Check WAF Logs: if real visitors are blocked, switch the rule off for the website "+
		"(or everywhere) from the log entry, or put a new rule back to watching in the Learning Center.", s.RuleID, s.Msg, s.LastHour, s.Hosts, s.Usual)
}

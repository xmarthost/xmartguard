package core

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/mail"
	"github.com/xmarthost/xmartguard/agent/internal/store"
)

// kvEximOurs: the Exim blocklists xPGuard switched on (it only ever
// switches those off again).
const kvEximOurs = "exim_guard_ours"

// eximGuardEvery: blocklists are re-tested this often (a resolver change
// can make a list refuse every message).
const eximGuardEvery = 6 * time.Hour

// mailGuardLoop keeps cPanel's Exim blocklists and the phishing filter in
// line with Settings » RBL & IP Reputation.
func (a *Agent) mailGuardLoop(ctx context.Context) {
	last, lastRun := "", time.Time{}
	wait := 45 * time.Second
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = time.Minute
		r := a.Settings.Get().Reputation
		key := fmt.Sprint(r.EximRBLs, r.PhishingFilter, r.SpamhausDQSKey)
		if key == last && time.Since(lastRun) < eximGuardEvery {
			continue
		}
		a.runMailGuard(ctx)
		last, lastRun = key, time.Now()
	}
}

func (a *Agent) runMailGuard(ctx context.Context) mail.EximGuardStatus {
	r := a.Settings.Get().Reputation
	var ours []string
	_ = json.Unmarshal([]byte(store.GetKV(a.DB, kvEximOurs)), &ours)
	st, ours := mail.ApplyEximGuardDQS(ctx, r.EximRBLs, r.PhishingFilter, strings.ToLower(strings.TrimSpace(r.SpamhausDQSKey)), ours)
	if b, err := json.Marshal(ours); err == nil {
		_ = store.SetKV(a.DB, kvEximOurs, string(b))
	}
	a.mailGuard.Store(&st)
	switch {
	case st.Error != "":
		a.Log.Warn("Exim mail protection not applied", "err", st.Error)
	case st.Rebuilt:
		a.Log.Info("Exim mail protection applied", "rbls_on", ours, "phishing_filter", st.Phishing)
	}
	return st
}

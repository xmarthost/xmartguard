package core

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/mail"
	"github.com/xmarthost/xmartguard/agent/internal/settings"
	"github.com/xmarthost/xmartguard/agent/internal/store"
)

// kvEximOurs: the Exim blocklists xPGuard switched on (it only ever
// switches those off again).
const kvEximOurs = "exim_guard_ours"

// kvMailGlobal: the portal's account-wide mail settings (Spamhaus DQS key),
// used where the server has no key of its own.
const kvMailGlobal = "mail_global"

// MailGlobal is what the portal sends with mail.global: the account-wide
// keys every server uses unless it has its own.
type MailGlobal struct {
	DQSKey          string `json:"dqs_key"`
	SafeBrowsingKey string `json:"safe_browsing_key,omitempty"`
}

func (a *Agent) mailGlobal() MailGlobal {
	var g MailGlobal
	_ = json.Unmarshal([]byte(store.GetKV(a.DB, kvMailGlobal)), &g)
	return g
}

// setMailGlobal stores the portal's settings and applies them at once.
func (a *Agent) setMailGlobal(g MailGlobal) error {
	g.DQSKey = strings.ToLower(strings.TrimSpace(g.DQSKey))
	if g.DQSKey != "" && !mail.ValidDQSKey(g.DQSKey) {
		return fmt.Errorf("invalid Spamhaus DQS key")
	}
	g.SafeBrowsingKey = strings.TrimSpace(g.SafeBrowsingKey)
	if !settings.ValidSafeBrowsingKey(g.SafeBrowsingKey) {
		return fmt.Errorf("invalid Google Safe Browsing key")
	}
	if g == a.mailGlobal() {
		return nil
	}
	b, _ := json.Marshal(g)
	if err := store.SetKV(a.DB, kvMailGlobal, string(b)); err != nil {
		return err
	}
	go a.runMailGuard(context.Background())
	return nil
}

// dqsKey: the server's own key, else the portal's.
func (a *Agent) dqsKey() (key, source string) {
	if k := strings.ToLower(strings.TrimSpace(a.Settings.Get().Reputation.SpamhausDQSKey)); k != "" {
		return k, "server"
	}
	if k := a.mailGlobal().DQSKey; k != "" {
		return k, "portal"
	}
	return "", ""
}

// safeBrowsingKey: the server's own key, else the portal's.
func (a *Agent) safeBrowsingKey() (key, source string) {
	if k := a.Settings.Get().DomainRep.SafeBrowsingKey; k != "" {
		return k, "server"
	}
	if k := a.mailGlobal().SafeBrowsingKey; k != "" {
		return k, "portal"
	}
	return "", ""
}

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
		dqs, _ := a.dqsKey()
		key := fmt.Sprint(r.EximRBLs, r.PhishingFilter, dqs)
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
	dqs, src := a.dqsKey()
	a.mailGuardMu.Lock()
	defer a.mailGuardMu.Unlock()
	st, ours := mail.ApplyEximGuardDQS(ctx, r.EximRBLs, r.PhishingFilter, dqs, ours)
	st.DQSSource = src
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

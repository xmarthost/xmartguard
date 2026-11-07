package core

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/captcha"
	"github.com/xmarthost/xmartguard/agent/internal/store"
)

// loadGateSecret returns the key that signs login-page CAPTCHA passes,
// created once and kept in the agent database.
func loadGateSecret(db *sql.DB) []byte {
	if b, err := hex.DecodeString(store.GetKV(db, "captcha_gate_secret")); err == nil && len(b) == 32 {
		return b
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil
	}
	_ = store.SetKV(db, "captcha_gate_secret", hex.EncodeToString(b))
	return b
}

// gateLoop re-applies the WAF when the day changes, so the login-page
// CAPTCHA accepts the new day's pass (and forgets the day before yesterday's).
func (a *Agent) gateLoop(ctx context.Context) {
	day := time.Now().UTC().Unix() / 86400
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		d := time.Now().UTC().Unix() / 86400
		if d == day {
			continue
		}
		newWeek := d/7 != day/7
		day = d
		st := a.Settings.Get()
		// The server's own login-page CAPTCHA: its values change daily.
		if captcha.GateWanted(st) {
			if err := a.WAF.Apply(); err != nil {
				a.Log.Warn("WAF re-apply for the login-page CAPTCHA failed", "err", err)
			}
			continue
		}
		// The portal's pass cookie: values for a whole week, so one
		// reload a week, with the next one the server makes (background;
		// the last day of the old week stays good meanwhile).
		if newWeek && (captcha.SiteWanted(st) || a.central.sitePage.Load()) {
			if err := a.WAF.ApplyBackground(); err != nil {
				a.Log.Warn("WAF re-apply for the CAPTCHA pass values failed", "err", err)
			}
		}
	}
}

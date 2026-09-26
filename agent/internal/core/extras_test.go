package core

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/xmarthost/xmartguard/agent/internal/config"
	"github.com/xmarthost/xmartguard/agent/internal/scanner"
	"github.com/xmarthost/xmartguard/agent/internal/settings"
	"github.com/xmarthost/xmartguard/agent/internal/store"
)

func newTestAgent(t *testing.T, settingsJSON string) *Agent {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XG_STATE_DIR", filepath.Join(dir, "state"))
	t.Setenv("XG_CONFIG_DIR", filepath.Join(dir, "conf"))
	os.MkdirAll(filepath.Join(dir, "conf"), 0o700)
	os.WriteFile(filepath.Join(dir, "conf", "settings.json"), []byte(settingsJSON), 0o600)
	a, err := New(&config.Config{ServerURL: "https://portal.example", ServerID: "x"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.DB.Close() })
	return a
}

func TestDashboardAggregates(t *testing.T) {
	a := newTestAgent(t, `{"firewall":{"enabled":false}}`)
	now := store.Now()
	for i, cat := range []string{"virus", "virus", "suspicious"} {
		a.DB.Exec(`INSERT INTO findings (source, path, owner, category, signature, status, created_at, updated_at) VALUES ('manual',?,?,?, 'X', 'detected', ?, ?)`,
			"/home/a/f"+string(rune('a'+i)), "alice", cat, now-100, now-100)
	}
	a.DB.Exec(`INSERT INTO findings (source, path, owner, category, signature, status, created_at, updated_at) VALUES ('manual','/old','alice','virus','X','deleted',?,?)`, now-40*86400, now-40*86400)
	a.DB.Exec(`INSERT INTO waf_events (at, ip, category) VALUES (?, '1.2.3.4', 'waf'), (?, '1.2.3.5', 'bot'), (?, '1.2.3.6', 'login')`, now-50, now-50, now-50)
	a.DB.Exec(`INSERT INTO drop_stats (minute, kind, packets) VALUES (?, 'ipdb', 500), (?, 'deny', 20)`, now-now%60-60, now-now%60-60)
	a.DB.Exec(`INSERT INTO domain_reputation (domain, user, status, reasons, checked_at) VALUES ('bad.example','bob','listed','PHISHING (SURBL)',?)`, now)
	d := a.Dashboard(30)
	th := d["threats"].(periodCount)
	if th.Current != 3 || th.Previous != 1 || th.Overall != 4 {
		t.Fatalf("threats %+v", th)
	}
	if w := d["web_attacks"].(periodCount); w.Current != 2 {
		t.Fatalf("web %+v (login attempts must not count)", w)
	}
	if c := d["blocked_connections"].(periodCount); c.Current != 520 {
		t.Fatalf("conns %+v", c)
	}
	if len(d["attacks_daily"].([]dayPoint)) != 30 {
		t.Fatal("daily length")
	}
	inf := d["infections_daily"].(map[string][]dayPoint)
	var virus int64
	for _, p := range inf["virus"] {
		virus += p.N
	}
	if virus != 2 {
		t.Fatalf("virus daily %d", virus)
	}
	sum := d["summary"].(map[string]any)
	if sum["domains_blacklisted"].(int) != 1 {
		t.Fatalf("summary %+v", sum)
	}
	raw, _ := json.Marshal(d["alerts"])
	var alerts []struct {
		Text    string   `json:"text"`
		Details []string `json:"details"`
	}
	json.Unmarshal(raw, &alerts)
	if len(alerts) == 0 || alerts[0].Text != "1 Blacklisted Domain found" || len(alerts[0].Details) != 1 {
		t.Fatalf("alerts %s", raw)
	}
}

func TestAutoSuspendThreshold(t *testing.T) {
	a := newTestAgent(t, `{"firewall":{"enabled":false},"auto_suspend":{"enabled":true,"detections":3,"window_hours":24,"exclude_users":["trusted"]}}`)
	now := store.Now()
	add := func(owner string) scanner.Finding {
		a.DB.Exec(`INSERT INTO findings (source, path, owner, category, signature, status, created_at, updated_at) VALUES ('realtime','/x',?, 'virus','X','detected',?,?)`, owner, now, now)
		return scanner.Finding{Owner: owner, Category: scanner.CatVirus}
	}
	a.maybeSuspend(add("alice"))
	a.maybeSuspend(add("alice"))
	if len(a.suspensions()) != 0 {
		t.Fatal("suspended below threshold")
	}
	a.maybeSuspend(add("alice"))
	s := a.suspensions()
	// No cPanel here, so the attempt is recorded as failed (and not retried as a duplicate "suspended").
	if len(s) != 1 || s[0].User != "alice" || s[0].Status != "failed" {
		t.Fatalf("suspensions %+v", s)
	}
	for i := 0; i < 5; i++ {
		a.maybeSuspend(add("trusted"))
	}
	if len(a.suspensions()) != 1 {
		t.Fatal("excluded user suspended")
	}
	if err := a.liftSuspension(s[0].ID); err == nil {
		t.Fatal("lifted a failed suspension")
	}
}

func TestSecretMasking(t *testing.T) {
	a := newTestAgent(t, `{"firewall":{"enabled":false},"domain_reputation":{"safe_browsing_key":"AIzaSecretKey1234"}}`)
	h := a.Handlers()
	out, _ := h["settings.get"](context.Background(), nil)
	got := out.(map[string]any)["settings"].(settings.Settings).DomainRep.SafeBrowsingKey
	if got != "********1234" {
		t.Fatalf("masked key %q", got)
	}
	// Saving the masked value back keeps the real key.
	if _, err := h["settings.set"](context.Background(), []byte(`{"domain_reputation":{"safe_browsing_key":"********1234","interval_hours":6}}`)); err != nil {
		t.Fatal(err)
	}
	if k := a.Settings.Get().DomainRep.SafeBrowsingKey; k != "AIzaSecretKey1234" || a.Settings.Get().DomainRep.IntervalHours != 6 {
		t.Fatalf("stored %q", k)
	}
	// A new key replaces it.
	h["settings.set"](context.Background(), []byte(`{"domain_reputation":{"safe_browsing_key":"NewKey5678"}}`))
	if a.Settings.Get().DomainRep.SafeBrowsingKey != "NewKey5678" {
		t.Fatal("new key not saved")
	}
}

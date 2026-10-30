package core

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/audit"
	"github.com/xmarthost/xmartguard/agent/internal/client"
	"github.com/xmarthost/xmartguard/agent/internal/cms"
	"github.com/xmarthost/xmartguard/agent/internal/scanner"
	"github.com/xmarthost/xmartguard/agent/internal/store"
)

// The server audit (risky settings, keys and backups in websites, stuck
// PHP, cron jobs) runs once a night and on request. It only reports.

var auditRunning atomic.Bool

func auditPath() string { return filepath.Join(store.StateDir(), "audit.json") }

func (a *Agent) auditor() *audit.Auditor {
	return &audit.Auditor{
		Accounts: func() []audit.Account {
			var out []audit.Account
			for _, u := range scanner.Users() {
				out = append(out, audit.Account{Name: u.Name, Home: u.Home})
			}
			return out
		},
		Docroots:   func() map[string]string { return cms.CPanelDocroots("/var/cpanel/userdata") },
		MySQLUsers: audit.DefaultMySQLUsers,
		OwnNames:   ownNames,
		Realtime: func() (int, int64) {
			if a.Realtime == nil || !a.Settings.Get().Scanner.Realtime {
				return 0, 0
			}
			st := a.Realtime.Stats()
			return st.Unwatched, st.Overflows
		},
	}
}

// ownNames are this server's host name and addresses.
func ownNames() []string {
	var out []string
	if h, err := os.Hostname(); err == nil {
		out = append(out, h)
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, ad := range addrs {
			if n, ok := ad.(*net.IPNet); ok {
				out = append(out, n.IP.String())
			}
		}
	}
	return out
}

// runAudit runs one audit unless one is running, and saves the report.
func (a *Agent) runAudit(ctx context.Context) bool {
	if !auditRunning.CompareAndSwap(false, true) {
		return false
	}
	go func() {
		defer auditRunning.Store(false)
		r := a.auditor().Run(ctx)
		b, err := json.Marshal(r)
		if err == nil {
			tmp := auditPath() + ".tmp"
			if os.WriteFile(tmp, b, 0o600) == nil {
				_ = os.Rename(tmp, auditPath())
			}
		}
		a.Log.Info("server audit done", "items", len(r.Items), "high", r.Counts["high"], "seconds", int(r.Seconds))
	}()
	return true
}

func lastAudit() (audit.Report, bool) {
	var r audit.Report
	b, err := os.ReadFile(auditPath())
	if err != nil || json.Unmarshal(b, &r) != nil {
		return r, false
	}
	return r, true
}

// auditLoop runs the audit at night, once a day; the first one an hour
// after the agent starts when there is no report yet.
func (a *Agent) auditLoop(ctx context.Context) {
	first := time.NewTimer(time.Hour)
	defer first.Stop()
	tick := time.NewTicker(30 * time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-first.C:
			if _, ok := lastAudit(); !ok {
				a.runAudit(ctx)
			}
		case <-tick.C:
			r, ok := lastAudit()
			if a.nightNow() && (!ok || time.Since(time.Unix(r.At, 0)) > 20*time.Hour) {
				a.runAudit(ctx)
			}
		}
	}
}

func (a *Agent) auditHandlers(h map[string]client.Handler) {
	h["audit.get"] = func(context.Context, json.RawMessage) (any, error) {
		r, ok := lastAudit()
		out := map[string]any{"running": auditRunning.Load()}
		if ok {
			out["report"] = r
		}
		return out, nil
	}
	h["audit.run"] = func(context.Context, json.RawMessage) (any, error) {
		// Detached from the request: the walk outlives the portal's call.
		started := a.runAudit(context.Background())
		return map[string]any{"started": started, "running": true}, nil
	}
}

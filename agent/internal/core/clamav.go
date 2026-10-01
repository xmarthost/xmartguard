package core

import (
	"github.com/xmarthost/xmartguard/agent/internal/prio"

	"context"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/clamdb"
	"github.com/xmarthost/xmartguard/agent/internal/scanner"
	"github.com/xmarthost/xmartguard/agent/internal/store"
)

// clamState is shown in the portal (Settings » Virus Scanner).
type clamState struct {
	mu       sync.Mutex
	print    string
	loadedAt int64
	stats    clamdb.Stats
	errors   map[string]string
}

func clamSubDir() string { return filepath.Join(store.StateDir(), "clamav") }

// reloadClam downloads the subscription databases and rebuilds the
// signature engine when any database changed.
func (a *Agent) reloadClam(ctx context.Context, force bool) {
	sc := a.Settings.Get().Scanner
	if !sc.ClamAV {
		scanner.SetClamDB(nil)
		a.clam.mu.Lock()
		a.clam.print, a.clam.stats, a.clam.loadedAt = "", clamdb.Stats{}, 0
		a.clam.mu.Unlock()
		return
	}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Minute)
	defer cancel()
	errs := clamdb.Fetch(cctx, &http.Client{Timeout: 10 * time.Minute}, strings.Fields(sc.ClamAVURLs), clamSubDir())
	srcs := append(clamdb.FindLocal(clamdb.LocalDirs), clamdb.FindLocal([]string{clamSubDir()})...)
	for i := range srcs {
		if strings.HasPrefix(srcs[i].Path, clamSubDir()) {
			srcs[i].Unofficial = true
		}
	}
	fp := clamdb.Fingerprint(srcs)
	a.clam.mu.Lock()
	a.clam.errors = errs
	same := fp == a.clam.print && !force
	a.clam.mu.Unlock()
	if same {
		return
	}
	start := time.Now()
	e := clamdb.Load(srcs)
	if e.Empty() {
		scanner.SetClamDB(nil)
	} else {
		scanner.SetClamDB(e)
	}
	a.clam.mu.Lock()
	a.clam.print, a.clam.stats, a.clam.loadedAt = fp, e.Stats, time.Now().Unix()
	a.clam.mu.Unlock()
	a.Log.Info("ClamAV-format signatures loaded", "hashes", e.Stats.Hashes, "body", e.Stats.Body, "logical", e.Stats.Logical,
		"skipped", e.Stats.Skipped, "databases", len(e.Stats.Databases), "took", time.Since(start).Round(time.Millisecond))
}

func (a *Agent) clamStatus() map[string]any {
	a.clam.mu.Lock()
	defer a.clam.mu.Unlock()
	st := a.clam.stats
	if st.Databases == nil {
		st.Databases = []string{}
	}
	// Subscription files are named by hash; show them as "subscription".
	dbs := make([]string, 0, len(st.Databases))
	for _, d := range st.Databases {
		if strings.HasPrefix(d, clamSubDir()) {
			d = "subscription database (" + filepath.Ext(d) + ")"
		}
		dbs = append(dbs, d)
	}
	st.Databases = dbs
	errs := a.clam.errors
	if errs == nil {
		errs = map[string]string{}
	}
	return map[string]any{"enabled": a.Settings.Get().Scanner.ClamAV, "loaded_at": a.clam.loadedAt, "stats": st, "errors": errs}
}

// clamLoop loads the databases at start and checks for updates every
// six hours (freshclam updates the local ones several times a day).
func (a *Agent) clamLoop(ctx context.Context) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(30 * time.Second):
	}
	// Building the signature engine takes a CPU core for a while: the first
	// load happens at once, later updates at night (checked hourly).
	prio.LowThread()
	for {
		a.clam.mu.Lock()
		loaded := a.clam.loadedAt != 0
		a.clam.mu.Unlock()
		if !loaded || a.nightNow() {
			a.reloadClam(ctx, false)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Hour):
		}
	}
}

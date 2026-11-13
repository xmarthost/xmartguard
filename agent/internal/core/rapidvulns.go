package core

import (
	"context"
	"encoding/json"
	"strconv"
	"sync"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/client"
	"github.com/xmarthost/xmartguard/agent/internal/cms"
	"github.com/xmarthost/xmartguard/agent/internal/store"
)

// New plugin vulnerabilities from the portal (cms/rapid.go): fetched every
// hour and when the portal says new ones arrived, acted on at once.

const kvVulnCursor = "cms_vuln_cursor"

var rapidMu sync.Mutex

// syncVulns fetches the advisories after the stored cursor and acts on them.
func (a *Agent) syncVulns(ctx context.Context) error {
	if a.AI == nil || a.AI.Portal == nil || a.CMS == nil {
		return nil
	}
	cfg := a.Settings.Get().CMS
	if !cfg.Enabled || !cfg.Rapid {
		return nil
	}
	if !rapidMu.TryLock() {
		return nil // one at a time
	}
	defer rapidMu.Unlock()
	// Results recorded before the portal kept them, then any the portal
	// did not take yet (it was offline).
	if n := a.CMS.BackfillRapid(); n > 0 {
		a.Log.Info("earlier fast response actions recorded for the portal's report", "marks", n)
	}
	if n := a.CMS.CorrectRapid(); n > 0 {
		a.Log.Info("fast response results corrected from the sites' files", "results", n)
	}
	a.reportRapid(ctx, nil)
	since := int64(-1) // first time: only the cursor (the backlog is the nightly checks')
	if v := store.GetKV(a.DB, kvVulnCursor); v != "" {
		since, _ = strconv.ParseInt(v, 10, 64)
	}
	// The portal answers in pages (2,000): a resend of earlier weeks
	// (Master » Plugin Vulnerabilities) can be longer; every page is read.
	for page := 0; page < 50; page++ {
		var r struct {
			Items  []cms.Advisory `json:"items"`
			Cursor int64          `json:"cursor"`
		}
		if err := a.AI.Portal.Post(ctx, "/api/agent/cms/vulns", map[string]any{"since": since}, &r); err != nil {
			return err
		}
		if len(r.Items) > 0 {
			n := a.CMS.Rapid(ctx, r.Items)
			a.Log.Info("new plugin vulnerabilities checked against the sites", "advisories", len(r.Items), "sites_acted_on", n)
			seqs := make([]int64, 0, len(r.Items))
			for _, it := range r.Items {
				seqs = append(seqs, it.Seq)
			}
			a.reportRapid(ctx, map[string]any{"seqs": seqs, "sites": n})
		}
		if err := store.SetKV(a.DB, kvVulnCursor, strconv.FormatInt(r.Cursor, 10)); err != nil {
			return err
		}
		if len(r.Items) == 0 || r.Cursor <= since || ctx.Err() != nil {
			return nil
		}
		since = r.Cursor
	}
	return nil
}

// reportRapid sends the fast response's results (and, with receipt, which
// advisories this server received) to the portal, 500 at a time.
func (a *Agent) reportRapid(ctx context.Context, receipt map[string]any) {
	for i := 0; i < 200; i++ {
		rs, err := a.CMS.PendingRapid(500)
		if err != nil || (len(rs) == 0 && receipt == nil) {
			return
		}
		body := map[string]any{"results": rs}
		if receipt != nil {
			body["receipt"] = receipt
			receipt = nil
		}
		if rs == nil {
			body["results"] = []cms.RapidResult{}
		}
		if err := a.AI.Portal.Post(ctx, "/api/agent/cms/vulns/results", body, &struct{}{}); err != nil {
			a.Log.Debug("fast response results not sent", "err", err)
			return
		}
		a.CMS.MarkRapidReported(rs)
		if len(rs) < 500 {
			return
		}
	}
}

func (a *Agent) vulnLoop(ctx context.Context) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(7 * time.Minute):
	}
	for {
		if err := a.syncVulns(ctx); err != nil {
			a.Log.Debug("new plugin vulnerabilities not fetched", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Hour):
		}
	}
}

func (a *Agent) vulnHandlers(h map[string]client.Handler) {
	// The portal read new advisories: fetch them now (in the background,
	// the updates can take minutes).
	h["cms.vuln_sync"] = func(context.Context, json.RawMessage) (any, error) {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
			defer cancel()
			if err := a.syncVulns(ctx); err != nil {
				a.Log.Info("new plugin vulnerabilities not fetched", "err", err)
			}
		}()
		return map[string]any{"ok": true}, nil
	}
}

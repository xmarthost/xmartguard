package core

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/client"
	"github.com/xmarthost/xmartguard/agent/internal/store"
	"github.com/xmarthost/xmartguard/agent/internal/waf"
)

// Fleet intelligence: the file names of web shells this server's scanner
// found go to the portal, which learns the names seen across the fleet and
// sends every server the accepted names and its virtual patches.

const (
	kvWAFIntel      = "waf_intel"          // waf.Intel JSON
	kvIntelReported = "waf_intel_reported" // last finding id reported
	kvIntelCleanAt  = "waf_intel_clean_at" // last restored finding time reported
)

// nameReport is one web shell file name found here (clean: the finding was
// restored as a false positive).
type nameReport struct {
	Name      string `json:"name"`
	Tail      string `json:"tail"`
	Signature string `json:"signature"`
	Clean     bool   `json:"clean,omitempty"`
}

// wafIntel is the stored fleet intelligence (nil = none yet).
func (a *Agent) wafIntel() *waf.Intel {
	raw := store.GetKV(a.DB, kvWAFIntel)
	if raw == "" {
		return nil
	}
	var in waf.Intel
	if json.Unmarshal([]byte(raw), &in) != nil {
		return nil
	}
	return &in
}

// reportable turns a finding's path into a report: PHP files outside
// WordPress core folders whose name is specific enough to block.
func reportable(path string) (name, tail string, ok bool) {
	p := strings.ToLower(filepath.ToSlash(path))
	if strings.Contains(p, "/wp-admin/") || strings.Contains(p, "/wp-includes/") {
		return "", "", false
	}
	name = filepath.Base(p)
	if !waf.FleetNameOK(name) {
		return "", "", false
	}
	// The part under the web root only: no home folder or user name.
	tail = name
	for _, root := range []string{"/public_html/", "/www/", "/htdocs/", "/httpdocs/"} {
		if i := strings.LastIndex(p, root); i >= 0 {
			tail = p[i+len(root):]
			break
		}
	}
	if i := strings.Index(tail, "wp-content/"); i > 0 {
		tail = tail[i:]
	}
	if len(tail) > 200 {
		tail = tail[len(tail)-200:]
	}
	return name, tail, true
}

// collectNameReports lists web shells found (and false positives restored)
// since the last report, with the marks to store once they were sent.
func (a *Agent) collectNameReports() ([]nameReport, int64, int64) {
	lastID, _ := strconv.ParseInt(store.GetKV(a.DB, kvIntelReported), 10, 64)
	lastClean, _ := strconv.ParseInt(store.GetKV(a.DB, kvIntelCleanAt), 10, 64)
	var out []nameReport
	seen := map[string]bool{}
	add := func(path, sig string, clean bool) {
		if name, tail, ok := reportable(path); ok && !seen[name+strconv.FormatBool(clean)] {
			seen[name+strconv.FormatBool(clean)] = true
			if len(sig) > 120 {
				sig = sig[:120]
			}
			out = append(out, nameReport{Name: name, Tail: tail, Signature: sig, Clean: clean})
		}
	}
	maxID := lastID
	if rows, err := a.DB.Query(`SELECT id, path, signature FROM findings WHERE id > ? AND category = 'virus'
		AND status NOT IN ('restored', 'ignored') ORDER BY id LIMIT 1000`, lastID); err == nil {
		for rows.Next() {
			var id int64
			var path, sig string
			if rows.Scan(&id, &path, &sig) == nil {
				add(path, sig, false)
				maxID = id
			}
		}
		rows.Close()
	}
	maxClean := lastClean
	if rows, err := a.DB.Query(`SELECT path, signature, updated_at FROM findings WHERE status = 'restored' AND updated_at > ?
		ORDER BY updated_at LIMIT 1000`, lastClean); err == nil {
		for rows.Next() {
			var path, sig string
			var at int64
			if rows.Scan(&path, &sig, &at) == nil {
				add(path, sig, true)
				maxClean = at
			}
		}
		rows.Close()
	}
	return out, maxID, maxClean
}

// storeIntel keeps the portal's intelligence and reloads the WAF when it
// changed.
func (a *Agent) storeIntel(in *waf.Intel) error {
	in = in.Clean()
	if in == nil {
		return nil
	}
	b, _ := json.Marshal(in)
	if store.GetKV(a.DB, kvWAFIntel) == string(b) {
		return nil
	}
	if err := store.SetKV(a.DB, kvWAFIntel, string(b)); err != nil {
		return err
	}
	if !a.Settings.Get().WAF.Enabled {
		return nil
	}
	a.central.applyMu.Lock()
	defer a.central.applyMu.Unlock()
	return a.WAF.Apply()
}

// syncIntel sends new reports and fetches the fleet intelligence.
func (a *Agent) syncIntel(ctx context.Context) error {
	if a.AI == nil || a.AI.Portal == nil {
		return nil
	}
	reports, maxID, maxClean := a.collectNameReports()
	etag := ""
	if in := a.wafIntel(); in != nil {
		etag = in.ETag
	}
	var r struct {
		Unchanged bool       `json:"unchanged"`
		Intel     *waf.Intel `json:"intel"`
	}
	if err := a.AI.Portal.Post(ctx, "/api/agent/waf/intel", map[string]any{"etag": etag, "reports": reports}, &r); err != nil {
		return err
	}
	_ = store.SetKV(a.DB, kvIntelReported, strconv.FormatInt(maxID, 10))
	_ = store.SetKV(a.DB, kvIntelCleanAt, strconv.FormatInt(maxClean, 10))
	if r.Unchanged || r.Intel == nil {
		return nil
	}
	return a.storeIntel(r.Intel)
}

// intelLoop syncs every 30 minutes.
func (a *Agent) intelLoop(ctx context.Context) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(3 * time.Minute):
	}
	for {
		if err := a.syncIntel(ctx); err != nil {
			a.Log.Debug("WAF fleet intelligence not synced", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(30 * time.Minute):
		}
	}
}

// intelHandlers: the portal pushes changed intelligence (waf.intel) and
// asks for an immediate sync (waf.intel_sync).
func (a *Agent) intelHandlers(h map[string]client.Handler) {
	h["waf.intel"] = func(_ context.Context, p json.RawMessage) (any, error) {
		in, err := decode[waf.Intel](p)
		if err != nil {
			return nil, err
		}
		if err := a.storeIntel(&in); err != nil {
			return nil, err
		}
		c := a.wafIntel()
		return map[string]any{"ok": true, "names": len(c.Names), "patches": len(c.Patches)}, nil
	}
	h["waf.intel_sync"] = func(ctx context.Context, _ json.RawMessage) (any, error) {
		return map[string]any{"ok": true}, a.syncIntel(ctx)
	}
}

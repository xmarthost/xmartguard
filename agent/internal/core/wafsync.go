package core

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/store"
	"github.com/xmarthost/xmartguard/agent/internal/waf"
)

// WAF Rule Sets: the portal holds one ModSecurity configuration for all
// servers (XMart Guard rules, OWASP CRS, cPanel vendors, custom rules).
// The agent pulls it every 15 minutes and at once when the portal sends
// "waf.sync" after a change, applies it and reports how each rule set did.

var wafSyncMu sync.Mutex

// loadRuleSets restores the last configuration before the WAF starts, so a
// restart does not drop the portal's rule sets until the next sync.
func (a *Agent) loadRuleSets() {
	var rs waf.RuleSets
	if s := store.GetKV(a.DB, "waf_rulesets"); s != "" && json.Unmarshal([]byte(s), &rs) == nil {
		a.WAF.SetRuleSets(rs)
	}
}

// WAFSyncResult is what "waf.sync" returns and the portal stores.
type WAFSyncResult struct {
	Version  int64              `json:"version"`
	Status   waf.Status         `json:"status"`
	Vendors  []waf.VendorInfo   `json:"vendors,omitempty"`
	RuleSets []waf.RuleSetState `json:"rule_sets"`
	Error    string             `json:"error,omitempty"`
	At       int64              `json:"at"`
}

// syncWAF fetches the portal's rule sets and applies them. force re-applies
// even when the configuration did not change.
func (a *Agent) syncWAF(ctx context.Context, force bool) (WAFSyncResult, error) {
	wafSyncMu.Lock()
	defer wafSyncMu.Unlock()
	if a.AI.Portal == nil {
		return WAFSyncResult{}, errors.New("not linked to a portal")
	}
	var cur waf.RuleSets
	if s := store.GetKV(a.DB, "waf_rulesets"); s != "" {
		_ = json.Unmarshal([]byte(s), &cur)
	}
	haveCRS := ""
	if a.WAF.CRSInstalled(cur.CRS.Version) {
		haveCRS = cur.CRS.Version
	}
	var r struct {
		Unchanged bool          `json:"unchanged"`
		Config    *waf.RuleSets `json:"config"`
		CRS       *struct {
			Version string            `json:"version"`
			Files   map[string]string `json:"files"`
		} `json:"crs"`
	}
	if err := a.AI.Portal.Post(ctx, "/api/agent/waf/config", map[string]any{"version": cur.Version, "crs_version": haveCRS}, &r); err != nil {
		return WAFSyncResult{}, err
	}
	if r.Unchanged && !force {
		return a.wafResult(ctx, cur), nil
	}
	next := cur
	if r.Config != nil {
		next = *r.Config
	}
	if r.CRS != nil && len(r.CRS.Files) > 0 {
		if err := a.WAF.InstallCRS(r.CRS.Version, r.CRS.Files); err != nil {
			a.Log.Warn("OWASP CRS install failed", "err", err)
		}
	}
	// XMart Guard's own rules follow the portal switch when it is set.
	if next.XMartGuard != nil && a.Settings.Get().WAF.Enabled != next.XMartGuard.Enabled {
		patch, _ := json.Marshal(map[string]any{"waf": map[string]any{"enabled": next.XMartGuard.Enabled}})
		if _, err := a.Settings.Patch(patch); err != nil {
			a.Log.Warn("could not switch XMart Guard WAF rules", "err", err)
		}
	}
	a.WAF.SetRuleSets(next)
	b, _ := json.Marshal(next)
	_ = store.SetKV(a.DB, "waf_rulesets", string(b))
	applyErr := a.WAF.Apply()
	res := a.wafResult(ctx, next)
	if applyErr != nil {
		res.Error = applyErr.Error()
	}
	return res, nil
}

// wafResult applies the vendors and collects the state of every rule set.
func (a *Agent) wafResult(ctx context.Context, rs waf.RuleSets) WAFSyncResult {
	managed := map[string]string{}
	_ = json.Unmarshal([]byte(store.GetKV(a.DB, "waf_vendors_managed")), &managed)
	t := waf.Detect()
	vendorStates := waf.ApplyVendors(ctx, t, rs.Vendors, managed)
	b, _ := json.Marshal(managed)
	_ = store.SetKV(a.DB, "waf_vendors_managed", string(b))

	st := a.WAF.Status()
	res := WAFSyncResult{Version: rs.Version, Status: st, At: time.Now().Unix()}
	xg := waf.RuleSetState{ID: "xmartguard", Name: "XMart Guard rules", State: "off"}
	if a.Settings.Get().WAF.Enabled {
		xg.State, xg.Detail = "active", ""
		if !st.Available {
			xg.State, xg.Detail = "unsupported", st.WebServer
		} else if st.Error != "" {
			xg.State, xg.Detail = "error", st.Error
		} else if st.SelfTest != nil && !st.SelfTest.OK {
			xg.State, xg.Detail = "error", st.SelfTest.Detail
		} else if st.SelfTest != nil {
			xg.Detail = "self-test passed: a test attack was blocked"
		}
	}
	res.RuleSets = append([]waf.RuleSetState{xg}, a.WAF.RuleSetStates()...)
	res.RuleSets = append(res.RuleSets, vendorStates...)
	if t.Name == "cpanel" {
		if v, err := waf.CPanelVendors(ctx); err == nil {
			res.Vendors = v
		}
	}
	return res
}

// reportWAF sends the result to the portal (shown on WAF Rule Sets).
func (a *Agent) reportWAF(ctx context.Context, res WAFSyncResult) {
	if a.AI.Portal == nil {
		return
	}
	var ok map[string]any
	_ = a.AI.Portal.Post(ctx, "/api/agent/waf/status", res, &ok)
}

func (a *Agent) wafSyncLoop(ctx context.Context) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(40 * time.Second):
	}
	first := true
	for {
		if a.AI.Portal != nil {
			res, err := a.syncWAF(ctx, first)
			if err != nil {
				a.Log.Debug("WAF rule set sync failed", "err", err)
			} else {
				a.reportWAF(ctx, res)
				first = false
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(15 * time.Minute):
		}
	}
}

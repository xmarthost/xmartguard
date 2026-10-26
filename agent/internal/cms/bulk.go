package cms

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/prio"
)

// BulkRequest is an update of many WordPress sites at once (CMS Threat
// Alerts: the selected sites, one hosting account's, or all of them).
type BulkRequest struct {
	Paths   []string `json:"paths"`   // these sites (else Account's, else all)
	Account string   `json:"account"` // a hosting account's sites
	// Mode: "vulnerable" updates what has a known vulnerability (plugins,
	// themes, and core to its branch's security release); "outdated"
	// updates every plugin and theme with a newer release and core to its
	// branch's latest release.
	Mode string `json:"mode"`
}

// BulkStatus is the progress of the last bulk update.
type BulkStatus struct {
	Running  bool     `json:"running"`
	Mode     string   `json:"mode"`
	Sites    int      `json:"sites"`
	Done     int      `json:"done"`
	Updated  int      `json:"updated"`
	Failed   int      `json:"failed"`
	Current  string   `json:"current"`
	Started  int64    `json:"started"`
	Finished int64    `json:"finished"`
	Errors   []string `json:"errors,omitempty"` // the first few
}

// Bulk reports the progress of the last bulk update.
func (m *Manager) Bulk() BulkStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	b := m.bulk
	b.Errors = slices.Clone(b.Errors)
	return b
}

// BulkUpdate starts a bulk update in the background. Accounts in
// "never patched automatically" are left out unless their sites were
// selected one by one.
func (m *Manager) BulkUpdate(req BulkRequest) (int, error) {
	if req.Mode != "vulnerable" && req.Mode != "outdated" {
		return 0, fmt.Errorf("unknown mode %q", req.Mode)
	}
	f := SiteFilter{Type: WordPress, Limit: -1}
	if len(req.Paths) == 0 && req.Account != "" {
		f.User = req.Account
	}
	all, _, err := m.Sites(f)
	if err != nil {
		return 0, err
	}
	excluded := m.Settings.Get().CMS.ExcludeUsers
	var sites []Site
	for _, s := range all {
		switch {
		case len(req.Paths) > 0:
			if slices.Contains(req.Paths, s.Path) {
				sites = append(sites, s)
			}
		case !slices.Contains(excluded, s.User):
			sites = append(sites, s)
		}
	}
	if len(sites) == 0 {
		return 0, errors.New("no WordPress site to update")
	}
	m.mu.Lock()
	if m.bulk.Running {
		m.mu.Unlock()
		return 0, errors.New("a bulk update is already running")
	}
	if m.running {
		m.mu.Unlock()
		return 0, errors.New("a CMS scan is running: try again when it has finished")
	}
	m.running = true // no scan while sites are updated
	m.bulk = BulkStatus{Running: true, Mode: req.Mode, Sites: len(sites), Started: time.Now().Unix()}
	m.mu.Unlock()
	go func() {
		prio.LowThread()
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Hour)
		defer cancel()
		for _, s := range sites {
			m.mu.Lock()
			m.bulk.Current = s.Path
			m.mu.Unlock()
			n, errs := m.updateSite(ctx, s, req.Mode)
			m.mu.Lock()
			m.bulk.Done++
			m.bulk.Updated += n
			m.bulk.Failed += len(errs)
			for _, e := range errs {
				if len(m.bulk.Errors) < 20 {
					m.bulk.Errors = append(m.bulk.Errors, s.Path+": "+e)
				}
			}
			m.mu.Unlock()
			// The list shows the site as the updates left it.
			m.refresh(ctx, s)
			if ctx.Err() != nil {
				break
			}
		}
		m.mu.Lock()
		m.bulk.Running, m.bulk.Current, m.bulk.Finished = false, "", time.Now().Unix()
		m.running = false
		b := m.bulk
		m.mu.Unlock()
		m.Log.Info("CMS bulk update finished", "mode", req.Mode, "sites", b.Sites, "updated", b.Updated, "failed", b.Failed)
	}()
	return len(sites), nil
}

// updateSite runs one site's updates and returns how many wp-cli updates
// changed something, and the errors.
func (m *Manager) updateSite(ctx context.Context, s Site, mode string) (int, []string) {
	wp := m.WPCLI
	if m.RunWPCLI != nil {
		wp = m.RunWPCLI
	}
	var cmds [][]string
	if mode == "outdated" {
		if s.OutdatedPlugins > 0 {
			cmds = append(cmds, []string{"plugin", "update", "--all"})
		}
		if s.OutdatedThemes > 0 {
			cmds = append(cmds, []string{"theme", "update", "--all"})
		}
		if s.Latest != "" && s.Version != "" && CompareVersions(s.Version, s.Latest) < 0 {
			cmds = append(cmds, []string{"core", "update", "--minor"})
		}
	} else {
		for _, p := range s.Plugins {
			if len(p.Vulns) > 0 && p.Latest != "" && CompareVersions(p.Version, p.Latest) < 0 {
				args, _ := UpdateArgs("plugin", p)
				cmds = append(cmds, args)
			}
		}
		for _, t := range s.Themes {
			if len(t.Vulns) > 0 && t.Latest != "" && CompareVersions(t.Version, t.Latest) < 0 {
				args, _ := UpdateArgs("theme", t)
				cmds = append(cmds, args)
			}
		}
		if len(s.Core.Vulns) > 0 {
			args, _ := UpdateArgs("core", Component{Version: s.Version})
			cmds = append(cmds, args)
		}
	}
	n := 0
	var errs []string
	for _, args := range cmds {
		if ctx.Err() != nil {
			break
		}
		out, err := wp(ctx, s.Path, args...)
		switch {
		case err != nil:
			errs = append(errs, fmt.Sprintf("%v: %v", args, err))
			m.Log.Warn("CMS bulk update failed", "site", s.Path, "args", args, "err", err)
		case notUpdated(out):
		default:
			n++
			m.Log.Info("CMS bulk update", "site", s.Path, "args", args, "out", out)
		}
	}
	return n, errs
}

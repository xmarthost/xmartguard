package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/cms"
	"github.com/xmarthost/xmartguard/agent/internal/local"
	"github.com/xmarthost/xmartguard/agent/internal/scanner"
	"github.com/xmarthost/xmartguard/agent/internal/version"
	"github.com/xmarthost/xmartguard/agent/internal/waf"
)

// portalOnly commands are never exposed on the local socket.
var portalOnly = map[string]bool{"agent.update": true, "fleet.set": true, "mail.global": true, "ipdb.sync": true, "ipdb.apply": true, "waf.intel": true}

// LocalServer builds the Unix-socket API used by the WHM/cPanel plugins.
func (a *Agent) LocalServer() *local.Server {
	root := map[string]local.Handler{}
	for k, h := range a.Handlers() {
		if !portalOnly[k] {
			root[k] = h
		}
	}
	root["overview"] = func(context.Context, json.RawMessage) (any, error) {
		return map[string]any{
			"version":  version.Version,
			"portal":   a.Cfg.ServerURL,
			"summary":  a.SecuritySummary(),
			"firewall": a.Firewall.Status(),
			"ipdb":     a.Firewall.IPDBStatus(),
			"scanner":  a.Settings.Get().Scanner.Enabled,
			"realtime": a.Settings.Get().Scanner.Realtime,
		}, nil
	}
	return &local.Server{Root: root, User: a.userHandlers, Log: a.Log}
}

// account resolves the hosting account behind a panel user.
func account(u *user.User) (name, home, web string, ok bool) {
	for _, h := range scanner.Users() {
		if h.Name == u.Username {
			return h.Name, h.Home, h.WebRoot, true
		}
	}
	return "", "", "", false
}

// within reports whether p (after resolving symlinks) is home or below it.
func within(home, p string) (string, bool) {
	p = filepath.Clean(p)
	if r, err := filepath.EvalSymlinks(p); err == nil {
		p = r
	}
	h := filepath.Clean(home)
	if r, err := filepath.EvalSymlinks(h); err == nil {
		h = r
	}
	return p, p == h || strings.HasPrefix(p, h+"/")
}

// userHandlers is what a cPanel account may do: scan and manage its own files.
func (a *Agent) userHandlers(u *user.User) map[string]local.Handler {
	name, home, web, ok := account(u)
	if !ok {
		return nil
	}
	if a.Scanner.UserWhitelisted(name) {
		return nil
	}
	owns := func(id int64) error {
		p, err := a.Scanner.FindingPath(id)
		if err != nil {
			return err
		}
		if _, ok := within(home, p); !ok {
			return errors.New("finding not found")
		}
		return nil
	}
	h := map[string]local.Handler{}
	h["overview"] = func(context.Context, json.RawMessage) (any, error) {
		counts := map[string]int{}
		for _, st := range []string{"detected", "quarantined", "disabled", "restored", "deleted"} {
			_, n, _ := a.Scanner.ListFindings(scanner.FindingFilter{Status: st, Under: home, Limit: 1})
			counts[st] = n
		}
		scans, _ := a.Scanner.ListScansUnder(home, 1)
		return map[string]any{
			"user": name, "home": home, "web_root": web, "version": version.Version,
			"findings": counts, "last_scan": scans, "scanner": a.Settings.Get().Scanner.Enabled,
			"realtime": a.Settings.Get().Scanner.Realtime,
		}, nil
	}
	h["dashboard"] = func(context.Context, json.RawMessage) (any, error) {
		return a.userDashboard(name, home), nil
	}
	// dirs lists the account's folders for the path scan (two levels).
	h["dirs"] = func(context.Context, json.RawMessage) (any, error) {
		return map[string]any{"dirs": userDirs(home, web)}, nil
	}
	h["cms.list"] = func(_ context.Context, p json.RawMessage) (any, error) {
		f, err := decode[cms.SiteFilter](p)
		if err != nil {
			return nil, err
		}
		f.User = name
		sites, total, err := a.CMS.Sites(f)
		return map[string]any{"sites": sites, "total": total}, err
	}
	h["waf.events"] = func(_ context.Context, p json.RawMessage) (any, error) {
		f, err := decode[waf.EventFilter](p)
		if err != nil {
			return nil, err
		}
		f.User = name
		ev, total, err := a.WAF.Events(f)
		return map[string]any{"events": ev, "total": total}, err
	}
	h["scan.start"] = func(_ context.Context, p json.RawMessage) (any, error) {
		in, err := decode[struct {
			Path string `json:"path"`
			// Kind: full (the whole account), quick (the website), path.
			Kind string `json:"kind"`
		}](p)
		if err != nil {
			return nil, err
		}
		kind := "path"
		switch in.Kind {
		case "full":
			in.Path = home
		case "quick":
			in.Path, kind = web, "quick"
			if web == "" {
				in.Path = home
			}
		}
		if !a.Settings.Get().Scanner.Enabled {
			return nil, errors.New("the virus scanner is disabled by the server administrator")
		}
		if !a.Settings.Get().Scanner.UserScans {
			return nil, errors.New("manual scans are disabled by the server administrator")
		}
		target := in.Path
		switch {
		case target == "" && web != "":
			target = web
		case target == "":
			target = home
		case !filepath.IsAbs(target):
			target = filepath.Join(home, target)
		}
		real, ok := within(home, target)
		if !ok {
			return nil, fmt.Errorf("you can only scan files inside %s", home)
		}
		if _, err := os.Stat(real); err != nil {
			return nil, fmt.Errorf("path not found: %s", target)
		}
		running, _ := a.Scanner.ListScansUnder(home, 20)
		for _, s := range running {
			if s.Status == "queued" || s.Status == "running" {
				return nil, errors.New("a scan of your account is already running")
			}
		}
		id, err := a.Scanner.Start(kind, real, "cpanel:"+name)
		return map[string]any{"id": id}, err
	}
	h["scan.list"] = func(context.Context, json.RawMessage) (any, error) {
		scans, err := a.Scanner.ListScansUnder(home, 50)
		return map[string]any{"scans": scans}, err
	}
	h["scan.stop"] = func(_ context.Context, p json.RawMessage) (any, error) {
		in, err := decode[struct{ ID int64 }](p)
		if err != nil {
			return nil, err
		}
		scans, _ := a.Scanner.ListScansUnder(home, 200)
		for _, s := range scans {
			if s.ID == in.ID {
				return map[string]any{"ok": true}, a.Scanner.Stop(in.ID)
			}
		}
		return nil, errors.New("scan not found")
	}
	h["findings.list"] = func(_ context.Context, p json.RawMessage) (any, error) {
		f, err := decode[scanner.FindingFilter](p)
		if err != nil {
			return nil, err
		}
		f.Under = home
		list, total, err := a.Scanner.ListFindings(f)
		return map[string]any{"findings": list, "total": total}, err
	}
	h["finding.action"] = func(_ context.Context, p json.RawMessage) (any, error) {
		in, err := decode[struct {
			IDs    []int64 `json:"ids"`
			Action string  `json:"action"`
		}](p)
		if err != nil {
			return nil, err
		}
		if len(in.IDs) == 0 || len(in.IDs) > 200 {
			return nil, errors.New("select between 1 and 200 files")
		}
		done, failed := 0, map[int64]string{}
		for _, id := range in.IDs {
			err := owns(id)
			if err == nil {
				switch in.Action {
				case "quarantine":
					err = a.Scanner.Quarantine(id)
				case "restore":
					err = a.restoreFinding(id)
				case "delete":
					err = a.Scanner.Delete(id)
				default:
					return nil, fmt.Errorf("unknown action %q", in.Action)
				}
			}
			if err != nil {
				failed[id] = err.Error()
			} else {
				done++
			}
		}
		return map[string]any{"done": done, "failed": failed}, nil
	}
	return h
}

// userDirs lists the folders a cPanel account can scan: the home folder's
// visible folders and those inside the website root.
func userDirs(home, web string) []string {
	out := []string{}
	add := func(dir string) {
		ents, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range ents {
			n := e.Name()
			if !e.IsDir() || strings.HasPrefix(n, ".") || n == "mail" || n == "etc" || n == "tmp" || n == "logs" || n == "ssl" {
				continue
			}
			out = append(out, filepath.Join(dir, n))
			if len(out) >= 400 {
				return
			}
		}
	}
	add(home)
	if web != "" {
		add(web)
	}
	sort.Strings(out)
	return out
}

// userDashboard is the cPanel account's home page: threats stopped and
// attacks blocked on its websites (30 days, with the previous 30 days for
// comparison), CMS issues and daily charts.
func (a *Agent) userDashboard(name, home string) map[string]any {
	now := time.Now().Unix()
	from, prevFrom := now-30*86400, now-60*86400
	count := func(q string, args ...any) int {
		var n int
		_ = a.DB.QueryRow(q, args...).Scan(&n)
		return n
	}
	under := []any{len(home) + 1, home + "/"}
	threats := count(`SELECT count(*) FROM findings WHERE substr(path, 1, ?) = ? AND created_at >= ?`, append(under, from)...)
	threatsPrev := count(`SELECT count(*) FROM findings WHERE substr(path, 1, ?) = ? AND created_at >= ? AND created_at < ?`, append(under, prevFrom, from)...)
	attacks := count(`SELECT count(*) FROM waf_events WHERE user = ? AND action LIKE 'Access denied%' AND at >= ?`, name, from)
	attacksPrev := count(`SELECT count(*) FROM waf_events WHERE user = ? AND action LIKE 'Access denied%' AND at >= ? AND at < ?`, name, prevFrom, from)
	daily := func(q string, args ...any) []map[string]any {
		out := []map[string]any{}
		rows, err := a.DB.Query(q, args...)
		if err != nil {
			return out
		}
		defer rows.Close()
		for rows.Next() {
			var d string
			var n int
			if rows.Scan(&d, &n) == nil {
				out = append(out, map[string]any{"day": d, "n": n})
			}
		}
		return out
	}
	cmsIssues := 0
	if sites, _, err := a.CMS.Sites(cms.SiteFilter{User: name, Limit: 500}); err == nil {
		for _, s := range sites {
			if s.CoreIssues > 0 || s.DBIssues > 0 || s.Vulnerable > 0 {
				cmsIssues++
			}
		}
	}
	return map[string]any{
		"user": name, "version": version.Version,
		"threats": threats, "threats_prev": threatsPrev,
		"attacks": attacks, "attacks_prev": attacksPrev,
		"cms_issues":    cmsIssues,
		"daily_threats": daily(`SELECT date(created_at, 'unixepoch') d, count(*) FROM findings WHERE substr(path, 1, ?) = ? AND created_at >= ? GROUP BY d ORDER BY d`, append(under, from)...),
		"daily_attacks": daily(`SELECT date(at, 'unixepoch') d, count(*) FROM waf_events WHERE user = ? AND action LIKE 'Access denied%' AND at >= ? GROUP BY d ORDER BY d`, name, from),
	}
}

package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/xmarthost/xmartguard/agent/internal/local"
	"github.com/xmarthost/xmartguard/agent/internal/scanner"
	"github.com/xmarthost/xmartguard/agent/internal/version"
)

// portalOnly commands are never exposed on the local socket.
var portalOnly = map[string]bool{"agent.update": true, "ipdb.sync": true, "ipdb.apply": true}

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
	h["scan.start"] = func(_ context.Context, p json.RawMessage) (any, error) {
		in, err := decode[struct {
			Path string `json:"path"`
		}](p)
		if err != nil {
			return nil, err
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
		id, err := a.Scanner.Start("path", real, "cpanel:"+name)
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
					err = a.Scanner.Restore(id)
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

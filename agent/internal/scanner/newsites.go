package scanner

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/store"
)

// New websites are scanned as soon as they appear: a new cPanel account, an
// addon domain or subdomain, an account transferred from another server or
// restored from a backup (JetBackup, cPanel restore). Their document roots
// arrive with whatever the old server or the backup had, so each gets its
// own "new" scan at low speed, listed with the manual scans.

// userDataDomains lists every cPanel domain with its document root.
var userDataDomains = "/etc/userdatadomains"

// NewSiteDelay is how long a new document root is left alone before its
// scan (a transfer or restore is still writing it), NewSiteMaxWait the
// longest it waits for running restores, and NewSitePoll how often the
// domain list is checked.
var (
	NewSiteDelay   = 5 * time.Minute
	NewSiteMaxWait = 3 * time.Hour
	NewSitePoll    = time.Minute
)

const kvKnownDocroots = "scanner.known_docroots"

// docroots returns every website document root, with the account name.
func docroots() map[string]string {
	out := map[string]string{}
	if f, err := os.Open(userDataDomains); err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			// "example.com: user==owner==type==parent==/home/user/public_html==ip:port==…"
			_, rest, ok := strings.Cut(sc.Text(), ": ")
			if !ok {
				continue
			}
			fields := strings.Split(rest, "==")
			for _, fl := range fields[1:] {
				if strings.HasPrefix(fl, "/") {
					p := filepath.Clean(fl)
					if !systemPath(p) {
						out[p] = fields[0]
					}
					break
				}
			}
		}
		return out
	}
	for _, u := range Users() {
		if u.WebRoot != "" {
			out[filepath.Clean(u.WebRoot)] = u.Name
		}
	}
	return out
}

// restoreRunning reports a transfer or backup restore still at work.
func restoreRunning() bool {
	procs, _ := filepath.Glob("/proc/[0-9]*/cmdline")
	for _, p := range procs {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		cmd := strings.ToLower(strings.ReplaceAll(string(b), "\x00", " "))
		for _, w := range []string{"restorepkg", "transfer_session", "xferrestore", "pkgacct", "jetbackup5d restore", "jetbackup5 restore", "jetrestore"} {
			if strings.Contains(cmd, w) {
				return true
			}
		}
	}
	return false
}

// WatchNewSites scans new document roots until ctx ends.
func (s *Scanner) WatchNewSites(ctx context.Context) {
	known := map[string]bool{}
	first := true
	if v := store.GetKV(s.DB, kvKnownDocroots); v != "" {
		var list []string
		if json.Unmarshal([]byte(v), &list) == nil {
			for _, d := range list {
				known[d] = true
			}
			first = false
		}
	}
	pending := map[string]time.Time{} // docroot -> first seen
	var lastMod time.Time
	t := time.NewTicker(NewSitePoll)
	defer t.Stop()
	for {
		if st, err := os.Stat(userDataDomains); err != nil || !st.ModTime().Equal(lastMod) || len(pending) > 0 || first {
			if err == nil {
				lastMod = st.ModTime()
			}
			s.checkNewSites(known, pending, first)
			first = false
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (s *Scanner) checkNewSites(known map[string]bool, pending map[string]time.Time, first bool) {
	cur := docroots()
	if len(cur) == 0 {
		return
	}
	changed := false
	for d := range cur {
		if !known[d] {
			if first {
				// The websites already here when the agent first runs are
				// covered by the scheduled scans.
				known[d] = true
				changed = true
			} else if _, ok := pending[d]; !ok {
				pending[d] = time.Now()
			}
		}
	}
	for d := range known {
		if _, ok := cur[d]; !ok {
			delete(known, d) // removed: scanned again if it comes back
			changed = true
		}
	}
	cfg := s.Settings.Get().Scanner
	busy := false
	checkedBusy := false
	var ready []string
	for d, seen := range pending {
		if _, ok := cur[d]; !ok {
			delete(pending, d)
			continue
		}
		if time.Since(seen) < NewSiteDelay {
			continue
		}
		if !checkedBusy {
			busy, checkedBusy = restoreRunning(), true
		}
		if busy && time.Since(seen) < NewSiteMaxWait {
			continue
		}
		delete(pending, d)
		known[d] = true
		changed = true
		ready = append(ready, d)
	}
	// An addon domain inside a new account's public_html is scanned with it.
	sort.Strings(ready)
	var last string
	for _, d := range ready {
		if last != "" && strings.HasPrefix(d, last+"/") {
			continue
		}
		last = d
		if !cfg.Enabled {
			continue
		}
		if st, err := os.Stat(d); err != nil || !st.IsDir() {
			continue
		}
		if _, err := s.Start("new", d, "new website ("+cur[d]+")"); err != nil {
			s.Log.Warn("scan of new website failed to start", "path", d, "err", err)
		}
	}
	if changed {
		list := make([]string, 0, len(known))
		for d := range known {
			list = append(list, d)
		}
		sort.Strings(list)
		b, _ := json.Marshal(list)
		_ = store.SetKV(s.DB, kvKnownDocroots, string(b))
	}
}

// Package tor keeps the list of Tor exit node addresses, published by the
// Tor Project (check.torproject.org/torbulkexitlist), for the WAF's Tor
// rules. The list is cached on disk and refreshed a few times a day.
package tor

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// URL is the Tor Project's list of exit node addresses.
var URL = "https://check.torproject.org/torbulkexitlist"

// maxAddrs caps the list (it has about 1,500 addresses).
const maxAddrs = 20000

// List is the cached exit node list.
type List struct {
	Path   string
	Client *http.Client

	mu      sync.RWMutex
	addrs   []string
	updated int64
	err     string
}

type cache struct {
	Addrs   []string `json:"addrs"`
	Updated int64    `json:"updated"`
}

// New loads the cached list.
func New(path string) *List {
	l := &List{Path: path, Client: &http.Client{Timeout: 30 * time.Second}}
	if b, err := os.ReadFile(path); err == nil {
		var c cache
		if json.Unmarshal(b, &c) == nil {
			l.addrs, l.updated = clean(c.Addrs), c.Updated
		}
	}
	return l
}

// Addrs returns the exit node addresses.
func (l *List) Addrs() []string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return append([]string(nil), l.addrs...)
}

// Status reports the list size, last update and last error.
func (l *List) Status() map[string]any {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return map[string]any{"addresses": len(l.addrs), "updated": l.updated, "error": l.err, "source": URL}
}

// Due reports whether the list is older than age.
func (l *List) Due(age time.Duration) bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return time.Since(time.Unix(l.updated, 0)) > age
}

// Refresh downloads the list; a failed download keeps the old one. It
// reports whether the addresses changed.
func (l *List) Refresh(ctx context.Context) (bool, error) {
	addrs, err := l.fetch(ctx)
	l.mu.Lock()
	defer l.mu.Unlock()
	if err != nil {
		l.err = err.Error()
		return false, err
	}
	changed := strings.Join(addrs, ",") != strings.Join(l.addrs, ",")
	l.addrs, l.updated, l.err = addrs, time.Now().Unix(), ""
	if b, err := json.Marshal(cache{Addrs: addrs, Updated: l.updated}); err == nil {
		_ = os.MkdirAll(filepath.Dir(l.Path), 0o700)
		_ = os.WriteFile(l.Path, b, 0o600)
	}
	return changed, nil
}

func (l *List) fetch(ctx context.Context) ([]string, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, URL, nil)
	req.Header.Set("User-Agent", "xPGuard-Agent (Tor exit list)")
	resp, err := l.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", URL, resp.StatusCode)
	}
	var raw []string
	sc := bufio.NewScanner(io.LimitReader(resp.Body, 4<<20))
	for sc.Scan() {
		raw = append(raw, sc.Text())
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	out := clean(raw)
	if len(out) == 0 {
		return nil, fmt.Errorf("%s: no addresses in the list", URL)
	}
	return out, nil
}

// clean keeps valid, unique addresses (no private ones), sorted.
func clean(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, a := range in {
		a = strings.TrimSpace(a)
		ip := net.ParseIP(a)
		if ip == nil || ip.IsPrivate() || ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() {
			continue
		}
		a = ip.String()
		if !seen[a] && len(out) < maxAddrs {
			seen[a] = true
			out = append(out, a)
		}
	}
	sort.Strings(out)
	return out
}

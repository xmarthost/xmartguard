package waf

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// RemoteCheck downloads a remote rule feed the way ModSecurity's
// SecRemoteRules does (license key in the ModSec-key header) and counts the
// rules, so the portal shows whether the vendor accepted this server.
// Replaced in tests.
var RemoteCheck = checkRemote

var reRuleLine = regexp.MustCompile(`(?i)^\s*Sec(Rule|Action)\s`)

type remoteResult struct {
	rules int
	err   error
	at    time.Time
}

var (
	remoteMu    sync.Mutex
	remoteCache = map[string]remoteResult{}
)

func checkRemote(ctx context.Context, key, url string) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("ModSec-key", key)
	req.Header.Set("ModSec-status", "ModSecurity")
	req.Header.Set("User-Agent", "ModSecurity (XMart Guard feed check)")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("could not reach the feed: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		msg := fmt.Sprintf("the vendor refused the download (HTTP %d)", res.StatusCode)
		if res.StatusCode == 401 || res.StatusCode == 403 {
			msg += ": check the license key and that this server's IP is on the license"
		}
		return 0, fmt.Errorf("%s", msg)
	}
	n := 0
	sc := bufio.NewScanner(io.LimitReader(res.Body, 64<<20))
	sc.Buffer(make([]byte, 1<<20), 4<<20)
	for sc.Scan() {
		if reRuleLine.MatchString(sc.Text()) {
			n++
		}
	}
	if err := sc.Err(); err != nil {
		return n, fmt.Errorf("reading the feed: %v", err)
	}
	if n == 0 {
		return 0, fmt.Errorf("the feed answered but contains no rules: check the license key and that this server's IP is on the license")
	}
	return n, nil
}

// checkRemoteStates updates the state of each active remote feed with the
// outcome of a download check (cached for an hour per key and URL).
func (m *Manager) checkRemoteStates(states []RuleSetState) {
	m.mu.Lock()
	feeds := append([]RemoteRules(nil), m.ruleSets.Remote...)
	m.mu.Unlock()
	for i := range states {
		if states[i].State != "active" || !strings.HasPrefix(states[i].ID, "remote:") {
			continue
		}
		for _, f := range feeds {
			if "remote:"+f.ID != states[i].ID {
				continue
			}
			ck := f.Key + "\x00" + f.URL
			remoteMu.Lock()
			r, ok := remoteCache[ck]
			remoteMu.Unlock()
			if !ok || time.Since(r.at) > time.Hour {
				n, err := RemoteCheck(context.Background(), f.Key, f.URL)
				r = remoteResult{rules: n, err: err, at: time.Now()}
				remoteMu.Lock()
				remoteCache[ck] = r
				remoteMu.Unlock()
			}
			if r.err != nil {
				states[i].State, states[i].Detail = "error", r.err.Error()
			} else {
				states[i].Detail = fmt.Sprintf("%d rules downloaded by ModSecurity from %s%s", r.rules, f.URL, rblSuffix(states[i].Detail))
			}
		}
	}
}

func rblSuffix(detail string) string {
	if i := strings.Index(detail, "; POST blocklist "); i >= 0 {
		return detail[i:]
	}
	return ""
}

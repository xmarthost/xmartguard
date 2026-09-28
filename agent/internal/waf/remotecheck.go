package waf

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Remote feeds (SecRemoteRules) are downloaded by ModSecurity itself when
// the web server loads its configuration. Vendors such as Malware.Expert only
// answer genuine ModSecurity requests, so instead of downloading the feed
// again the agent reads what ModSecurity wrote to the web server's error log:
//
//	ModSecurity: Loaded 1234 rules from: 'https://…'.
//	ModSecurity: Problems loading external resources: Failed to download: "https://…" error: …
var (
	reRemoteLoaded  = regexp.MustCompile(`Loaded (\d+) rules from: '([^']+)'`)
	reRemoteProblem = regexp.MustCompile(`Problems loading external resources: (.*)`)
)

// remoteLogTail is how much of the end of each error log is read.
const remoteLogTail = 4 << 20

type remoteLog struct {
	rules int
	err   string
	found bool
}

// remoteFromLogs finds the newest ModSecurity message about url.
func remoteFromLogs(logs []string, url string) remoteLog {
	var best remoteLog
	for _, p := range uniqueFiles(logs) {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		if st, err := f.Stat(); err == nil && st.Size() > remoteLogTail {
			_, _ = f.Seek(-remoteLogTail, io.SeekEnd)
		}
		b, _ := io.ReadAll(io.LimitReader(f, remoteLogTail))
		f.Close()
		for _, line := range strings.Split(string(b), "\n") {
			if !strings.Contains(line, url) {
				continue
			}
			if m := reRemoteLoaded.FindStringSubmatch(line); m != nil && m[2] == url {
				n, _ := strconv.Atoi(m[1])
				best = remoteLog{rules: n, found: true}
				if n == 0 {
					best.err = "ModSecurity loaded 0 rules from the feed"
				}
			} else if m := reRemoteProblem.FindStringSubmatch(line); m != nil {
				best = remoteLog{err: strings.TrimSpace(m[1]), found: true}
			}
		}
	}
	return best
}

// checkRemoteStates reports, for each active remote feed, whether the web
// server loaded it (from its error log).
func (m *Manager) checkRemoteStates(states []RuleSetState, logs []string) {
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
			r := remoteFromLogs(logs, f.URL)
			hits := 0
			if !r.found {
				hits = feedHits(logs, f.URL)
			}
			switch {
			case hits > 0:
				// LiteSpeed does not log loading remote rules; the feed's own
				// blocks show it is running.
				states[i].Detail = fmt.Sprintf("working: %d requests blocked by its rules in the recent web server log%s", hits, rblSuffix(states[i].Detail))
			case !r.found:
				states[i].Detail = "configured; the web server has not logged loading it yet" + rblSuffix(states[i].Detail)
			case r.err != "":
				msg := r.err
				if strings.Contains(msg, "HTTP response code said error") {
					msg += " (the vendor refused the download: check the license key and that this server's IP is on the license)"
				}
				states[i].State, states[i].Detail = "error", strings.ReplaceAll(msg, f.Key, "<key>")
			default:
				states[i].Detail = fmt.Sprintf("%d rules loaded by ModSecurity from %s%s", r.rules, f.URL, rblSuffix(states[i].Detail))
			}
		}
	}
}

// feedHits counts recent blocks by a vendor's own rules (Malware.Expert tags
// them "MEWAF" and names itself in the message).
func feedHits(logs []string, url string) int {
	if !strings.Contains(url, "malware.expert/") {
		return 0
	}
	n := 0
	for _, p := range uniqueFiles(logs) {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		if st, err := f.Stat(); err == nil && st.Size() > remoteLogTail {
			_, _ = f.Seek(-remoteLogTail, io.SeekEnd)
		}
		b, _ := io.ReadAll(io.LimitReader(f, remoteLogTail))
		f.Close()
		for _, line := range strings.Split(string(b), "\n") {
			if strings.Contains(line, "ModSecurity") && (strings.Contains(line, `[tag "MEWAF"]`) || strings.Contains(line, "Malware.Expert")) {
				n++
			}
		}
	}
	return n
}

// uniqueFiles drops paths that are the same file (cPanel links
// /etc/apache2/logs to /usr/local/apache/logs).
func uniqueFiles(paths []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range paths {
		r, err := filepath.EvalSymlinks(p)
		if err != nil {
			continue
		}
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	return out
}

func rblSuffix(detail string) string {
	if i := strings.Index(detail, "; POST blocklist "); i >= 0 {
		return detail[i:]
	}
	return ""
}

package waf

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/logtail"
	"github.com/xmarthost/xmartguard/agent/internal/store"
)

// ModSecurity also writes every intercepted request to its audit log (the
// source of WHM's "ModSecurity Tools" hit list). Some setups log blocks only
// there, so the agent reads it too. Serial logs hold the entries themselves;
// concurrent logs hold one index line per entry that names the entry file.

// auditLogs lists audit logs the web server writes.
func auditLogs() []string {
	var out []string
	for _, p := range []string{
		"/etc/apache2/logs/modsec_audit.log", "/usr/local/apache/logs/modsec_audit.log",
		"/var/log/httpd/modsec_audit.log", "/var/log/apache2/modsec_audit.log",
		"/usr/local/lsws/logs/auditmodsec.log", "/var/log/modsec_audit.log",
	} {
		if real, err := filepath.EvalSymlinks(p); err == nil {
			dup := false
			for _, o := range out {
				if o == real {
					dup = true
				}
			}
			if !dup {
				out = append(out, real)
			}
		}
	}
	return out
}

var reStorageDir = regexp.MustCompile(`(?mi)^\s*SecAuditLogStorageDir\s+"?([^"\s]+)"?`)

// auditStorageDir is where concurrent audit entries are kept.
func auditStorageDir() string {
	for _, g := range []string{"/etc/apache2/conf.d/modsec2.conf", "/etc/apache2/conf.d/modsec/*.conf", "/etc/httpd/conf.d/mod_security.conf", "/etc/modsecurity/*.conf"} {
		files, _ := filepath.Glob(g)
		for _, f := range files {
			b, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			if m := reStorageDir.FindStringSubmatch(string(b)); m != nil {
				d := m[1]
				if !filepath.IsAbs(d) {
					d = filepath.Join("/etc/apache2", d)
				}
				return d
			}
		}
	}
	for _, d := range []string{"/usr/local/apache/logs/modsec_audit", "/etc/apache2/logs/modsec_audit", "/var/log/httpd/modsec_audit"} {
		if exists(d) {
			return d
		}
	}
	return ""
}

var (
	reAuditBoundary = regexp.MustCompile(`^--([0-9a-zA-Z]+)-([A-Z])--$`)
	// A: [27/Sep/2026:00:30:11.123456 +0500] UNIQUEID 104.199.194.126 51234 10.0.0.1 443
	reAuditA       = regexp.MustCompile(`^\[[^\]]+\]\s+(\S+)\s+(\S+)\s+\d+\s+\S+\s+\d+`)
	reAuditRequest = regexp.MustCompile(`^([A-Z]+)\s+(\S+)\s+HTTP/`)
	reUniqueID     = regexp.MustCompile(`\[unique_id "([^"]+)"\]`)
	// Concurrent index line: ... "GET /uri HTTP/1.1" 406 ... UNIQUEID "-" /2026.../entry-file 0 1234 md5:...
	reIndexPath = regexp.MustCompile(`\s(/\d{8}/\d{8}-\d{4}/\S+)\s`)
)

// auditEntry collects the parts of one audit log entry.
type auditEntry struct {
	uid, ip, method, uri, host string
	msgs                       []string
	intercepted                bool
}

func (a *auditEntry) event() (Event, bool) {
	if a.ip == "" {
		return Event{}, false
	}
	// Prefer the message that denied the request.
	var line string
	for _, m := range a.msgs {
		if strings.Contains(m, "Access denied") {
			line = m
			break
		}
	}
	if line == "" {
		if !a.intercepted || len(a.msgs) == 0 {
			return Event{}, false // warnings only: the request went through
		}
		line = a.msgs[len(a.msgs)-1]
	}
	e := Event{At: store.Now(), IP: a.ip, Method: a.method, URI: a.uri, Host: strings.TrimPrefix(a.host, "www.")}
	for _, f := range reField.FindAllStringSubmatch(line, -1) {
		val := strings.ReplaceAll(f[2], `\"`, `"`)
		switch f[1] {
		case "msg":
			e.Msg = val
		case "id":
			e.RuleID, _ = strconv.Atoi(val)
		case "hostname":
			if e.Host == "" {
				e.Host = val
			}
		case "uri":
			if e.URI == "" {
				e.URI = val
			}
		}
	}
	if d := reDenied.FindStringSubmatch(line); d != nil && d[1] != "" {
		e.Action = "Access denied with code " + d[1]
	} else {
		e.Action = "Access denied"
	}
	// OWASP CRS blocks with a score rule; name the attack that scored.
	if isScoreRule(e.RuleID) {
		for _, m := range a.msgs {
			if strings.Contains(m, "Access denied") {
				continue
			}
			if f := reMsg.FindStringSubmatch(m); f != nil {
				e.Msg = scoreMsg(f[1], e.Msg)
				break
			}
		}
	}
	e.Category = classify(e.RuleID, e.Msg)
	return e, true
}

var reMsg = regexp.MustCompile(`\[msg "((?:[^"\\]|\\.)*)"\]`)

// isScoreRule: CRS anomaly-score blocking rules (inbound, outbound).
func isScoreRule(id int) bool { return id == 949110 || id == 959100 || id == 980130 }

func scoreMsg(attack, score string) string {
	if attack == "" {
		return score
	}
	if i := strings.Index(score, "Total Score:"); i >= 0 {
		return attack + " (" + strings.TrimSuffix(strings.TrimSpace(score[i:]), ")") + ")"
	}
	return attack
}

// reasons remembers the first warning message of each request, to name
// the attack when OWASP CRS blocks it by score in a later log line.
type reasons struct {
	mu   sync.Mutex
	msg  map[string]string
	ring []string
	pos  int
}

func newReasons(n int) *reasons { return &reasons{msg: map[string]string{}, ring: make([]string, n)} }

func (r *reasons) apply(e Event) Event {
	if e.UID == "" {
		return e
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if isScoreRule(e.RuleID) {
		if m, ok := r.msg[e.UID]; ok {
			e.Msg = scoreMsg(m, e.Msg)
			e.Category = classify(e.RuleID, e.Msg)
		}
		return e
	}
	if _, ok := r.msg[e.UID]; ok || e.Msg == "" || strings.HasPrefix(e.Action, "Access denied") {
		return e
	}
	if old := r.ring[r.pos]; old != "" {
		delete(r.msg, old)
	}
	r.ring[r.pos] = e.UID
	r.pos = (r.pos + 1) % len(r.ring)
	r.msg[e.UID] = e.Msg
	return e
}

// auditParser turns serial audit log lines into events.
type auditParser struct {
	cur     *auditEntry
	section string
	first   bool
}

// feed consumes one line; it returns an event when an entry ends.
func (p *auditParser) feed(line string) (Event, string, bool) {
	line = strings.TrimRight(line, "\r")
	if m := reAuditBoundary.FindStringSubmatch(line); m != nil {
		p.section, p.first = m[2], true
		switch m[2] {
		case "A":
			p.cur = &auditEntry{}
		case "Z":
			if p.cur != nil {
				e, ok := p.cur.event()
				uid := p.cur.uid
				p.cur = nil
				return e, uid, ok
			}
		}
		return Event{}, "", false
	}
	if p.cur == nil {
		return Event{}, "", false
	}
	switch p.section {
	case "A":
		if m := reAuditA.FindStringSubmatch(line); m != nil {
			p.cur.uid, p.cur.ip = m[1], m[2]
		}
	case "B":
		if p.first {
			if m := reAuditRequest.FindStringSubmatch(line); m != nil {
				p.cur.method, p.cur.uri = m[1], m[2]
			}
		} else if strings.HasPrefix(strings.ToLower(line), "host:") {
			p.cur.host = strings.TrimSpace(line[5:])
			if h, _, ok := strings.Cut(p.cur.host, ":"); ok {
				p.cur.host = h
			}
		}
	case "H":
		switch {
		case strings.HasPrefix(line, "Message:"):
			p.cur.msgs = append(p.cur.msgs, line)
		case strings.HasPrefix(line, "Action: Intercepted"):
			p.cur.intercepted = true
		}
	}
	if strings.TrimSpace(line) != "" {
		p.first = false
	}
	return Event{}, "", false
}

// parseAuditFile reads one complete serial entry file (concurrent logs).
func parseAuditFile(path string) (Event, string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return Event{}, "", false
	}
	defer f.Close()
	var p auditParser
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		if e, uid, ok := p.feed(sc.Text()); ok {
			return e, uid, true
		}
	}
	return Event{}, "", false
}

// followAudit tails one audit log and sends events.
func followAudit(ctx context.Context, path string, out chan<- auditHit) {
	lines := make(chan string, 1024)
	go logtail.Follow(ctx, path, lines)
	var p auditParser
	storage := ""
	for {
		select {
		case <-ctx.Done():
			return
		case line := <-lines:
			if strings.HasPrefix(line, "--") || p.cur != nil {
				if e, uid, ok := p.feed(line); ok {
					out <- auditHit{e, uid}
				}
				continue
			}
			// Concurrent index line.
			m := reIndexPath.FindStringSubmatch(line + " ")
			if m == nil {
				continue
			}
			if storage == "" {
				storage = auditStorageDir()
			}
			if storage == "" {
				continue
			}
			file := filepath.Join(storage, filepath.Clean(m[1]))
			if !strings.HasPrefix(file, storage) {
				continue
			}
			// The entry file may be completed a moment after the index line.
			go func() {
				time.Sleep(time.Second)
				if e, uid, ok := parseAuditFile(file); ok {
					out <- auditHit{e, uid}
				}
			}()
		}
	}
}

type auditHit struct {
	e   Event
	uid string
}

// seenIDs remembers recent ModSecurity unique ids so a hit that appears in
// both the error log and the audit log is recorded once.
type seenIDs struct {
	mu   sync.Mutex
	set  map[string]bool
	ring []string
	pos  int
}

func newSeenIDs(n int) *seenIDs { return &seenIDs{set: map[string]bool{}, ring: make([]string, n)} }

// add reports whether id is new (an empty id always is).
func (s *seenIDs) add(id string) bool {
	if id == "" {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.set[id] {
		return false
	}
	if old := s.ring[s.pos]; old != "" {
		delete(s.set, old)
	}
	s.ring[s.pos] = id
	s.pos = (s.pos + 1) % len(s.ring)
	s.set[id] = true
	return true
}

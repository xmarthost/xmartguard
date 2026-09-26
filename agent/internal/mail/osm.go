// Package mail is the Outgoing Spam Monitor: it follows the Exim main log,
// counts outgoing messages per sender, flags spam-like subjects and can
// hold or suspend a cPanel account's outgoing mail.
package mail

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/xmarthost/xmartguard/agent/internal/logtail"
	"github.com/xmarthost/xmartguard/agent/internal/settings"
	"github.com/xmarthost/xmartguard/agent/internal/store"
)

// LogPath is Exim's main log (overridable in tests).
var LogPath = "/var/log/exim_mainlog"

// Message is one outgoing message parsed from an Exim "<=" line.
type Message struct {
	At      time.Time
	ID      string // Exim message id
	Sender  string // envelope sender
	Auth    string // authenticated user (A=...:user), "" for local submissions
	LocalU  string // local user (U=...) for scripts
	IP      string // client IP for SMTP submissions
	Subject string
	Rcpts   int
	CWD     string // working directory of a local script (from the preceding cwd= line)
}

var (
	reArrival = regexp.MustCompile(`^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)(?:\.\d+)? (?:\[\d+\] )?(\S+) <= (\S+) (.*)$`)
	reAuth    = regexp.MustCompile(`\bA=[a-z_]+:(\S+)`)
	reLocalU  = regexp.MustCompile(`\bU=(\S+)`)
	reHostIP  = regexp.MustCompile(`\bH=.*?\[([0-9a-fA-F.:]+)\](?::\d+)?`)
	reSubject = regexp.MustCompile(`\bT="((?:[^"\\]|\\.)*)"`)
	reProto   = regexp.MustCompile(`\bP=(\S+)`)
	reFor     = regexp.MustCompile(` for (.+)$`)
	reCWD     = regexp.MustCompile(`^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)(?:\.\d+)? (?:\[\d+\] )?cwd=(\S+) \d+ args:`)
)

// ParseArrival parses an Exim arrival line. It returns false for lines that
// are not outgoing submissions (incoming mail, bounces, other log lines).
func ParseArrival(line string) (Message, bool) {
	m := reArrival.FindStringSubmatch(line)
	if m == nil {
		return Message{}, false
	}
	rest := m[4]
	msg := Message{ID: m[2], Sender: strings.ToLower(m[3])}
	msg.At, _ = time.ParseInLocation("2006-01-02 15:04:05", m[1], time.Local)
	if msg.Sender == "<>" {
		return Message{}, false // bounce
	}
	if a := reAuth.FindStringSubmatch(rest); a != nil {
		msg.Auth = strings.ToLower(a[1])
	}
	proto := ""
	if p := reProto.FindStringSubmatch(rest); p != nil {
		proto = p[1]
	}
	if u := reLocalU.FindStringSubmatch(rest); u != nil && (proto == "local" || strings.HasPrefix(proto, "local")) {
		msg.LocalU = u[1]
	}
	if msg.Auth == "" && msg.LocalU == "" {
		return Message{}, false // incoming or relayed mail: not ours to count
	}
	if h := reHostIP.FindStringSubmatch(rest); h != nil {
		msg.IP = h[1]
	}
	if s := reSubject.FindStringSubmatch(rest); s != nil {
		msg.Subject = strings.ReplaceAll(s[1], `\"`, `"`)
	}
	// Recipients follow " for " at the end; ignore " for " inside the subject.
	if f := reFor.FindStringSubmatch(reSubject.ReplaceAllString(rest, "")); f != nil {
		msg.Rcpts = len(strings.Fields(f[1]))
	}
	return msg, true
}

// key is who we count: the authenticated login, else the local account.
func (m Message) key() string {
	if m.Auth != "" {
		return m.Auth
	}
	return m.LocalU + " (" + m.Sender + ")"
}

// Source describes how the message was submitted (shown in the portal).
func (m Message) Source() string {
	switch {
	case m.Auth != "":
		return "Authenticated User"
	case m.CWD != "":
		return "Script " + m.CWD
	default:
		return "Local user " + m.LocalU
	}
}

// Event is a threshold or content violation.
type Event struct {
	ID       int64  `json:"id"`
	At       int64  `json:"at"`
	MsgID    string `json:"msg_id"`
	Sender   string `json:"sender"`
	Source   string `json:"source"`
	Remarks  string `json:"remarks"`
	Interval string `json:"interval"` // e.g. "50/m", "300/h"
	Count    int    `json:"count"`
	Action   string `json:"action"`
	User     string `json:"user"` // cPanel account
}

// Monitor follows the Exim log.
type Monitor struct {
	DB       *sql.DB
	Settings *settings.Store
	Log      *slog.Logger
	// Owner maps a sender address or login to its cPanel account.
	Owner func(sender string) string
	// OnEvent is called for each new event (notifications).
	OnEvent func(Event)
	// Run whmapi1 (overridable in tests).
	WHMAPI func(args ...string) error

	mu      sync.Mutex
	counts  map[string][]time.Time
	flagged map[string]time.Time // key|interval -> last event (one event per window)
}

func (o *Monitor) init() {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.counts == nil {
		o.counts = map[string][]time.Time{}
		o.flagged = map[string]time.Time{}
	}
}

// Run follows the log until ctx ends.
func (o *Monitor) Run(ctx context.Context) {
	o.init()
	// Wait for the log to exist: Exim may be installed later.
	for logged := false; ; logged = true {
		if _, err := os.Stat(LogPath); err == nil {
			break
		}
		if !logged {
			o.Log.Info("exim log not found; outgoing spam monitor idle", "path", LogPath)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(10 * time.Minute):
		}
	}
	lines := make(chan string, 1024)
	go logtail.Follow(ctx, LogPath, lines)
	var lastCWD string
	var lastCWDAt time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case l := <-lines:
			if c := reCWD.FindStringSubmatch(l); c != nil {
				lastCWD, lastCWDAt = c[2], time.Now()
				continue
			}
			msg, ok := ParseArrival(l)
			if !ok {
				continue
			}
			if msg.LocalU != "" && time.Since(lastCWDAt) < 3*time.Second {
				msg.CWD = lastCWD
			}
			o.Observe(msg)
		}
	}
}

func (o *Monitor) whitelisted(cfg settings.OSM, m Message) bool {
	for _, s := range cfg.WhitelistSenders {
		if strings.EqualFold(s, m.Sender) || strings.EqualFold(s, m.Auth) {
			return true
		}
	}
	if ip := net.ParseIP(m.IP); ip != nil {
		for _, w := range cfg.WhitelistIPs {
			if _, n, err := net.ParseCIDR(w); err == nil && n.Contains(ip) {
				return true
			}
			if w == m.IP {
				return true
			}
		}
	}
	for _, p := range cfg.WhitelistPaths {
		if m.CWD != "" && (m.CWD == p || strings.HasPrefix(m.CWD, strings.TrimRight(p, "/")+"/")) {
			return true
		}
	}
	return false
}

// SubjectIssue explains why a subject looks like spam ("" if it doesn't).
func SubjectIssue(subject string, patterns []string) string {
	s := strings.TrimSpace(subject)
	letters, upper := 0, 0
	for _, r := range s {
		if unicode.IsLetter(r) {
			letters++
			if unicode.IsUpper(r) {
				upper++
			}
		}
	}
	if letters >= 12 && upper == letters {
		return "SubjectSpam-ALL CAPS SHOUTING : " + s
	}
	low := strings.ToLower(s)
	for _, p := range patterns {
		if p != "" && strings.Contains(low, strings.ToLower(p)) {
			return fmt.Sprintf("SubjectSpam-Pattern %q : %s", p, s)
		}
	}
	return ""
}

// Observe counts one message and raises events when thresholds are crossed.
func (o *Monitor) Observe(m Message) {
	o.init()
	cfg := o.Settings.Get().OSM
	if !cfg.Enabled || o.whitelisted(cfg, m) {
		return
	}
	now := m.At
	if now.IsZero() {
		now = time.Now()
	}
	k := m.key()
	o.mu.Lock()
	keep := o.counts[k][:0]
	for _, t := range o.counts[k] {
		if now.Sub(t) < time.Hour {
			keep = append(keep, t)
		}
	}
	keep = append(keep, now)
	o.counts[k] = keep
	perMin := 0
	for _, t := range keep {
		if now.Sub(t) < time.Minute {
			perMin++
		}
	}
	perHour := len(keep)
	var trigger []struct {
		interval string
		n        int
		window   time.Duration
	}
	if perMin >= cfg.PerMinute {
		trigger = append(trigger, struct {
			interval string
			n        int
			window   time.Duration
		}{fmt.Sprintf("%d/m", cfg.PerMinute), perMin, time.Minute})
	}
	if perHour >= cfg.PerHour {
		trigger = append(trigger, struct {
			interval string
			n        int
			window   time.Duration
		}{fmt.Sprintf("%d/h", cfg.PerHour), perHour, time.Hour})
	}
	var fire []Event
	for _, t := range trigger {
		fk := k + "|" + t.interval
		if last, ok := o.flagged[fk]; ok && now.Sub(last) < t.window {
			continue // one event per sender per window
		}
		o.flagged[fk] = now
		remark := ""
		if cfg.CheckSubjects {
			remark = SubjectIssue(m.Subject, cfg.SpamPatterns)
		}
		fire = append(fire, Event{MsgID: m.ID, Sender: firstNonEmpty(m.Auth, m.Sender), Source: m.Source(), Remarks: remark, Interval: t.interval, Count: t.n})
	}
	// A spam-like subject from a sender that is already busy (at least the
	// per-minute threshold within the hour, minimum 10) is reported even below
	// the limits.
	if len(fire) == 0 && cfg.CheckSubjects && perHour >= max(cfg.PerMinute, 10) {
		if remark := SubjectIssue(m.Subject, cfg.SpamPatterns); remark != "" {
			fk := k + "|subject"
			if last, ok := o.flagged[fk]; !ok || now.Sub(last) >= time.Hour {
				o.flagged[fk] = now
				fire = append(fire, Event{MsgID: m.ID, Sender: firstNonEmpty(m.Auth, m.Sender), Source: m.Source(), Remarks: remark,
					Interval: fmt.Sprintf("%d/h", perHour), Count: perHour})
			}
		}
	}
	o.mu.Unlock()
	for _, e := range fire {
		o.raise(cfg, e, m)
	}
}

func firstNonEmpty(a ...string) string {
	for _, s := range a {
		if s != "" {
			return s
		}
	}
	return ""
}

func (o *Monitor) raise(cfg settings.OSM, e Event, m Message) {
	e.At = store.Now()
	if o.Owner != nil {
		e.User = o.Owner(firstNonEmpty(m.Auth, m.Sender))
	}
	if e.User == "" && m.LocalU != "" {
		e.User = m.LocalU
	}
	e.Action = "notified"
	if cfg.Action != "notify" && e.User != "" && e.User != "root" {
		api := o.WHMAPI
		if api == nil {
			api = whmapi
		}
		call := "hold_outgoing_email"
		e.Action = "outgoing mail held"
		if cfg.Action == "suspend" {
			call, e.Action = "suspend_outgoing_email", "outgoing mail suspended"
		}
		if err := api(call, "user="+e.User); err != nil {
			e.Action = "notified (" + call + " failed: " + err.Error() + ")"
		}
	}
	res, err := o.DB.Exec(`INSERT INTO osm_events (at, msg_id, sender, source, remarks, interval, count, action, user) VALUES (?,?,?,?,?,?,?,?,?)`,
		e.At, e.MsgID, e.Sender, e.Source, e.Remarks, e.Interval, e.Count, e.Action, e.User)
	if err == nil {
		e.ID, _ = res.LastInsertId()
	}
	o.Log.Warn("outgoing spam threshold", "sender", e.Sender, "interval", e.Interval, "action", e.Action)
	if o.OnEvent != nil {
		o.OnEvent(e)
	}
}

func whmapi(args ...string) error {
	bin := "/usr/sbin/whmapi1"
	if _, err := os.Stat(bin); err != nil {
		return fmt.Errorf("whmapi1 not available (cPanel only)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	if strings.Contains(string(out), "result: 0") {
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return nil
}

// Release lifts a hold/suspension of a cPanel account's outgoing mail.
func (o *Monitor) Release(user string) error {
	if user == "" || strings.ContainsAny(user, " /;&|$`") {
		return fmt.Errorf("invalid user")
	}
	api := o.WHMAPI
	if api == nil {
		api = whmapi
	}
	e1 := api("release_outgoing_email", "user="+user)
	e2 := api("unsuspend_outgoing_email", "user="+user)
	if e1 != nil && e2 != nil {
		return e2
	}
	return nil
}

// EventFilter narrows Events.
type EventFilter struct {
	Query  string `json:"q"`
	Limit  int    `json:"limit"`
	Offset int    `json:"offset"`
}

// Events lists events, newest first.
func (o *Monitor) Events(f EventFilter) ([]Event, int, error) {
	where, args := "1=1", []any{}
	if f.Query != "" {
		where, args = "(sender LIKE ? OR msg_id LIKE ? OR user LIKE ? OR remarks LIKE ?)", []any{"%" + f.Query + "%", "%" + f.Query + "%", "%" + f.Query + "%", "%" + f.Query + "%"}
	}
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 25
	}
	var total int
	if err := o.DB.QueryRow(`SELECT count(*) FROM osm_events WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := o.DB.Query(`SELECT id, at, msg_id, sender, source, remarks, interval, count, action, user FROM osm_events WHERE `+where+
		` ORDER BY id DESC LIMIT ? OFFSET ?`, append(args, f.Limit, f.Offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ID, &e.At, &e.MsgID, &e.Sender, &e.Source, &e.Remarks, &e.Interval, &e.Count, &e.Action, &e.User); err != nil {
			return nil, 0, err
		}
		out = append(out, e)
	}
	return out, total, rows.Err()
}

// Delete removes events.
func (o *Monitor) Delete(ids []int64) (int, error) {
	n := 0
	for _, id := range ids {
		res, err := o.DB.Exec(`DELETE FROM osm_events WHERE id = ?`, id)
		if err != nil {
			return n, err
		}
		k, _ := res.RowsAffected()
		n += int(k)
	}
	return n, nil
}

// Transaction returns the Exim log lines of one message (for the detail view).
func Transaction(msgID string) ([]string, error) {
	if !regexp.MustCompile(`^[A-Za-z0-9-]{10,40}$`).MatchString(msgID) {
		return nil, fmt.Errorf("invalid message id")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, "grep", "-F", "--", msgID, LogPath).Output()
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) > 200 {
		lines = lines[:200]
	}
	if len(lines) == 1 && lines[0] == "" {
		return []string{}, nil
	}
	return lines, nil
}

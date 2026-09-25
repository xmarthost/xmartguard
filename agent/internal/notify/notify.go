// Package notify sends alert emails through the server's local MTA
// (sendmail/Exim), batching bursts into one message.
package notify

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/mail"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Mailer batches messages per recipient and flushes every Interval.
type Mailer struct {
	Hostname string
	Log      *slog.Logger
	Interval time.Duration

	mu      sync.Mutex
	pending map[string][]string // to -> lines
	subject map[string]string
	timer   *time.Timer
}

// Sendmail is the MTA binary (overridable in tests).
var Sendmail = "/usr/sbin/sendmail"

// Enqueue adds an alert line for recipient.
func (m *Mailer) Enqueue(to, subject, line string) {
	if _, err := mail.ParseAddress(to); err != nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pending == nil {
		m.pending, m.subject = map[string][]string{}, map[string]string{}
	}
	if len(m.pending[to]) < 500 {
		m.pending[to] = append(m.pending[to], line)
	}
	if m.subject[to] == "" {
		m.subject[to] = subject
	}
	if m.timer == nil {
		d := m.Interval
		if d == 0 {
			d = 2 * time.Minute
		}
		m.timer = time.AfterFunc(d, m.Flush)
	}
}

// Flush sends everything queued.
func (m *Mailer) Flush() {
	m.mu.Lock()
	pending, subjects := m.pending, m.subject
	m.pending, m.subject, m.timer = nil, nil, nil
	m.mu.Unlock()
	for to, lines := range pending {
		subj := subjects[to]
		if len(lines) > 1 {
			subj = fmt.Sprintf("%s (+%d more)", subj, len(lines)-1)
		}
		if err := Send(to, "[XMart Guard] "+m.Hostname+": "+subj, strings.Join(lines, "\n")); err != nil && m.Log != nil {
			m.Log.Warn("alert email failed", "to", to, "err", err)
		}
	}
}

// Send delivers one plain-text email via sendmail -t.
func Send(to, subject, body string) error {
	if _, err := os.Stat(Sendmail); err != nil {
		return fmt.Errorf("no local MTA (%s)", Sendmail)
	}
	host, _ := os.Hostname()
	var msg bytes.Buffer
	fmt.Fprintf(&msg, "To: %s\r\nFrom: XMart Guard <xmartguard@%s>\r\nSubject: %s\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s\r\n\r\n-- \r\nXMart Guard on %s\r\n",
		to, host, strings.ReplaceAll(subject, "\n", " "), body, host)
	cmd := exec.Command(Sendmail, "-t", "-i")
	cmd.Stdin = &msg
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Package notify sends alert emails through the server's local MTA
// (sendmail/Exim), batching bursts into one message.
package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Channels are the extra destinations every admin alert also goes to.
type Channels struct {
	Extra         string // additional email address
	From          string // From address ("" = xmartguard@hostname)
	SlackWebhook  string
	TelegramToken string
	TelegramChat  string
}

// Mailer batches messages per recipient and flushes every Interval.
type Mailer struct {
	Hostname string
	Log      *slog.Logger
	Interval time.Duration
	// Channels returns the current extra destinations (nil = email only).
	Channels func() Channels
	// Admin is the main admin address; chat channels and the extra
	// address receive what is sent to it.
	Admin func() string

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
	var ch Channels
	if m.Channels != nil {
		ch = m.Channels()
	}
	admin := ""
	if m.Admin != nil {
		admin = m.Admin()
	}
	for to, lines := range pending {
		subj := subjects[to]
		if len(lines) > 1 {
			subj = fmt.Sprintf("%s (+%d more)", subj, len(lines)-1)
		}
		full := "[XMart Guard] " + m.Hostname + ": " + subj
		body := strings.Join(lines, "\n")
		m.deliver(to, full, body, ch.From)
		if to == admin {
			if ch.Extra != "" && ch.Extra != to {
				m.deliver(ch.Extra, full, body, ch.From)
			}
			if err := Chat(ch, full, body); err != nil && m.Log != nil {
				m.Log.Warn("chat alert failed", "err", err)
			}
		}
	}
}

func (m *Mailer) deliver(to, subject, body, from string) {
	if err := SendFrom(to, subject, body, from); err != nil && m.Log != nil {
		m.Log.Warn("alert email failed", "to", to, "err", err)
	}
}

// Send delivers one plain-text email via sendmail -t.
func Send(to, subject, body string) error { return SendFrom(to, subject, body, "") }

// SlackURL / TelegramURL are the chat endpoints (tests override them).
var (
	TelegramURL = "https://api.telegram.org"
	chatClient  = &http.Client{Timeout: 20 * time.Second}
)

// Chat posts an alert to the configured Slack webhook and Telegram chat.
func Chat(ch Channels, subject, body string) error {
	text := subject + "\n" + body
	if len(text) > 3500 {
		text = text[:3500] + "\n…"
	}
	var errs []string
	if ch.SlackWebhook != "" {
		payload, _ := json.Marshal(map[string]string{"text": text})
		if res, err := chatClient.Post(ch.SlackWebhook, "application/json", bytes.NewReader(payload)); err != nil {
			errs = append(errs, "slack: request failed")
		} else {
			res.Body.Close()
			if res.StatusCode >= 300 {
				errs = append(errs, fmt.Sprintf("slack: HTTP %d", res.StatusCode))
			}
		}
	}
	if ch.TelegramToken != "" && ch.TelegramChat != "" {
		payload, _ := json.Marshal(map[string]any{"chat_id": ch.TelegramChat, "text": text, "disable_web_page_preview": true})
		u := TelegramURL + "/bot" + url.PathEscape(ch.TelegramToken) + "/sendMessage"
		if res, err := chatClient.Post(u, "application/json", bytes.NewReader(payload)); err != nil {
			errs = append(errs, "telegram: request failed")
		} else {
			res.Body.Close()
			if res.StatusCode >= 300 {
				errs = append(errs, fmt.Sprintf("telegram: HTTP %d", res.StatusCode))
			}
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

// SendFrom is Send with a custom From address.
func SendFrom(to, subject, body, from string) error {
	if _, err := os.Stat(Sendmail); err != nil {
		return fmt.Errorf("no local MTA (%s)", Sendmail)
	}
	host, _ := os.Hostname()
	var msg bytes.Buffer
	if a, err := mail.ParseAddress(from); err == nil && from != "" {
		from = a.Address
	} else {
		from = "xmartguard@" + host
	}
	fmt.Fprintf(&msg, "To: %s\r\nFrom: XMart Guard <%s>\r\nSubject: %s\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s\r\n\r\n-- \r\nXMart Guard on %s\r\n",
		to, from, strings.ReplaceAll(subject, "\n", " "), body, host)
	cmd := exec.Command(Sendmail, "-t", "-i")
	cmd.Stdin = &msg
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

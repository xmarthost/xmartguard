// Package notify sends alerts by email through the server's local MTA
// (sendmail/Exim) and to Slack and Telegram, batching bursts into one
// message.
package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
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
	From          string // From address ("" = xpguard@hostname)
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

// adminKey queues the administrator's alerts: they go to the admin email
// (when set), the extra address, Slack and Telegram, so chat alerts work
// without an email address.
const adminKey = "\x00admin"

// EnqueueAdmin adds an alert line for the administrator's channels.
func (m *Mailer) EnqueueAdmin(subject, line string) { m.enqueue(adminKey, subject, line) }

// Enqueue adds an alert line for recipient (the admin address is routed to
// all of the administrator's channels).
func (m *Mailer) Enqueue(to, subject, line string) {
	if _, err := mail.ParseAddress(to); err != nil {
		return
	}
	if m.Admin != nil && to == m.Admin() {
		to = adminKey
	}
	m.enqueue(to, subject, line)
}

func (m *Mailer) enqueue(to, subject, line string) {
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
		full := "[xPGuard] " + m.Hostname + ": " + subj
		body := strings.Join(lines, "\n")
		if to != adminKey {
			m.deliver(to, full, body, ch.From)
			continue
		}
		if _, err := mail.ParseAddress(admin); err == nil {
			m.deliver(admin, full, body, ch.From)
		}
		if ch.Extra != "" && ch.Extra != admin {
			m.deliver(ch.Extra, full, body, ch.From)
		}
		if err := Chat(ch, full, body); err != nil && m.Log != nil {
			m.Log.Warn("chat alert failed", "err", err)
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

// TelegramToken cleans a bot token as pasted (spaces, a "bot" prefix or the
// whole https://api.telegram.org/bot<token>/ URL).
func TelegramToken(t string) string {
	t = strings.TrimSpace(t)
	if i := strings.Index(t, "/bot"); i >= 0 {
		t = t[i+4:]
	}
	t = strings.TrimPrefix(t, "bot")
	t, _, _ = strings.Cut(t, "/")
	return strings.TrimSpace(t)
}

// telegramError reads Telegram's explanation ({"ok":false,"description":...}).
func telegramError(res *http.Response) string {
	var r struct {
		Description string `json:"description"`
	}
	_ = json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&r)
	msg := fmt.Sprintf("telegram: HTTP %d", res.StatusCode)
	if r.Description != "" {
		msg += ": " + r.Description
	}
	switch {
	case res.StatusCode == 401 || res.StatusCode == 404:
		msg += " (check the bot token from @BotFather)"
	case strings.Contains(r.Description, "chat not found"):
		msg += " (check the chat id, and send /start to the bot or add it to the group/channel first)"
	case strings.Contains(r.Description, "bot was blocked") || strings.Contains(r.Description, "not enough rights"):
		msg += " (unblock the bot, or make it an admin of the channel)"
	}
	return msg
}

// Chat posts an alert to the configured Slack webhook and Telegram chat.
func Chat(ch Channels, subject, body string) error {
	text := subject + "\n" + body
	if len(text) > 3500 {
		text = text[:3500] + "\n…"
	}
	ch.TelegramToken, ch.TelegramChat = TelegramToken(ch.TelegramToken), strings.TrimSpace(ch.TelegramChat)
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
			errs = append(errs, "telegram: cannot reach api.telegram.org from this server (outgoing HTTPS blocked?)")
		} else {
			if res.StatusCode >= 300 {
				errs = append(errs, telegramError(res))
			}
			res.Body.Close()
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
		from = "xpguard@" + host
	}
	fmt.Fprintf(&msg, "To: %s\r\nFrom: xPGuard <%s>\r\nSubject: %s\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s\r\n\r\n-- \r\nxPGuard on %s\r\n",
		to, from, strings.ReplaceAll(subject, "\n", " "), body, host)
	cmd := exec.Command(Sendmail, "-t", "-i")
	cmd.Stdin = &msg
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

package notify

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"
)

// MailConfig says how email leaves the server.
type MailConfig struct {
	// Method is "local" (the server's MTA through sendmail, e.g. Exim on
	// cPanel) or "smtp" (an external SMTP server).
	Method   string
	Host     string
	Port     int
	Security string // ssl (implicit TLS, 465) | starttls (587) | none (25)
	User     string
	Password string
	// From is the sender address ("" = xpguard@hostname).
	From string
	// PortalURL is linked from administrator emails.
	PortalURL string
}

func (mc MailConfig) smtp() bool { return mc.Method == "smtp" }

func (mc MailConfig) Via() string {
	if mc.smtp() {
		return "SMTP " + mc.Host
	}
	return "local mail server"
}

func (mc MailConfig) port() int {
	if mc.Port > 0 {
		return mc.Port
	}
	switch mc.Security {
	case "ssl":
		return 465
	case "none":
		return 25
	}
	return 587
}

// Sendmail is the MTA binary (overridable in tests).
var Sendmail = "/usr/sbin/sendmail"

//go:embed email-logo.png
var logoPNG []byte

const logoCID = "logo@xpguard"

// Send delivers one email (HTML with a plain-text alternative) to one
// recipient, through the local MTA or SMTP as configured.
func Send(mc MailConfig, to string, e Email) error {
	host, _ := os.Hostname()
	if e.Host == "" {
		e.Host = host
	}
	e.PortalURL = mc.PortalURL
	from := "xpguard@" + host
	if a, err := mail.ParseAddress(mc.From); err == nil && mc.From != "" {
		from = a.Address
	}
	if mc.smtp() && mc.User != "" && mc.From == "" && strings.Contains(mc.User, "@") {
		from = mc.User // most SMTP services only accept their own address
	}
	msg, err := buildMessage(from, to, e)
	if err != nil {
		return err
	}
	if mc.smtp() {
		return sendSMTP(mc, from, to, msg)
	}
	return sendLocal(msg)
}

func sendLocal(msg []byte) error {
	if _, err := os.Stat(Sendmail); err != nil {
		return fmt.Errorf("no local MTA (%s); choose SMTP in the notification settings", Sendmail)
	}
	cmd := exec.Command(Sendmail, "-t", "-i")
	cmd.Stdin = bytes.NewReader(msg)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// SMTPDialTimeout bounds connecting and the whole conversation.
var SMTPDialTimeout = 20 * time.Second

func sendSMTP(mc MailConfig, from, to string, msg []byte) error {
	if mc.Host == "" {
		return errors.New("SMTP server is not set")
	}
	addr := net.JoinHostPort(mc.Host, strconv.Itoa(mc.port()))
	tlsCfg := &tls.Config{ServerName: mc.Host, MinVersion: tls.VersionTLS12}
	d := &net.Dialer{Timeout: SMTPDialTimeout}
	var conn net.Conn
	var err error
	if mc.Security == "ssl" {
		conn, err = tls.DialWithDialer(d, "tcp", addr, tlsCfg)
	} else {
		conn, err = d.Dial("tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("SMTP %s: %v", addr, err)
	}
	_ = conn.SetDeadline(time.Now().Add(3 * SMTPDialTimeout))
	c, err := smtp.NewClient(conn, mc.Host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("SMTP %s: %v", addr, err)
	}
	defer c.Close()
	if h, _ := os.Hostname(); h != "" {
		if err := c.Hello(h); err != nil {
			return fmt.Errorf("SMTP HELO: %v", err)
		}
	}
	if mc.Security == "starttls" || mc.Security == "" {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return errors.New("the SMTP server does not offer STARTTLS; choose SSL/TLS (port 465) or None")
		}
		if err := c.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("SMTP STARTTLS: %v", err)
		}
	}
	if mc.User != "" {
		ok, mechs := c.Extension("AUTH")
		if !ok {
			return errors.New("the SMTP server does not accept a login on this connection")
		}
		var auth smtp.Auth
		if slices.Contains(strings.Fields(strings.ToUpper(mechs)), "PLAIN") {
			auth = smtp.PlainAuth("", mc.User, mc.Password, mc.Host)
		} else {
			auth = &loginAuth{mc.User, mc.Password, mc.Host}
		}
		if err := c.Auth(auth); err != nil {
			return fmt.Errorf("SMTP login failed: %v", err)
		}
	}
	if err := c.Mail(from); err != nil {
		return fmt.Errorf("SMTP sender %s refused: %v", from, err)
	}
	if err := c.Rcpt(to); err != nil {
		return fmt.Errorf("SMTP recipient %s refused: %v", to, err)
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("SMTP DATA: %v", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("SMTP DATA: %v", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("SMTP server refused the message: %v", err)
	}
	return c.Quit()
}

// loginAuth is AUTH LOGIN (Office 365 and some hosting providers offer no
// PLAIN). Like smtp.PlainAuth it is only used over TLS or to localhost.
type loginAuth struct{ user, pass, host string }

func (a *loginAuth) Start(s *smtp.ServerInfo) (string, []byte, error) {
	local := s.Name == "localhost" || s.Name == "127.0.0.1" || s.Name == "::1"
	if !s.TLS && !local {
		return "", nil, errors.New("unencrypted connection")
	}
	return "LOGIN", nil, nil
}

func (a *loginAuth) Next(from []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	switch strings.ToLower(strings.TrimSpace(string(from))) {
	case "username:":
		return []byte(a.user), nil
	case "password:":
		return []byte(a.pass), nil
	}
	return nil, fmt.Errorf("unexpected LOGIN prompt %q", from)
}

func boundary() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return "xpg-" + hex.EncodeToString(b)
}

func qp(s string) string {
	var b bytes.Buffer
	w := quotedprintable.NewWriter(&b)
	_, _ = w.Write([]byte(strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\n", "\r\n")))
	_ = w.Close()
	return b.String()
}

func b64lines(data []byte) string {
	enc := base64.StdEncoding.EncodeToString(data)
	var b strings.Builder
	for len(enc) > 76 {
		b.WriteString(enc[:76] + "\r\n")
		enc = enc[76:]
	}
	b.WriteString(enc + "\r\n")
	return b.String()
}

// buildMessage renders e as multipart/alternative: plain text, and HTML with
// the logo attached inline (multipart/related), which Gmail, Outlook and
// Apple Mail all show.
func buildMessage(from, to string, e Email) ([]byte, error) {
	html, err := e.HTML()
	if err != nil {
		return nil, err
	}
	alt, rel := boundary(), boundary()
	var b bytes.Buffer
	h := func(k, v string) { b.WriteString(k + ": " + v + "\r\n") }
	h("From", mime.QEncoding.Encode("utf-8", "xPGuard")+" <"+from+">")
	h("To", to)
	h("Subject", mime.QEncoding.Encode("utf-8", strings.ReplaceAll(e.Subject, "\n", " ")))
	h("Date", time.Now().Format(time.RFC1123Z))
	id := make([]byte, 10)
	_, _ = rand.Read(id)
	domain := from[strings.LastIndex(from, "@")+1:]
	h("Message-ID", "<"+hex.EncodeToString(id)+"@"+domain+">")
	h("MIME-Version", "1.0")
	h("X-Mailer", "xPGuard")
	h("Auto-Submitted", "auto-generated")
	h("Content-Type", `multipart/alternative; boundary="`+alt+`"`)
	b.WriteString("\r\n")

	b.WriteString("--" + alt + "\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n")
	b.WriteString(qp(e.Text()) + "\r\n")
	b.WriteString("--" + alt + "\r\nContent-Type: multipart/related; boundary=\"" + rel + "\"\r\n\r\n")
	b.WriteString("--" + rel + "\r\nContent-Type: text/html; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n")
	b.WriteString(qp(html) + "\r\n")
	b.WriteString("--" + rel + "\r\nContent-Type: image/png; name=\"xpguard.png\"\r\nContent-Transfer-Encoding: base64\r\n" +
		"Content-ID: <" + logoCID + ">\r\nContent-Disposition: inline; filename=\"xpguard.png\"\r\n\r\n")
	b.WriteString(b64lines(logoPNG))
	b.WriteString("--" + rel + "--\r\n")
	b.WriteString("--" + alt + "--\r\n")
	return b.Bytes(), nil
}

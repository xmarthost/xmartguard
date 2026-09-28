package notify

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/mail"
	"net/smtp"
	"strings"
	"testing"
)

// fakeSMTP accepts one message on 127.0.0.1 and returns what it received.
func fakeSMTP(t *testing.T, authMech string) (port int, got chan map[string]string) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	got = make(chan map[string]string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r, w := bufio.NewReader(c), c
		res := map[string]string{}
		say := func(s string) { io.WriteString(w, s+"\r\n") }
		say("220 fake ESMTP")
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			cmd := strings.TrimSpace(line)
			up := strings.ToUpper(cmd)
			switch {
			case strings.HasPrefix(up, "EHLO"):
				say("250-fake")
				say("250 AUTH " + authMech)
			case strings.HasPrefix(up, "AUTH PLAIN"):
				raw, _ := base64.StdEncoding.DecodeString(strings.Fields(cmd)[2])
				res["auth"] = string(bytes.ReplaceAll(raw, []byte{0}, []byte("|")))
				say("235 ok")
			case strings.HasPrefix(up, "AUTH LOGIN"):
				say("334 " + base64.StdEncoding.EncodeToString([]byte("Username:")))
				u, _ := r.ReadString('\n')
				say("334 " + base64.StdEncoding.EncodeToString([]byte("Password:")))
				p, _ := r.ReadString('\n')
				du, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(u))
				dp, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(p))
				res["auth"] = "|" + string(du) + "|" + string(dp)
				say("235 ok")
			case strings.HasPrefix(up, "MAIL FROM"):
				res["from"] = cmd
				say("250 ok")
			case strings.HasPrefix(up, "RCPT TO"):
				res["to"] = cmd
				say("250 ok")
			case up == "DATA":
				say("354 go")
				var b strings.Builder
				for {
					l, _ := r.ReadString('\n')
					if l == ".\r\n" {
						break
					}
					b.WriteString(strings.TrimPrefix(l, "."))
				}
				res["data"] = b.String()
				say("250 queued")
			case up == "QUIT":
				say("221 bye")
				got <- res
				return
			default:
				say("250 ok")
			}
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, got
}

func testEmail() Email {
	return Email{Subject: "[xPGuard] h1: malware detected (+1 more)", Host: "h1", ForAdmin: true, Alerts: []Alert{
		{Subject: "malware detected", Text: "[virus] php.webshell.b374k\n  file: /home/bob/public_html/x.php\n  owner: bob\n  status: quarantined\n"},
		{Subject: "IP blocked", Text: "203.0.113.9 blocked: wordpress brute force"},
	}}
}

func TestSMTPSendsBrandedMessage(t *testing.T) {
	for _, mech := range []string{"PLAIN LOGIN", "LOGIN"} {
		port, got := fakeSMTP(t, mech)
		mc := MailConfig{Method: "smtp", Host: "127.0.0.1", Port: port, Security: "none", User: "alerts@example.com", Password: "s3cret", PortalURL: "https://app.example.org"}
		if err := Send(mc, "admin@example.com", testEmail()); err != nil {
			t.Fatal(mech, err)
		}
		res := <-got
		if res["auth"] != "|alerts@example.com|s3cret" || !strings.Contains(res["from"], "<alerts@example.com>") || !strings.Contains(res["to"], "<admin@example.com>") {
			t.Fatalf("%s: %v", mech, res)
		}
		msg, err := mail.ReadMessage(strings.NewReader(res["data"]))
		if err != nil {
			t.Fatal(err)
		}
		subj, _ := new(mime.WordDecoder).DecodeHeader(msg.Header.Get("Subject"))
		if subj != "[xPGuard] h1: malware detected (+1 more)" {
			t.Fatalf("subject %q", subj)
		}
		_, params, _ := mime.ParseMediaType(msg.Header.Get("Content-Type"))
		mr := multipart.NewReader(msg.Body, params["boundary"])
		parts := map[string]string{}
		var walk func(r *multipart.Reader)
		walk = func(r *multipart.Reader) {
			for {
				p, err := r.NextPart()
				if err != nil {
					return
				}
				ct, pp, _ := mime.ParseMediaType(p.Header.Get("Content-Type"))
				if strings.HasPrefix(ct, "multipart/") {
					walk(multipart.NewReader(p, pp["boundary"]))
					continue
				}
				b, _ := io.ReadAll(p) // multipart decodes quoted-printable
				if ct == "image/png" {
					parts[ct] = p.Header.Get("Content-Id")
					b, _ = base64.StdEncoding.DecodeString(strings.ReplaceAll(string(b), "\r\n", ""))
					if !bytes.Equal(b, logoPNG) {
						t.Fatal("logo corrupted")
					}
					continue
				}
				parts[ct] = string(b)
			}
		}
		walk(mr)
		html, text := parts["text/html"], parts["text/plain"]
		for _, want := range []string{`src="cid:logo@xpguard"`, "Threat detected", "/home/bob/public_html/x.php", "https://app.example.org", "Malware detected and 1 more alert", "viewport"} {
			if !strings.Contains(html, want) {
				t.Fatalf("html missing %q", want)
			}
		}
		if !strings.Contains(text, "file: /home/bob/public_html/x.php") || parts["image/png"] != "<logo@xpguard>" {
			t.Fatalf("text/logo: %q %q", text, parts["image/png"])
		}
	}
}

// Passwords never go over an unencrypted connection to a remote server.
func TestLoginAuthNeedsTLS(t *testing.T) {
	a := &loginAuth{"u", "p", "mail.example.com"}
	if _, _, err := a.Start(&smtp.ServerInfo{Name: "mail.example.com", TLS: false}); err == nil {
		t.Fatal("LOGIN over plain text accepted")
	}
	if _, _, err := a.Start(&smtp.ServerInfo{Name: "mail.example.com", TLS: true}); err != nil {
		t.Fatal(err)
	}
}

func TestItemsParsing(t *testing.T) {
	e := Email{Alerts: []Alert{{Subject: "daily security report", Text: "Security report for the last 24 hours\n\n  Malware detections:      3\n  Addresses banned:        12\n\n2 infected file(s) still need action.\n"}}}
	it := e.items()[0]
	if it.Title != "Security report for the last 24 hours" || len(it.Rows) != 2 || it.Rows[1] != (Row{"Addresses banned", "12"}) || len(it.Notes) != 1 {
		t.Fatalf("%+v", it)
	}
	if _, _, l := e.tone(); l != "Security report" {
		t.Fatal(l)
	}
	if u := (Email{Alerts: []Alert{{Subject: "malware found in your account", Text: "x"}}}).Text(); !strings.Contains(u, "own a hosting account") {
		t.Fatal(u)
	}
}

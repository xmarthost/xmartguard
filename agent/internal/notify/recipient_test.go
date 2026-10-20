package notify

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A recipient with a line break can not add a hidden Bcc to the message
// that sendmail -t reads; only the parsed address goes into To (A5 F16).
func TestSendRecipientHeaderInjection(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "msg")
	fake := filepath.Join(dir, "sendmail")
	os.WriteFile(fake, []byte("#!/bin/sh\ncat > "+out+"\n"), 0o755)
	old := Sendmail
	Sendmail = fake
	defer func() { Sendmail = old }()
	mc := MailConfig{}
	if err := Send(mc, "admin@example.com\r\nBcc: other@example.net", Email{Subject: "test"}); err == nil {
		t.Fatal("injected recipient accepted")
	}
	if _, err := os.Stat(out); err == nil {
		t.Fatal("a message was sent")
	}
	if err := Send(mc, "Admin <admin@example.com>", Email{Subject: "test"}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(out)
	if !strings.Contains(string(b), "\r\nTo: admin@example.com\r\n") || strings.Contains(string(b), "\nBcc:") {
		t.Fatalf("headers:\n%s", b)
	}
}

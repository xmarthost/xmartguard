package settings

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// The notification addresses are single valid addresses: a line break
// would add headers (a hidden Bcc) to every alert (A5 F16).
func TestNotificationAddressesValidated(t *testing.T) {
	for _, bad := range []string{"a@example.com\r\nBcc: b@example.net", "a@example.com, b@example.net", "not an address"} {
		s := Defaults()
		s.Notifications.ExtraEmail = bad
		normalize(&s)
		if validate(s) == nil {
			t.Errorf("extra_email %q accepted", bad)
		}
		s = Defaults()
		s.Notifications.From = bad
		normalize(&s)
		if validate(s) == nil {
			t.Errorf("from %q accepted", bad)
		}
	}
	s := Defaults()
	s.Notifications.Email, s.Notifications.ExtraEmail, s.Notifications.From = "admin@example.com", "Ops <ops@example.com>", "alerts@example.com"
	normalize(&s)
	if err := validate(s); err != nil {
		t.Fatal(err)
	}
}

// A long Urdu brand name is cut at 60 letters, never inside one (A5 F20).
func TestBrandCutByLetters(t *testing.T) {
	s := Defaults()
	s.Notifications.Brand = strings.Repeat("ہوسٹ", 30) // 120 letters, 2 bytes each
	normalize(&s)
	if !utf8.ValidString(s.Notifications.Brand) || utf8.RuneCountInString(s.Notifications.Brand) != 60 {
		t.Fatalf("%q", s.Notifications.Brand)
	}
}

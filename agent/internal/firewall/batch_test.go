package firewall

import (
	"strings"
	"testing"
)

// Mass Operations: many addresses in one call, each with its own result.
func TestAddRemoveMany(t *testing.T) {
	m := newManager(t, ProviderNFTables)
	res, err := m.AddMany(KindAllow, []string{"198.51.100.10", "198.51.100.0/28", "not-an-ip", "2001:db8::5"}, "office")
	if err != nil {
		t.Fatal(err)
	}
	ok := 0
	for _, r := range res {
		if r.OK {
			ok++
		} else if r.Addr != "not-an-ip" || r.Error == "" {
			t.Errorf("unexpected failure %+v", r)
		}
	}
	if ok != 3 {
		t.Fatalf("added %d of 3: %+v", ok, res)
	}
	var n int
	m.DB.QueryRow(`SELECT count(*) FROM fw_rules WHERE kind = 'allow' AND comment = 'office'`).Scan(&n)
	if n != 3 {
		t.Fatalf("%d allow rules stored", n)
	}
	// Blocking: a protected address is refused on its own, the rest go in.
	res, _ = m.AddMany(KindDeny, []string{"203.0.113.9", "192.0.2.250", "203.0.113.10"}, "abuse")
	if !res[0].OK || res[1].OK || !res[2].OK {
		t.Fatalf("deny batch: %+v", res)
	}
	res, _ = m.RemoveMany(KindAllow, []string{"198.51.100.10", "192.0.2.77"})
	if !res[0].OK || res[1].OK {
		t.Fatalf("remove batch: %+v", res)
	}
	res, _ = m.RemoveMany("unblock", []string{"203.0.113.9", "203.0.113.10"})
	m.DB.QueryRow(`SELECT count(*) FROM fw_rules WHERE kind = 'deny'`).Scan(&n)
	if n != 0 || !res[0].OK {
		t.Fatalf("unblock batch left %d deny rules: %+v", n, res)
	}
	if _, err := m.AddMany(KindTempBan, []string{"203.0.113.1"}, ""); err == nil {
		t.Fatal("temp bans need a duration and are not batched")
	}
}

// Whitelisting an address makes it a plain, permanent whitelist entry:
// the temporary allow from a solved CAPTCHA goes, solving the CAPTCHA
// again adds none, and the other firewalls are told.
func TestWhitelistReplacesTempAllow(t *testing.T) {
	m := newManager(t, ProviderNFTables)
	calls := 0
	m.OnAllowChange = func() { calls++ }
	m.AutoBan("203.0.113.40", "5 failed Mail (Dovecot) logins in 10 min", "bruteforce")
	if err := m.CaptchaSolved("203.0.113.40", 0); err != nil {
		t.Fatal(err)
	}
	if r, _ := m.Check("203.0.113.40"); strings.Join(r.Found, ",") != "TEMP-ALLOW" {
		t.Fatalf("before whitelisting: %v", r.Found)
	}
	if _, err := m.Add(KindAllow, "203.0.113.40", "transfer", 0); err != nil {
		t.Fatal(err)
	}
	r, _ := m.Check("203.0.113.40")
	if strings.Join(r.Found, ",") != "WHITELIST" || r.Status != "allowed" {
		t.Fatalf("after whitelisting: %v %s", r.Found, r.Status)
	}
	if err := m.CaptchaSolved("203.0.113.40", 0); err != nil {
		t.Fatal(err)
	}
	if r, _ := m.Check("203.0.113.40"); strings.Join(r.Found, ",") != "WHITELIST" {
		t.Fatalf("CAPTCHA added a temporary allow again: %v", r.Found)
	}
	// Old data: a temporary allow next to a whitelist entry is cleaned up.
	m.DB.Exec(`INSERT INTO fw_rules (kind, cidr, comment, created_at, expires_at) VALUES ('tempallow','203.0.113.40','solved CAPTCHA',1,9999999999)`)
	m.expire()
	if r, _ := m.Check("203.0.113.40"); strings.Join(r.Found, ",") != "WHITELIST" {
		t.Fatalf("old temporary allow kept: %v", r.Found)
	}
	m.AutoBan("203.0.113.40", "again", "bruteforce")
	if r, _ := m.Check("203.0.113.40"); r.Status != "allowed" {
		t.Fatalf("whitelisted address banned: %s", r.Status)
	}
	if m.Remove(KindAllow, "203.0.113.40") != nil || calls != 2 {
		t.Fatalf("whitelist change callbacks: %d", calls)
	}
}

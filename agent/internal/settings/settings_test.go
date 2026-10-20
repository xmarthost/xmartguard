package settings

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestSEOCrawlersJoinBotList(t *testing.T) {
	s := Defaults()
	s.WAF.SEOBots, s.WAF.BotBlocker = true, true
	normalize(&s)
	if s.WAF.SEOBots || !slices.Contains(s.WAF.BotList, "petalbot") {
		t.Fatalf("not merged: %v %v", s.WAF.SEOBots, s.WAF.BotList)
	}
	// AhrefsBot is already listed: no case-insensitive duplicate.
	n := 0
	for _, b := range s.WAF.BotList {
		if b == "AhrefsBot" || b == "ahrefsbot" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("duplicates: %v", s.WAF.BotList)
	}
	// With the blocker off the old switch stays, so nothing stops being blocked.
	s = Defaults()
	s.WAF.SEOBots, s.WAF.BotBlocker = true, false
	normalize(&s)
	if !s.WAF.SEOBots {
		t.Fatal("switched off while the blocker is off")
	}
}

// Real search engines and too-short parts of a User-Agent leave saved lists.
func TestRetiredBotsLeaveSavedLists(t *testing.T) {
	s := Defaults()
	// Audit A3 F16: very short entries and parts of browser User-Agents
	// would block every visitor.
	s.WAF.BotList = []string{"AhrefsBot", "Yandex", "XX", "user-agent", "Baidu", "Sogou", "MyScraper", "a", "bot", "Mozilla", "Chrome", "safari", "AppleWebKit", "Gecko", "Windows", "Android", "iPhone", "like"}
	normalize(&s)
	if !slices.Equal(s.WAF.BotList, []string{"AhrefsBot", "MyScraper"}) {
		t.Fatalf("got %v", s.WAF.BotList)
	}
}

// cPGuard's default scanner lists reach new and existing servers once; an
// entry the administrator removes is not added again.
func TestScannerListDefaults(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XG_CONFIG_DIR", dir)
	st, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	sc := st.Get().Scanner
	if strings.Join(sc.WhitelistPaths, ",") != "mysql.sock" || strings.Join(sc.BlacklistNames, ",") != "1.sh,libworker.so" {
		t.Fatalf("fresh: %v %v", sc.WhitelistPaths, sc.BlacklistNames)
	}
	// An existing server with its own entries and no marker.
	os.WriteFile(filepath.Join(dir, "settings.json"), []byte(`{"scanner":{"whitelist_paths":["/home/u/cache"],"blacklist_names":["evil.php","1.sh"]}}`), 0o600)
	st, _ = Load()
	sc = st.Get().Scanner
	if strings.Join(sc.WhitelistPaths, ",") != "/home/u/cache,mysql.sock" || strings.Join(sc.BlacklistNames, ",") != "evil.php,1.sh,libworker.so" {
		t.Fatalf("existing: %v %v", sc.WhitelistPaths, sc.BlacklistNames)
	}
	// Removed by the administrator: stays removed.
	if _, err := st.Patch([]byte(`{"scanner":{"blacklist_names":["evil.php"]}}`)); err != nil {
		t.Fatal(err)
	}
	st, _ = Load()
	if strings.Join(st.Get().Scanner.BlacklistNames, ",") != "evil.php" {
		t.Fatalf("re-added: %v", st.Get().Scanner.BlacklistNames)
	}
}

// Old "allowed countries" become whitelisted countries.
func TestAllowedCountriesBecomeWhitelisted(t *testing.T) {
	s := Defaults()
	s.Firewall.AllowedCountries = []string{"pk", "AE"}
	s.Firewall.IgnoredCountries = []string{"PK"}
	normalize(&s)
	if len(s.Firewall.AllowedCountries) != 0 || strings.Join(s.Firewall.IgnoredCountries, ",") != "PK,AE" {
		t.Fatalf("%v %v", s.Firewall.AllowedCountries, s.Firewall.IgnoredCountries)
	}
}

// Audit A10 F6: whitelist ranges wider than the firewall accepts are
// refused, and IPv4-mapped addresses are stored as the IPv4 that matches.
func TestWhitelistAddresses(t *testing.T) {
	t.Setenv("XG_CONFIG_DIR", t.TempDir())
	st, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"0.0.0.0/0", "::/0", "10.0.0.0/7", "2001::/15", "999.1.1.1"} {
		for _, sec := range []string{"waf", "osm"} {
			if _, err := st.Patch([]byte(`{"` + sec + `":{"whitelist_ips":["` + bad + `"]}}`)); err == nil {
				t.Errorf("%s.whitelist_ips accepted %q", sec, bad)
			}
		}
	}
	s, err := st.Patch([]byte(`{"waf":{"whitelist_ips":["::ffff:192.0.2.7","192.0.2.9/24","::ffff:198.51.100.0/120","2001:db8::1"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(s.WAF.WhitelistIPs, ","); got != "192.0.2.7,192.0.2.0/24,198.51.100.0/24,2001:db8::1" {
		t.Fatalf("stored %s", got)
	}
}

// Audit A10 F1: Patch decoded over the live struct, writing into the slice
// arrays that Get() copies share.
func TestPatchDoesNotWriteIntoSharedLists(t *testing.T) {
	t.Setenv("XG_CONFIG_DIR", t.TempDir())
	st, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Patch([]byte(`{"waf":{"rule_exclusions":[{"rule":942100,"domain":"a.example","path":"/x"}]},"firewall":{"blocked_countries":["CN"]}}`)); err != nil {
		t.Fatal(err)
	}
	before := st.Get()
	// 1. A new list element without domain/path stays for all websites.
	got, err := st.Patch([]byte(`{"waf":{"rule_exclusions":[{"rule":942200}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if ex := got.WAF.RuleExclusions; len(ex) != 1 || ex[0] != (RuleExclusion{Rule: 942200}) {
		t.Fatalf("stale fields merged: %+v", ex)
	}
	// 2. The caller's earlier copy keeps its values.
	if _, err := st.Patch([]byte(`{"firewall":{"blocked_countries":["RU"]}}`)); err != nil {
		t.Fatal(err)
	}
	if strings.Join(before.Firewall.BlockedCountries, ",") != "CN" || before.WAF.RuleExclusions[0].Domain != "a.example" {
		t.Fatalf("snapshot changed: %v %+v", before.Firewall.BlockedCountries, before.WAF.RuleExclusions)
	}
	// 3. A rejected patch leaves nothing behind.
	wl := strings.Join(st.Get().WAF.WhitelistIPs, ",")
	if _, err := st.Patch([]byte(`{"waf":{"whitelist_ips":["not-an-ip"]}}`)); err == nil {
		t.Fatal("invalid address accepted")
	}
	if strings.Join(st.Get().WAF.WhitelistIPs, ",") != wl {
		t.Fatalf("rejected value live: %v", st.Get().WAF.WhitelistIPs)
	}
	if _, err := st.Patch([]byte(`{"scanner":{"realtime":false}}`)); err != nil {
		t.Fatalf("later save fails: %v", err)
	}
	// Sections still merge field by field; null leaves a section alone.
	s, err := st.Patch([]byte(`{"waf":null,"firewall":{"dos":true}}`))
	if err != nil || strings.Join(s.Firewall.BlockedCountries, ",") != "RU" || !s.Firewall.DoS || s.WAF.Level == "" {
		t.Fatalf("merge: %v %v %v", err, s.Firewall.BlockedCountries, s.Firewall.DoS)
	}
	if _, err := st.Patch([]byte(`[1]`)); err == nil {
		t.Fatal("non-object accepted")
	}
}

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

package settings

import (
	"slices"
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

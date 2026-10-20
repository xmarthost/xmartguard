package core

import (
	"context"
	"strings"
	"testing"

	"github.com/xmarthost/xmartguard/agent/internal/store"
)

// Every settings change is remembered and can be undone, by change or by time.
func TestSettingsHistoryRollback(t *testing.T) {
	a := newTestAgent(t, "")
	h := a.Handlers()
	ctx := context.Background()
	if a.Settings.Get().Scanner.KeepDays == 7 {
		t.Fatal("unexpected default")
	}
	if _, err := h["settings.set"](ctx, []byte(`{"scanner":{"keep_days":7}}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := h["settings.set"](ctx, []byte(`{"scanner":{"keep_days":9}}`)); err != nil {
		t.Fatal(err)
	}
	hist := a.settingsHistory(10)
	if len(hist) != 2 || hist[0].Summary != "scanner.keep_days" {
		t.Fatalf("history %+v", hist)
	}
	// Undo the first change: the settings from before it come back.
	orig := a.settingsHistory(10)[1]
	if _, err := h["settings.rollback"](ctx, []byte(`{"id":`+itoa(orig.ID)+`}`)); err != nil {
		t.Fatal(err)
	}
	if d := a.Settings.Get().Scanner.KeepDays; d == 7 || d == 9 {
		t.Fatalf("not rolled back: %d", d)
	}
	// The rollback itself can be undone.
	if hist := a.settingsHistory(10); len(hist) != 3 || hist[0].Summary == "" {
		t.Fatalf("history after rollback %+v", hist)
	}
	if _, err := h["settings.rollback"](ctx, []byte(`{"before":1}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := h["settings.rollback"](ctx, []byte(`{}`)); err == nil {
		t.Fatal("rollback without a change")
	}
}

// Audit A1 F19: a rejected change leaves no history row; "ignore" is in the
// history and does not add the same path twice.
func TestSettingsHistoryOnlyForSavedChanges(t *testing.T) {
	a := newTestAgent(t, "")
	h := a.Handlers()
	ctx := context.Background()
	if _, err := h["settings.set"](ctx, []byte(`{"waf":{"whitelist_ips":["not-an-ip"]}}`)); err == nil {
		t.Fatal("invalid address accepted")
	}
	if hist := a.settingsHistory(10); len(hist) != 0 {
		t.Fatalf("history for a rejected change: %+v", hist)
	}
	now := store.Now()
	for i := 0; i < 2; i++ {
		a.DB.Exec(`INSERT INTO findings (source, path, owner, category, signature, status, created_at, updated_at) VALUES ('manual','/home/u/public_html/x.php','u','suspicious','X','detected',?,?)`, now, now)
	}
	before := len(a.Settings.Get().Scanner.WhitelistPaths)
	if _, err := h["finding.action"](ctx, []byte(`{"ids":[1,2],"action":"ignore"}`)); err != nil {
		t.Fatal(err)
	}
	wl := a.Settings.Get().Scanner.WhitelistPaths
	if len(wl) != before+1 || wl[len(wl)-1] != "/home/u/public_html/x.php" {
		t.Fatalf("whitelist %v", wl)
	}
	if hist := a.settingsHistory(10); len(hist) != 1 || !strings.Contains(hist[0].Summary, "whitelist_paths") {
		t.Fatalf("history %+v", hist)
	}
}

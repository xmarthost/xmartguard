package core

import (
	"context"
	"testing"
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

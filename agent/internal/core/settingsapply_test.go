package core

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Saving settings answers at once; the firewall and WAF follow in the
// background, saves made meanwhile are applied together, and a failure
// shows among the server's problems.
func TestSettingsApplyInBackground(t *testing.T) {
	a := newTestAgent(t, `{"firewall":{"enabled":false}}`)
	a.syncSettings = false
	release := make(chan struct{})
	var runs atomic.Int32
	fail := ""
	a.applyFn = func(ctx context.Context, job settingsJob) (string, error) {
		runs.Add(1)
		<-release
		if fail != "" {
			return "", errors.New(fail)
		}
		return "", nil
	}
	set := func(patch string) map[string]any {
		t.Helper()
		start := time.Now()
		r, err := a.Handlers()["settings.set"](context.Background(), json.RawMessage(patch))
		if err != nil {
			t.Fatal(err)
		}
		if time.Since(start) > time.Second {
			t.Fatal("settings.set waited for the apply")
		}
		return r.(map[string]any)
	}
	r := set(`{"firewall":{"ignored_countries":["PK"]}}`)
	if st := r["apply"].(ApplyState); st.State != "applying" {
		t.Fatalf("state %+v", st)
	}
	// Saved at once, before the apply finished.
	if got := a.Settings.Get().Firewall.IgnoredCountries; len(got) != 1 || got[0] != "PK" {
		t.Fatalf("not saved: %v", got)
	}
	// Two more saves while the first applies: one more apply for both.
	set(`{"firewall":{"ignored_countries":["PK","AE"]}}`)
	set(`{"firewall":{"blocked_countries":["XX"]}}`)
	release <- struct{}{}
	release <- struct{}{}
	waitState(t, a, "applied")
	if n := runs.Load(); n != 2 {
		t.Fatalf("%d applies, want 2", n)
	}
	if a.settingsProblem() != "" {
		t.Fatal("problem after a good apply")
	}
	// A failed apply is shown with the server's problems.
	fail = "country list download failed"
	set(`{"firewall":{"ignored_countries":["PK"]}}`)
	release <- struct{}{}
	waitState(t, a, "failed")
	if p := a.settingsProblem(); !strings.Contains(p, "country list download failed") {
		t.Fatalf("problem %q", p)
	}
	found := false
	for _, p := range a.serviceProblems() {
		found = found || p["name"] == "Settings"
	}
	if !found {
		t.Fatal("failure not among the server's problems")
	}
	if st, _ := a.Handlers()["settings.apply_status"](context.Background(), nil); st.(ApplyState).State != "failed" {
		t.Fatalf("status %+v", st)
	}
}

// Audit A10 F1: a list edited to the same length still counts as a firewall
// change (the "before" snapshot no longer shares the list with the patch).
func TestSameLengthListChangeIsApplied(t *testing.T) {
	a := newTestAgent(t, `{"firewall":{"enabled":false,"blocked_countries":["CN"]}}`)
	a.syncSettings = false
	var job settingsJob
	a.applyFn = func(_ context.Context, j settingsJob) (string, error) {
		job = j
		return "", nil
	}
	if _, err := a.Handlers()["settings.set"](context.Background(), json.RawMessage(`{"firewall":{"blocked_countries":["RU"]}}`)); err != nil {
		t.Fatal(err)
	}
	waitState(t, a, "applied")
	if strings.Join(job.fw.BlockedCountries, ",") != "CN" || !fwChanged(job.fw, a.Settings.Get().Firewall) {
		t.Fatalf("before %v, now %v", job.fw.BlockedCountries, a.Settings.Get().Firewall.BlockedCountries)
	}
}

func waitState(t *testing.T, a *Agent, want string) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if a.settingsApply.status().State == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("state %+v, want %s", a.settingsApply.status(), want)
}

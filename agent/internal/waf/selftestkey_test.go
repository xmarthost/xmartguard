package waf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// 2026-11-05 (server audit): the self-test's probe rules relaxed the WAF
// for any request to /xpguard-crs-selftest/mech/<way> (allow, detection
// only, threshold 10000…): a website's front controller answers that
// path, so a visitor's attack passed every rule. Each probe now chains to
// the agent's key header.
func TestSelfTestProbesNeedTheKey(t *testing.T) {
	dir := t.TempDir()
	k := loadProbeKey(dir)
	if len(k) != 32 {
		t.Fatalf("key %q", k)
	}
	if fi, err := os.Stat(filepath.Join(dir, "selftest.key")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file: %v %v", fi, err)
	}
	if loadProbeKey(dir) != k {
		t.Fatal("key not kept")
	}
	out := mechProbeSetup() + multipartProbeSetup()
	guard := `SecRule REQUEST_HEADERS:X-XPGuard-Probe "@streq ` + k + `"`
	var ids []int
	for i := range mechProbes {
		ids = append(ids, IDMechProbe+i)
	}
	for bi := range scoreProbeBodies {
		for ti := range scoreProbeThresholds {
			ids = append(ids, IDScoreProbe+bi*10+ti)
		}
	}
	ids = append(ids, IDMultipartProbe+len(multipartProbes))
	for _, id := range ids {
		ch := chainOf(out, id)
		if len(ch) < 2 || !strings.HasPrefix(ch[1], guard) {
			t.Errorf("probe %d relaxes without the key: %q", id, ch)
		}
		// Nothing relaxes on the first rule (its setvar and ctl would run
		// without the rest of the chain).
		if strings.Contains(ch[0], "setvar") || strings.Contains(ch[0], "ctl:") {
			t.Errorf("probe %d acts before the key: %q", id, ch[0])
		}
	}
}

// The self-test's events are never counted or banned; before, an attack
// whose address only contained the name got the same treatment.
func TestSelfTestEventsOnlyFromThisServer(t *testing.T) {
	cases := []struct {
		ev   Event
		want bool
	}{
		{Event{IP: "127.0.0.1", URI: "/xpguard-crs-selftest/score/xss_20"}, true},
		{Event{IP: "::1", URI: "/xpguard-waf-selftest?t=1"}, true},
		{Event{IP: "127.0.0.1", URI: "/xpguard-crs-selftest?q=x"}, true},
		{Event{IP: "203.0.113.9", URI: "/?id=1'+union+select+1&x=/xpguard-waf-selftest"}, false},
		{Event{IP: "203.0.113.9", URI: "/wp-login.php/xpguard-crs-selftest/"}, false},
		{Event{IP: "203.0.113.9", URI: "/xpguard-crs-selftest/mech/allow?cmd=id"}, false},
		{Event{IP: "127.0.0.1", URI: "/shop/?q=/xpguard-crs-selftest/"}, false},
	}
	for _, c := range cases {
		if got := isSelfTest(c.ev); got != c.want {
			t.Errorf("%+v: %v, want %v", c.ev, got, c.want)
		}
	}
}

// business500 (2026-11-05): the self-test ran after every Apply, every 20
// to 80 seconds, though most applies loaded nothing. A passed result is
// used again until the web server loads new rules or an hour passes.
func TestSelfTestOnlyAfterALoad(t *testing.T) {
	m := &Manager{}
	ok := &SelfTest{OK: true, CRS: "blocked"}
	if m.reusableSelfTest(true) != nil {
		t.Fatal("reused before any test")
	}
	m.selfTest, m.testedAt = ok, time.Now()
	m.loadedAt = m.testedAt.Add(-time.Minute)
	if m.reusableSelfTest(true) != ok {
		t.Fatal("not reused without a load")
	}
	if m.reusableSelfTest(false) != nil {
		t.Fatal("reused though OWASP CRS was switched")
	}
	m.markLoaded()
	if m.reusableSelfTest(true) != nil {
		t.Fatal("reused after new rules were loaded")
	}
	m.loadedAt = m.testedAt.Add(-time.Minute)
	m.testedAt = time.Now().Add(-2 * selfTestMaxAge)
	if m.reusableSelfTest(true) != nil {
		t.Fatal("reused past its age")
	}
	m.testedAt = time.Now()
	m.selfTest = &SelfTest{OK: false}
	if m.reusableSelfTest(false) != nil {
		t.Fatal("a failed test reused")
	}
	m.selfTest = &SelfTest{OK: true, CRS: "OWASP CRS did not block"}
	if m.reusableSelfTest(true) != nil {
		t.Fatal("a CRS failure reused")
	}
}

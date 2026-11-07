package captcha

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Site mode without port 7743 (2026-11-06): the check is served on every
// website's own address (https://<website>/xpguard-verify/) from one
// folder of the agent through a global Alias; no port the visitor's
// network may refuse.
func TestSitePage(t *testing.T) {
	p := SitePageHTML("https://captcha.test/v")
	for _, want := range []string{sitePageMarker, `PAGE="https://captcha.test/v",ORIGIN="https://captcha.test"`, `"&fs=1&u="`,
		`e.origin===ORIGIN&&e.source===f.contentWindow`} {
		if !strings.Contains(p, want) {
			t.Errorf("page misses %q", want)
		}
	}
	if strings.Contains(p, "&fh=1") || strings.Contains(p, hostPageMarker) {
		t.Error("site page reads as the hostname page")
	}
	if SitePageHTML("http://captcha.test/v") != "" {
		t.Error("page for a portal address that is not https")
	}

	dir := filepath.Join(t.TempDir(), "share", "verify")
	saved := SitePageDir
	SitePageDir = dir
	defer func() { SitePageDir = saved }()

	conf := SiteAliasConf()
	for _, want := range []string{"Alias /xpguard-verify/ " + dir + "/\n", `<Directory "` + dir + `">`,
		"Options None", "AllowOverride None", "Require all granted", "Require all denied"} {
		if !strings.Contains(conf, want) {
			t.Errorf("alias misses %q:\n%s", want, conf)
		}
	}
	if strings.Contains(SiteAliasOff, "Alias") {
		t.Error("the off text still serves the page")
	}

	if err := InstallSitePage("https://captcha.test/v"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "index.html")
	if b, _ := os.ReadFile(path); string(b) != p {
		t.Fatal("page not written")
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o644 {
		t.Fatalf("mode %v", st.Mode())
	}
	if InstallSitePage("javascript:alert(1)") == nil {
		t.Fatal("installed a page for a bad portal address")
	}
	RemoveSitePage()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("page left behind")
	}
	os.MkdirAll(dir, 0o755)
	os.WriteFile(path, []byte("someone's page"), 0o644)
	RemoveSitePage()
	if _, err := os.Stat(path); err != nil {
		t.Fatal("a page that is not ours was removed")
	}
}

// The self-test asks the web server for the page on the server's hostname
// (the alias serves every name alike) and only a page for this portal
// passes; the hostname page at its own path does not count.
func TestCheckSitePage(t *testing.T) {
	site := SitePageHTML("https://captcha.test/v")
	mux := http.NewServeMux()
	mux.HandleFunc(SitePagePath, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(site)) })
	ts := httptest.NewTLSServer(mux)
	defer ts.Close()
	savedAddr, savedRoots := hostCheckAddr, hostCheckRoots
	defer func() { hostCheckAddr, hostCheckRoots = savedAddr, savedRoots }()
	hostCheckAddr = strings.TrimPrefix(ts.URL, "https://")
	hostCheckRoots = x509.NewCertPool()
	hostCheckRoots.AddCert(ts.Certificate())
	ctx := context.Background()
	if err := CheckSitePage(ctx, "example.com", "https://captcha.test/v", nil); err != nil {
		t.Fatal(err)
	}
	if err := CheckSitePage(ctx, "example.com", "https://other.test/v", nil); err == nil {
		t.Fatal("a page for another portal passed")
	}
	site = HostPageHTML("https://captcha.test/v")
	if err := CheckSitePage(ctx, "example.com", "https://captcha.test/v", nil); err == nil {
		t.Fatal("the hostname page passed as the site page")
	}
	ts.Config.Handler = http.NotFoundHandler()
	if err := CheckSitePage(ctx, "example.com", "https://captcha.test/v", nil); err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("missing page: %v", err)
	}
}

// The portal's browser test (server/test/altcha-browser.test.ts) runs this
// page; the copy there must be the agent's page (XG_UPDATE_FIXTURES=1
// writes it).
func TestSitePageFixture(t *testing.T) {
	path := filepath.Join("..", "..", "..", "server", "test", "fixtures", "sitepage.html")
	want := SitePageHTML("https://captcha.test/v")
	if os.Getenv("XG_UPDATE_FIXTURES") == "1" {
		os.MkdirAll(filepath.Dir(path), 0o755)
		if err := os.WriteFile(path, []byte(want), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Skip("portal tests not in this checkout")
	}
	if string(got) != want {
		t.Fatal("server/test/fixtures/sitepage.html differs from the page: run with XG_UPDATE_FIXTURES=1")
	}
}

// The site page sets the pass cookie the check hands it (only a pass value,
// only on this website, at most two days); the hostname page never does.
func TestSitePageSetsPassCookie(t *testing.T) {
	p := SitePageHTML("https://captcha.test/v")
	for _, want := range []string{`c.name==="xg_gate"`, `/^[0-9a-f]{32}$/.test(c.value)`, `c.max_age<=172800`, `document.cookie=`, `; path=/; max-age=`} {
		if !strings.Contains(p, want) {
			t.Errorf("site page misses %q", want)
		}
	}
	if strings.Contains(p, "domain=") {
		t.Error("cookie for other names")
	}
	if strings.Contains(HostPageHTML("https://captcha.test/v"), "document.cookie") {
		t.Error("hostname page sets a cookie")
	}
}

// One pass value for the address the website saw and the one the check
// was solved from; any other address sending it withdraws it.
func TestGiveAllAddresses(t *testing.T) {
	p := &SitePasses{Secret: []byte("0123456789abcdef0123456789abcdef")}
	now := time.Now()
	tok := p.GiveAll(now, "203.0.113.5", "198.51.100.7")
	if len(tok) != 32 {
		t.Fatalf("token %q", tok)
	}
	slot := -1
	for i, sl := range p.Slots(now) {
		if sl[0] == tok {
			slot = i
		}
	}
	if slot < 0 {
		t.Fatal("value not among the WAF's")
	}
	if p.Used("203.0.113.5", slot, now) || p.Used("198.51.100.7", slot, now) {
		t.Fatal("withdrawn from its own addresses")
	}
	if !p.Used("192.0.2.9", slot, now) {
		t.Fatal("another address kept it")
	}
	if p.GiveAll(now, "not-an-ip") != "" {
		t.Fatal("value for no address")
	}
}

// The pass values change with the week, not the day: the web server is not
// reloaded daily for them (owner's rule, 2026-11-07). A pass given on the
// last day of a week is still good after the week's reload; a value shared
// with another address changes every value of its slot.
func TestPassValuesForTheWeek(t *testing.T) {
	p := &SitePasses{Secret: []byte("0123456789abcdef0123456789abcdef")}
	// A Monday-to-Sunday-like UTC week: day 7*n is its first day.
	start := time.Unix(int64(20400*7)*86400+3600, 0)
	accepted := func(now time.Time) map[string]bool {
		m := map[string]bool{}
		for _, sl := range p.Slots(now) {
			for _, v := range sl {
				m[v] = true
			}
		}
		return m
	}
	first := accepted(start)
	for i := 1; i < 7; i++ {
		day := accepted(start.Add(time.Duration(i) * 24 * time.Hour))
		if len(day) != len(first) {
			t.Fatalf("day %d: %d values, week start %d", i, len(day), len(first))
		}
		for v := range day {
			if !first[v] {
				t.Fatalf("day %d: values changed within the week", i)
			}
		}
	}
	// Given on the last day of the week, before the new week's reload.
	last := start.Add(6*24*time.Hour + 20*time.Hour)
	tok := p.Give("203.0.113.5", last)
	if !first[tok] {
		t.Fatal("last day's value not in the week's")
	}
	if !accepted(start.Add(7 * 24 * time.Hour))[tok] {
		t.Fatal("last day's value dropped by the new week")
	}
	// Shared: the slot's values change for the whole window.
	slot := -1
	for i, sl := range p.Slots(last) {
		if sl[0] == tok {
			slot = i
		}
	}
	before := append([]string(nil), p.Slots(last)[slot]...)
	if !p.Used("198.51.100.7", slot, last) {
		t.Fatal("a value from another address kept")
	}
	after := p.Slots(last)[slot]
	for i := range before {
		if before[i] == after[i] {
			t.Fatalf("value %d of the slot not withdrawn", i)
		}
	}
}

// business500, 2026-11-08: a visitor behind a relay (87.81.0.0/16) sent its
// pass from a new address every few minutes; each report withdrew the slot
// again (two-minute quiet, while the WAF dropped the value only with the
// next background reload), breaking the other visitors' passes each time.
func TestWithdrawOncePerReload(t *testing.T) {
	p := &SitePasses{Secret: []byte("0123456789abcdef0123456789abcdef")}
	now := time.Now()
	tok := p.Give("87.81.229.30", now)
	slot := -1
	for i, sl := range p.Slots(now) {
		if sl[0] == tok {
			slot = i
		}
	}
	// The same visitor's network: its pass stays.
	if p.Used("87.81.231.117", slot, now) {
		t.Fatal("withdrawn for an address of the same network")
	}
	// Another network: withdrawn once; reports until the reload are the same misuse.
	if !p.Used("198.51.100.7", slot, now) {
		t.Fatal("not withdrawn")
	}
	for _, after := range []time.Duration{2 * time.Minute, 30 * time.Minute, 2 * time.Hour} {
		if p.Used("198.51.100.7", slot, now.Add(after)) {
			t.Fatalf("withdrawn again after %v", after)
		}
	}
}

package captcha

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// The portal's check on the website's own address: the page frames the
// portal's check (no redirect away), and the portal's ticket buys the pass
// cookie the WAF accepts, for that visitor only and once.
func TestSiteMode(t *testing.T) {
	s, _ := newServer(t)
	s.ServerID = "15d69a72-653a-47b6-90f6-fde737bce061"
	s.Passes = &SitePasses{Secret: []byte("0123456789abcdef0123456789abcdef")}
	var lifted []string
	s.Passed = func(ip string) { lifted = append(lifted, ip) }
	s.Settings.Patch([]byte(`{"waf":{"enabled":true},"captcha":{"central":true,"central_url":"https://captcha.xpguard.org/v","central_mode":"site","central_minutes":60}}`))
	if !Wanted(s.Settings.Get()) {
		t.Fatal("the CAPTCHA server does not run for the check on the websites' addresses")
	}
	req := func(method, target, body, from string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, target, strings.NewReader(body))
		r.Host = "shop.example.com:7743"
		r.Header.Set("Accept", "text/html")
		if body != "" {
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		r.RemoteAddr = from + ":4000"
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w
	}
	w := req("GET", "/.xpguard/gate?back=/wp-login.php?redirect_to=/wp-admin/&reauth=1", "", "203.0.113.5")
	body := w.Body.String()
	if w.Code != 200 || w.Header().Get("Location") != "" {
		t.Fatalf("gate page: %d %q", w.Code, w.Header().Get("Location"))
	}
	m := regexp.MustCompile(`<iframe src="([^"]+)"`).FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no frame:\n%s", body)
	}
	src := strings.ReplaceAll(m[1], "&amp;", "&")
	nonce := regexp.MustCompile(`&n=([a-f0-9]{32})&frame=1&u=`).FindStringSubmatch(src)
	if nonce == nil || !strings.HasPrefix(src, "https://captcha.xpguard.org/v?s=15d69a72-653a-47b6-90f6-fde737bce061&ip=203.0.113.5&h=shop.example.com&n=") ||
		!strings.HasSuffix(src, "&u=/wp-login.php?redirect_to=/wp-admin/&reauth=1") {
		t.Fatalf("frame address %q", src)
	}
	if csp := w.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "frame-src https://captcha.xpguard.org") {
		t.Fatalf("CSP %q", csp)
	}
	pass := func(n, from string) *httptest.ResponseRecorder {
		return req("POST", "/.xpguard/pass", "n="+n+"&back="+url.QueryEscape("/wp-login.php?redirect_to=/wp-admin/"), from)
	}
	// No ticket from the portal yet: no cookie.
	if w := pass(nonce[1], "203.0.113.5"); w.Code != 403 || len(w.Result().Cookies()) != 0 {
		t.Fatalf("pass without a ticket: %d", w.Code)
	}
	// A ticket for this visitor: another address cannot use it, and it is
	// used up by that try.
	if !s.AddTicket(nonce[1], "203.0.113.5") || s.AddTicket("short", "203.0.113.5") || s.AddTicket(nonce[1], "nope") {
		t.Fatal("ticket checks")
	}
	if w := pass(nonce[1], "198.51.100.9"); w.Code != 403 {
		t.Fatalf("ticket used from another address: %d", w.Code)
	}
	s.AddTicket(nonce[1], "203.0.113.5")
	w = pass(nonce[1], "203.0.113.5")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"redirect":"http://shop.example.com/wp-login.php?redirect_to=/wp-admin/"`) {
		t.Fatalf("pass: %d %s", w.Code, w.Body.String())
	}
	var c *http.Cookie
	for _, k := range w.Result().Cookies() {
		if k.Name == GateCookie {
			c = k
		}
	}
	given := false
	for _, sl := range s.Passes.Slots(time.Now()) {
		given = given || (c != nil && c.Value == sl[0])
	}
	if c == nil || !given || c.MaxAge != 3600 || !c.HttpOnly {
		t.Fatalf("cookie %+v", c)
	}
	if len(lifted) != 1 || lifted[0] != "203.0.113.5" {
		t.Fatalf("ban not lifted: %v", lifted)
	}
	if w := pass(nonce[1], "203.0.113.5"); w.Code != 403 {
		t.Fatalf("a ticket worked twice: %d", w.Code)
	}
	// A banned visitor (sent here by the firewall) gets the same page for
	// the page it asked for.
	w = req("GET", "/shop/?p=2", "", "203.0.113.6")
	if w.Code != 403 || !strings.Contains(strings.ReplaceAll(w.Body.String(), "&amp;", "&"), "&ip=203.0.113.6&h=shop.example.com&n=") {
		t.Fatalf("banned visitor: %d", w.Code)
	}
	// Back on the portal's domain when the mode is off.
	s.Settings.Patch([]byte(`{"captcha":{"central_mode":""}}`))
	if w := req("GET", "/.xpguard/gate?back=/wp-login.php", "", "203.0.113.5"); w.Code != 302 {
		t.Fatalf("portal's domain: %d", w.Code)
	}
}

// A pass cookie handed to other addresses (one solve for a botnet) is
// withdrawn as soon as the WAF reports it from an address it was not given
// to; the visitor it was given to keeps passing until then.
func TestSitePassShared(t *testing.T) {
	old := saveDelay
	saveDelay = 10 * time.Millisecond
	defer func() { saveDelay = old }()
	var mu sync.Mutex
	saved := []byte(nil)
	p := &SitePasses{Secret: []byte("0123456789abcdef0123456789abcdef"), Save: func(b []byte) { mu.Lock(); saved = b; mu.Unlock() }}
	now := time.Date(2026, 10, 19, 23, 0, 0, 0, time.UTC)
	tok := p.Give("203.0.113.5", now)
	slot := -1
	for i, sl := range p.Slots(now) {
		if sl[0] == tok {
			slot = i
		}
	}
	if tok == "" || slot < 0 || len(p.Slots(now)) != SiteSlots {
		t.Fatalf("value %q not among the accepted ones", tok)
	}
	// The owner, also after midnight (yesterday's value is still accepted).
	if p.Used("203.0.113.5", slot, now) || p.Used("203.0.113.5", slot, now.Add(2*time.Hour)) {
		t.Fatal("the visitor's own pass was withdrawn")
	}
	// IPv6 privacy addresses change within the /64.
	tok6 := p.Give("2001:db8:1:2::10", now)
	for i, sl := range p.Slots(now) {
		if sl[0] == tok6 && p.Used("2001:db8:1:2:aaaa::1", i, now) {
			t.Fatal("pass withdrawn for another address of the same /64")
		}
	}
	// Restarted agent: the state comes back.
	time.Sleep(100 * time.Millisecond)
	q := &SitePasses{Secret: p.Secret, Load: func() []byte { mu.Lock(); defer mu.Unlock(); return saved }}
	if q.Slots(now)[slot][0] != tok || q.Used("203.0.113.5", slot, now) {
		t.Fatal("state lost across a restart")
	}
	// Another address: the value is withdrawn (once; the reports that follow
	// before the WAF runs without it are the same misuse).
	if !p.Used("198.51.100.7", slot, now) || p.Used("198.51.100.8", slot, now.Add(time.Second)) {
		t.Fatal("shared pass not withdrawn exactly once")
	}
	if sl := p.Slots(now)[slot]; sl[0] == tok || sl[1] == tok {
		t.Fatal("the WAF still accepts the shared value")
	}
	for i, sl := range p.Slots(now) {
		if i != slot && sl[0] == tok {
			t.Fatal("value moved to another slot")
		}
	}
	// The other values stay; bad input is ignored.
	if p.Used("nope", 0, now) || p.Used("198.51.100.7", SiteSlots, now) || (&SitePasses{}).Give("203.0.113.5", now) != "" {
		t.Fatal("bad input")
	}
}

// Audit A5 F19: passes given together are saved once, not once each.
func TestSitePassesSavedTogether(t *testing.T) {
	old := saveDelay
	saveDelay = 50 * time.Millisecond
	defer func() { saveDelay = old }()
	var mu sync.Mutex
	saves := 0
	p := &SitePasses{Secret: []byte("0123456789abcdef0123456789abcdef"), Save: func([]byte) { mu.Lock(); saves++; mu.Unlock() }}
	now := time.Now()
	for i := 0; i < 100; i++ {
		p.Give(fmt.Sprintf("198.51.100.%d", i), now)
	}
	time.Sleep(200 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if saves != 1 {
		t.Fatalf("%d saves for 100 passes", saves)
	}
}

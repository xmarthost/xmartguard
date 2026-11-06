package captcha

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// A banned address must not reach other pages of the site through the
// machine-file proxy with a dot segment or an encoded dot or slash (A5 F1).
func TestMachinePathCanonicalOnly(t *testing.T) {
	for _, p := range []string{
		"/.well-known/../x",
		"/.well-known/%2e%2e/x",
		"/.well-known/./../x",
		"/.well-known/acme-challenge/../../x",
		"/.well-known/acme-challenge/%2e%2e%2fx",
		"/.well-known/acme-challenge/a%2fb",
		"/.well-known/acme-challenge/a%5cb",
		"//robots.txt",
		"/./robots.txt",
		"/.well-known/some-page", // not a certificate check: the site's own page
		"/.well-known/acme-challenge/",
	} {
		r := httptest.NewRequest(http.MethodGet, "http://shop.example"+p, nil)
		if MachinePath(r) {
			t.Errorf("%s is served from the site", p)
		}
		// Even with a redirected connection to port 80, it is not proxied.
		r = r.WithContext(context.WithValue(r.Context(), origDstKey{}, netip.MustParseAddrPort("127.0.0.1:80")))
		if serveFromSite(httptest.NewRecorder(), r) {
			t.Errorf("%s was proxied", p)
		}
		// The CAPTCHA server answers it like any other request: the check or a 403.
		rec := httptest.NewRecorder()
		r.Header.Set("Accept", "*/*")
		(&Server{}).ServeHTTP(rec, r)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s: %d", p, rec.Code)
		}
	}
	for _, p := range []string{"/robots.txt", "/sitemap_index.xml", "/.well-known/acme-challenge/AbC-123_x", "/.well-known/pki-validation/ABC.txt", "/.well-known/cpanel-dcv/X1", "/.well-known/security.txt", "/robots.txt?x=1"} {
		if !MachinePath(httptest.NewRequest(http.MethodGet, "http://shop.example"+p, nil)) {
			t.Errorf("%s is not served from the site", p)
		}
	}
}

// The request sent to the site carries only the checked path, never the query.
func TestSiteRewriteDropsQuery(t *testing.T) {
	in := httptest.NewRequest(http.MethodGet, "http://shop.example/robots.txt?rest_route=/x&p=1", nil)
	pr := &httputil.ProxyRequest{In: in, Out: in.Clone(context.Background())}
	siteRewrite(in, "http", netip.MustParseAddrPort("192.0.2.1:80"))(pr)
	if got := pr.Out.URL.String(); got != "http://192.0.2.1:80/robots.txt" {
		t.Fatalf("out %s", got)
	}
	if pr.Out.Host != "shop.example" {
		t.Fatalf("host %s", pr.Out.Host)
	}
}

// business900 hosts the portal's CAPTCHA domain: a banned or IPDB-listed
// visitor sent to that page must reach it (the web server, the portal),
// not this server's CAPTCHA again ("redirected you too many times",
// 2026-11-06). Other websites still get the check.
func TestPortalDomainOnThisServerPassesThrough(t *testing.T) {
	var gotHost, gotXFF, gotURI, gotBody string
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost, gotXFF, gotURI = r.Host, r.Header.Get("X-Forwarded-For"), r.URL.RequestURI()
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Security-Policy", "frame-ancestors https://shop.example.com")
		w.Write([]byte("portal page"))
	}))
	defer site.Close()
	dst := netip.MustParseAddrPort(strings.TrimPrefix(site.URL, "http://"))
	sitePorts[dst.Port()] = true
	defer delete(sitePorts, dst.Port())

	s, _ := newServer(t)
	s.ServerID = "15d69a72-653a-47b6-90f6-fde737bce061"
	s.Settings.Patch([]byte(`{"captcha":{"central":true,"central_url":"https://xpguardcaptcha.site/v","central_mode":"site"},"waf":{"enabled":true}}`))
	do := func(method, host, target, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, target, strings.NewReader(body))
		r.Host = host
		r.Header.Set("Accept", "text/html")
		r.Header.Set("X-Forwarded-For", "1.1.1.1")
		r.RemoteAddr = "37.203.35.18:5000"
		r = r.WithContext(context.WithValue(r.Context(), origDstKey{}, dst))
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w
	}
	w := do("GET", "XpGuardCaptcha.site", "/v?s=x&ip=37.203.35.18&h=shop.example.com&fs=1&u=/wp-login.php", "")
	if w.Code != 200 || w.Body.String() != "portal page" || w.Header().Get("X-Frame-Options") != "" {
		t.Fatalf("portal page: %d %q %v", w.Code, w.Body.String(), w.Header())
	}
	if gotHost != "XpGuardCaptcha.site" || gotXFF != "37.203.35.18" || gotURI != "/v?s=x&ip=37.203.35.18&h=shop.example.com&fs=1&u=/wp-login.php" {
		t.Fatalf("sent %q %q %q", gotHost, gotXFF, gotURI)
	}
	if w.Header().Get("Content-Security-Policy") == "" {
		t.Fatal("portal headers dropped")
	}
	// The answer (a POST without text/html) reaches the portal too.
	if w := do("POST", "xpguardcaptcha.site", "/v/verify", `{"a":1}`); w.Code != 200 || gotBody != `{"a":1}` {
		t.Fatalf("verify: %d %q", w.Code, gotBody)
	}
	// Any other website: the check, as before.
	gotURI = ""
	if w := do("GET", "shop.example.com", "/blog/", ""); w.Code == 200 && w.Body.String() == "portal page" || gotURI != "" {
		t.Fatal("another website passed through")
	}
	// Not a redirected website connection (the CAPTCHA port itself): not proxied.
	r := httptest.NewRequest("GET", "/v", nil)
	r.Host = "xpguardcaptcha.site"
	if servePortal(httptest.NewRecorder(), r, "xpguardcaptcha.site") {
		t.Fatal("proxied without a redirected connection")
	}
	if portalHost("http://x.test/v") != "" || portalHost("https://X.test/v") != "x.test" {
		t.Fatal("portal host")
	}
}

// The portal answers a solved check only after the website's server let
// the visitor in (a web server reload, often 10-30 seconds): the answer
// must reach the browser past this server's own short time limits
// ("Network error" after a passed check, 2026-11-06).
func TestPortalSlowAnswerOutlivesServerLimits(t *testing.T) {
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(600 * time.Millisecond)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer site.Close()
	dst := netip.MustParseAddrPort(strings.TrimPrefix(site.URL, "http://"))
	sitePorts[dst.Port()] = true
	defer delete(sitePorts, dst.Port())
	// This server as it runs: short read and write limits (20 s there).
	front := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(context.WithValue(r.Context(), origDstKey{}, dst))
		if !servePortal(w, r, "xpguardcaptcha.site") {
			http.Error(w, "not proxied", 500)
		}
	}))
	front.Config.ReadTimeout, front.Config.WriteTimeout = 200*time.Millisecond, 200*time.Millisecond
	front.Start()
	defer front.Close()
	req, _ := http.NewRequest("POST", front.URL+"/v/verify", strings.NewReader(`{"a":1}`))
	req.Host = "xpguardcaptcha.site"
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("answer cut off: %v", err)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || string(b) != `{"ok":true}` {
		t.Fatalf("%d %q", res.StatusCode, b)
	}
}

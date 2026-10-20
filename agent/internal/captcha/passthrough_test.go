package captcha

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/netip"
	"testing"
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

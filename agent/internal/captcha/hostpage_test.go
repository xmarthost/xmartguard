package captcha

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The check on the server's own hostname (hostname mode): no CAPTCHA port
// (7743 is refused by many networks, VPNs and Cloudflare) and no website
// cache or proxy in the way.
func TestHostPage(t *testing.T) {
	page := HostPageHTML("https://captcha.test/v")
	for _, want := range []string{hostPageMarker, `PAGE="https://captcha.test/v",ORIGIN="https://captcha.test"`, `"&fh=1&u="`,
		`e.origin===ORIGIN&&e.source===f.contentWindow`, `location.replace("https://"+site+back)`} {
		if !strings.Contains(page, want) {
			t.Errorf("page misses %q", want)
		}
	}
	if HostPageHTML("http://captcha.test/v") != "" || HostPageHTML("javascript:alert(1)") != "" {
		t.Error("page for a portal address that is not https")
	}
	if !strings.Contains(HostPageHTML(`https://captcha.test/v"</script>`), `\"</script>`) {
		t.Error("portal address not escaped")
	}

	// Installed into the hostname's document root and removed again; a file
	// someone else put there stays.
	root := t.TempDir()
	saved := HostDocRoot
	HostDocRoot = root
	defer func() { HostDocRoot = saved }()
	if err := InstallHostPage("https://captcha.test/v"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "xpguard-check", "index.html")
	if b, _ := os.ReadFile(path); string(b) != page {
		t.Fatal("page not written")
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o644 {
		t.Fatalf("mode %v", st.Mode())
	}
	RemoveHostPage()
	if _, err := os.Stat(filepath.Join(root, "xpguard-check")); !os.IsNotExist(err) {
		t.Fatal("page left behind")
	}
	os.MkdirAll(filepath.Join(root, "xpguard-check"), 0o755)
	os.WriteFile(path, []byte("someone's page"), 0o644)
	RemoveHostPage()
	if _, err := os.Stat(path); err != nil {
		t.Fatal("a page that is not ours was removed")
	}
	HostDocRoot = filepath.Join(root, "missing")
	if InstallHostPage("https://captcha.test/v") == nil {
		t.Fatal("installed without a document root")
	}
}

// The self-test reaches the page the way a visitor's browser does: port
// 443 of this machine, the hostname's certificate checked, this page.
func TestCheckHostPage(t *testing.T) {
	serve := page(HostPageHTML("https://captcha.test/v"))
	ts := httptest.NewTLSServer(serve)
	defer ts.Close()
	savedAddr, savedRoots := hostCheckAddr, hostCheckRoots
	defer func() { hostCheckAddr, hostCheckRoots = savedAddr, savedRoots }()
	hostCheckAddr = strings.TrimPrefix(ts.URL, "https://")
	hostCheckRoots = x509.NewCertPool()
	hostCheckRoots.AddCert(ts.Certificate())
	ctx := context.Background()
	// httptest's certificate is for example.com.
	if err := CheckHostPage(ctx, "example.com", "https://captcha.test/v", nil); err != nil {
		t.Fatal(err)
	}
	if err := CheckHostPage(ctx, "other.example.net", "https://captcha.test/v", nil); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("certificate for another name: %v", err)
	}
	if err := CheckHostPage(ctx, "example.com", "https://other.test/v", nil); err == nil {
		t.Fatal("a page for another portal passed")
	}
	if err := CheckHostPage(ctx, "localhost", "https://captcha.test/v", nil); err == nil {
		t.Fatal("a hostname without a domain passed")
	}
	// The hostname must lead here (its DNS name, as browsers look it up).
	if err := CheckHostPage(ctx, "example.com", "https://captcha.test/v", []string{"192.0.2.1"}); err == nil {
		t.Fatal("a hostname that resolves elsewhere passed")
	}
	ts.Config.Handler = http.NotFoundHandler()
	if err := CheckHostPage(ctx, "example.com", "https://captcha.test/v", nil); err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("missing page: %v", err)
	}
}

type page string

func (p page) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != HostPagePath {
		http.NotFound(w, r)
		return
	}
	_, _ = w.Write([]byte(p))
}

// A visitor the firewall sends to this server (IPDB, ban) has its
// connections to the hostname come here too: the page is served here, and
// the firewall's own redirect goes to it.
func TestHostPageForFirewallVisitors(t *testing.T) {
	s, _ := newServer(t)
	s.ServerID = "15d69a72-653a-47b6-90f6-fde737bce061"
	s.Settings.Patch([]byte(`{"captcha":{"central":true,"central_url":"https://captcha.test/v","central_mode":"hostname"}}`))
	hp := ""
	s.HostPage = func() string { return hp }
	get := func(host, target string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", target, nil)
		r.Host = host
		r.Header.Set("Accept", "text/html")
		r.RemoteAddr = "203.0.113.5:4000"
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w
	}
	// Not in use (its self-test failed): the portal address, as before.
	if w := get("shop.example.com", "/blog/"); !strings.HasPrefix(w.Header().Get("Location"), "https://captcha.test/v?") {
		t.Fatalf("without the hostname page: %q", w.Header().Get("Location"))
	}
	hp = "https://server1.example.net/xpguard-check/"
	w := get("shop.example.com", "/blog/?p=1")
	if want := "https://server1.example.net/xpguard-check/?s=15d69a72-653a-47b6-90f6-fde737bce061&ip=203.0.113.5&h=shop.example.com&k=fw&u=/blog/?p=1"; w.Code != 302 || w.Header().Get("Location") != want {
		t.Fatalf("redirect: %d %q", w.Code, w.Header().Get("Location"))
	}
	w = get("server1.example.net", "/xpguard-check/?s=x&ip=203.0.113.5&h=shop.example.com&u=/")
	if w.Code != 200 || !strings.Contains(w.Body.String(), hostPageMarker) {
		t.Fatalf("hostname page: %d %s", w.Code, w.Body.String())
	}
	// Only on the hostname: another website's /xpguard-check/ is no page here.
	if w := get("shop.example.com", "/xpguard-check/?s=x&ip=1.2.3.4&h=a.com&u=/"); strings.Contains(w.Body.String(), hostPageMarker) {
		t.Fatal("hostname page served on a website")
	}
}

// The portal's browser test (server/test/altcha-browser.test.ts) runs this
// page; the copy there must be the agent's page (XG_UPDATE_FIXTURES=1
// writes it).
func TestHostPageFixture(t *testing.T) {
	path := filepath.Join("..", "..", "..", "server", "test", "fixtures", "hostpage.html")
	want := HostPageHTML("https://captcha.test/v")
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
		t.Fatal("server/test/fixtures/hostpage.html differs from the page: run with XG_UPDATE_FIXTURES=1")
	}
}

// A visitor the firewall sends to this server (IPDB, ban) reaches the
// hostname page here, not at the web server: this server must present the
// hostname's certificate, which cPanel keeps with the service certificates
// (Firefox showed "Not Secure" for the self-signed one).
func TestHostnameServiceCertificate(t *testing.T) {
	dir := t.TempDir()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "server1.example.net"},
		DNSNames: []string{"server1.example.net"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	kb, _ := x509.MarshalECPrivateKey(key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
	// mycpanel.pem: the certificate, its key next to it.
	os.WriteFile(filepath.Join(dir, "mycpanel.pem"), certPEM, 0o600)
	os.WriteFile(filepath.Join(dir, "mycpanel.key"), keyPEM, 0o600)
	saved := ServiceCerts
	defer func() { ServiceCerts = saved }()
	ServiceCerts = []string{filepath.Join(dir, "missing.pem"), filepath.Join(dir, "mycpanel.pem")}
	c := &CertStore{Dirs: []string{filepath.Join(dir, "sites")}}
	cert, err := c.Get(&tls.ClientHelloInfo{ServerName: "server1.example.net"})
	if err != nil || !bytes.Equal(cert.Certificate[0], der) {
		t.Fatal("hostname did not get the service certificate")
	}
	if cert, _ := c.Get(&tls.ClientHelloInfo{ServerName: "shop.example.com"}); bytes.Equal(cert.Certificate[0], der) {
		t.Fatal("another name got the hostname's certificate")
	}
	// A combined file (key and certificate) works too.
	os.WriteFile(filepath.Join(dir, "cpanel.pem"), append(keyPEM, certPEM...), 0o600)
	ServiceCerts = []string{filepath.Join(dir, "cpanel.pem")}
	if got := serviceCert("server1.example.net"); got == nil || !bytes.Equal(got.Certificate[0], der) {
		t.Fatal("combined service certificate not used")
	}

	// The check of this server's own CAPTCHA port: a certificate the
	// browser trusts for the hostname, or the portal address for those
	// visitors.
	ts := httptest.NewUnstartedServer(http.NotFoundHandler())
	ts.TLS = &tls.Config{GetCertificate: c.Get}
	ts.StartTLS()
	defer ts.Close()
	savedAddr, savedRoots := ownTLSAddr, hostCheckRoots
	defer func() { ownTLSAddr, hostCheckRoots = savedAddr, savedRoots }()
	ownTLSAddr = strings.TrimPrefix(ts.URL, "https://")
	hostCheckRoots = x509.NewCertPool()
	leaf, _ := x509.ParseCertificate(der)
	hostCheckRoots.AddCert(leaf)
	if err := CheckOwnTLS(context.Background(), "server1.example.net", 7743); err != nil {
		t.Fatal(err)
	}
	// The self-signed fallback (no service certificate): refused.
	ServiceCerts = nil
	c2 := &CertStore{Dirs: []string{filepath.Join(dir, "sites")}}
	ts.TLS.GetCertificate = c2.Get
	if err := CheckOwnTLS(context.Background(), "server1.example.net", 7743); err == nil {
		t.Fatal("self-signed certificate passed")
	}
}

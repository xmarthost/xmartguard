package captcha

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"image/png"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/settings"
)

func newServer(t *testing.T) (*Server, *[]string) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XG_CONFIG_DIR", filepath.Join(dir, "conf"))
	st, err := settings.Load()
	if err != nil {
		t.Fatal(err)
	}
	var solved []string
	s := &Server{Settings: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Solved: func(ip string) error {
		solved = append(solved, ip)
		return nil
	}}
	s.key = make([]byte, 32)
	_, _ = rand.Read(s.key)
	return s, &solved
}

func TestSealOpen(t *testing.T) {
	s, _ := newServer(t)
	id, digits := s.newChallenge("198.51.100.7")
	if len(digits) != 5 || strings.Contains(id, digits) {
		t.Fatalf("challenge leaks digits: %s %s", id, digits)
	}
	if got, ok := s.open("198.51.100.7", id); !ok || got != digits {
		t.Fatalf("open: %q %v", got, ok)
	}
	if _, ok := s.open("198.51.100.8", id); ok {
		t.Fatal("challenge accepted from another address")
	}
	if _, ok := s.open("198.51.100.7", id[:len(id)-2]+"00"); ok {
		t.Fatal("tampered challenge accepted")
	}
}

func TestImage(t *testing.T) {
	var b bytes.Buffer
	if err := RenderPNG(&b, "40719"); err != nil {
		t.Fatal(err)
	}
	img, err := png.Decode(&b)
	if err != nil || img.Bounds().Dx() != 260 {
		t.Fatalf("png: %v", err)
	}
}

func TestBuiltinFlow(t *testing.T) {
	s, solved := newServer(t)
	srv := httptest.NewServer(s)
	defer srv.Close()
	res, err := http.Get(srv.URL + "/wp-login.php?x=1")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 403 || !strings.Contains(string(body), "Security check") {
		t.Fatalf("page: %d", res.StatusCode)
	}
	id := regexp.MustCompile(`name="id" value="([^"]+)"`).FindStringSubmatch(string(body))[1]
	id = strings.ReplaceAll(id, "&#43;", "+")
	if img, _ := http.Get(srv.URL + "/.xpguard/captcha.png?id=" + url.QueryEscape(id)); img.Header.Get("Content-Type") != "image/png" {
		t.Fatal("image not served")
	}
	digits, ok := s.open("127.0.0.1", id)
	if !ok {
		t.Fatal("cannot open id")
	}
	// Wrong answer.
	res, _ = http.PostForm(srv.URL+"/.xpguard/verify", url.Values{"id": {id}, "answer": {"00000x"}, "back": {"/wp-login.php"}})
	res.Body.Close()
	if len(*solved) != 0 {
		t.Fatal("wrong answer accepted")
	}
	// Right answer; an off-site "back" is not followed.
	res, _ = http.PostForm(srv.URL+"/.xpguard/verify", url.Values{"id": {id}, "answer": {digits}, "back": {"//evil.example/"}})
	body, _ = io.ReadAll(res.Body)
	res.Body.Close()
	if len(*solved) != 1 || (*solved)[0] != "127.0.0.1" || !strings.Contains(string(body), `url=/"`) {
		t.Fatalf("solve: %v %s", *solved, body)
	}
}

func TestAttemptLimit(t *testing.T) {
	s, _ := newServer(t)
	for i := 0; i < 10; i++ {
		if s.tooMany("203.0.113.1") {
			t.Fatalf("limited after %d", i)
		}
	}
	if !s.tooMany("203.0.113.1") {
		t.Fatal("not limited")
	}
}

func TestProviderVerify(t *testing.T) {
	s, solved := newServer(t)
	if _, err := s.Settings.Patch([]byte(`{"captcha":{"provider":"turnstile","site_key":"site","secret_key":"sec"}}`)); err != nil {
		t.Fatal(err)
	}
	var gotSecret string
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotSecret = r.PostForm.Get("secret")
		if r.PostForm.Get("response") == "good" {
			io.WriteString(w, `{"success":true}`)
			return
		}
		io.WriteString(w, `{"success":false}`)
	}))
	defer mock.Close()
	s.VerifyURL = mock.URL
	srv := httptest.NewServer(s)
	defer srv.Close()
	res, _ := http.Get(srv.URL + "/")
	body, _ := io.ReadAll(res.Body)
	if !strings.Contains(string(body), `data-sitekey="site"`) {
		t.Fatal("turnstile widget missing")
	}
	http.PostForm(srv.URL+"/.xpguard/verify", url.Values{"cf-turnstile-response": {"bad"}})
	if len(*solved) != 0 {
		t.Fatal("bad token accepted")
	}
	http.PostForm(srv.URL+"/.xpguard/verify", url.Values{"cf-turnstile-response": {"good"}})
	if len(*solved) != 1 || gotSecret != "sec" {
		t.Fatalf("good token: %v %q", *solved, gotSecret)
	}
}

func TestSelfSignedFallback(t *testing.T) {
	c := &CertStore{Dirs: []string{t.TempDir()}}
	cert, err := c.Get(&tls.ClientHelloInfo{ServerName: "example.com"})
	if err != nil || cert == nil {
		t.Fatal(err)
	}
	if again, _ := c.Get(&tls.ClientHelloInfo{ServerName: "../../etc"}); again != cert {
		t.Fatal("path-like name not sent to the fallback")
	}
}

func TestLoginGateFlow(t *testing.T) {
	s, solved := newServer(t)
	s.GateSecret = bytes.Repeat([]byte{7}, 32)
	srv := httptest.NewServer(s)
	defer srv.Close()
	// The WAF sends the visitor here with the login page (query unencoded).
	res, err := http.Get(srv.URL + "/.xpguard/gate?back=/wp-login.php?redirect_to=/wp-admin/&reauth=1")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || !strings.Contains(string(body), "login page is protected") || !strings.Contains(string(body), `name="gate" value="1"`) {
		t.Fatalf("gate page: %d %s", res.StatusCode, body)
	}
	id := strings.ReplaceAll(regexp.MustCompile(`name="id" value="([^"]+)"`).FindStringSubmatch(string(body))[1], "&#43;", "+")
	digits, _ := s.open("127.0.0.1", id)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err = client.PostForm(srv.URL+"/.xpguard/verify", url.Values{"id": {id}, "answer": {digits}, "gate": {"1"},
		"back": {"/wp-login.php?redirect_to=/wp-admin/&reauth=1"}})
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	loc := res.Header.Get("Location")
	if res.StatusCode != http.StatusSeeOther || !strings.HasPrefix(loc, "http://127.0.0.1/wp-login.php?redirect_to=") {
		t.Fatalf("redirect: %d %q", res.StatusCode, loc)
	}
	var cookie *http.Cookie
	for _, c := range res.Cookies() {
		if c.Name == GateCookie {
			cookie = c
		}
	}
	if cookie == nil || cookie.Value != GateTokens(s.GateSecret, time.Now())[0] {
		t.Fatalf("cookie: %+v", res.Cookies())
	}
	// Passing the login page does not unban or allow the address in the firewall.
	if len(*solved) != 0 {
		t.Fatalf("firewall touched: %v", *solved)
	}
	// Off-site back is refused.
	if got := safeBack("//evil.example/"); got != "/" {
		t.Fatal(got)
	}
}

func TestGateTokens(t *testing.T) {
	k := bytes.Repeat([]byte{1}, 32)
	now := time.Unix(1_800_000_000, 0)
	a, b := GateTokens(k, now), GateTokens(k, now.Add(24*time.Hour))
	if len(a) != 2 || a[0] == a[1] || b[1] != a[0] || len(a[0]) != 32 {
		t.Fatalf("%v %v", a, b)
	}
	if GateTokens(nil, now) != nil {
		t.Fatal("tokens without a key")
	}
}

func TestCertIndexFindsAddonDomains(t *testing.T) {
	dir := t.TempDir()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "helloroos.com"},
		DNSNames: []string{"helloroos.com", "www.helloroos.com", "*.shop.example"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	kb, _ := x509.MarshalECPrivateKey(key)
	combined := append(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	// cPanel names the folder after the vhost, not the addon domain.
	vh := filepath.Join(dir, "helloroos.com.clickcreek.com.au")
	_ = os.MkdirAll(vh, 0o700)
	_ = os.WriteFile(filepath.Join(vh, "combined"), combined, 0o600)
	c := &CertStore{Dirs: []string{dir}}
	for _, name := range []string{"helloroos.com", "www.helloroos.com", "a.shop.example"} {
		cert, err := c.Get(&tls.ClientHelloInfo{ServerName: name})
		if err != nil || cert == nil || len(cert.Certificate) == 0 || !bytes.Equal(cert.Certificate[0], der) {
			t.Fatalf("%s: not the site certificate", name)
		}
	}
	if cert, _ := c.Get(&tls.ClientHelloInfo{ServerName: "other.example"}); bytes.Equal(cert.Certificate[0], der) {
		t.Fatal("unrelated name got the site certificate")
	}
}

// Redirected connections must not be reused: after an unblock the next
// request of the browser has to reach the site, not this server.
func TestServerClosesEveryConnection(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := HTTPServer(0, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "captcha") }))
	go srv.Serve(ln)
	defer srv.Close()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "GET / HTTP/1.1\r\nHost: x\r\n\r\nGET / HTTP/1.1\r\nHost: x\r\n\r\n")
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	all, _ := io.ReadAll(c)
	if n := strings.Count(string(all), "HTTP/1.1 200"); n != 1 || !strings.Contains(string(all), "Connection: close") {
		t.Fatalf("connection kept open (%d responses):\n%s", n, all)
	}
}

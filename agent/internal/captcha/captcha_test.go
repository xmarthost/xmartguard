package captcha

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"image/png"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

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
	if img, _ := http.Get(srv.URL + "/.xmartguard/captcha.png?id=" + url.QueryEscape(id)); img.Header.Get("Content-Type") != "image/png" {
		t.Fatal("image not served")
	}
	digits, ok := s.open("127.0.0.1", id)
	if !ok {
		t.Fatal("cannot open id")
	}
	// Wrong answer.
	res, _ = http.PostForm(srv.URL+"/.xmartguard/verify", url.Values{"id": {id}, "answer": {"00000x"}, "back": {"/wp-login.php"}})
	res.Body.Close()
	if len(*solved) != 0 {
		t.Fatal("wrong answer accepted")
	}
	// Right answer; an off-site "back" is not followed.
	res, _ = http.PostForm(srv.URL+"/.xmartguard/verify", url.Values{"id": {id}, "answer": {digits}, "back": {"//evil.example/"}})
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
	http.PostForm(srv.URL+"/.xmartguard/verify", url.Values{"cf-turnstile-response": {"bad"}})
	if len(*solved) != 0 {
		t.Fatal("bad token accepted")
	}
	http.PostForm(srv.URL+"/.xmartguard/verify", url.Values{"cf-turnstile-response": {"good"}})
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

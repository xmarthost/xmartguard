package captcha

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// The "done" page and the check page clean the way back with safeBack:
// "/\host" (read as "//host" by browsers) does not leave the site (A5 F13).
func TestDoneAndPageUseSafeBack(t *testing.T) {
	s, solved := newServer(t)
	srv := httptest.NewServer(s)
	defer srv.Close()
	for _, back := range []string{`/\other.example`, "/ok\r\nx", "//other.example"} {
		id, digits := s.newChallenge("127.0.0.1")
		res, err := http.PostForm(srv.URL+"/.xpguard/verify", url.Values{"id": {id}, "answer": {digits}, "back": {back}})
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if len(*solved) == 0 {
			t.Fatalf("not solved: %s", body)
		}
		if strings.Contains(string(body), "other.example") || strings.Contains(string(body), "ok\r") {
			t.Fatalf("%q kept as the way back:\n%s", back, body)
		}
		// A wrong answer shows the check again, with the same clean way back.
		res, _ = http.PostForm(srv.URL+"/.xpguard/verify", url.Values{"id": {id}, "answer": {"x"}, "back": {back}})
		body, _ = io.ReadAll(res.Body)
		res.Body.Close()
		if strings.Contains(string(body), "other.example") {
			t.Fatalf("%q kept on the check page", back)
		}
	}
	if safeBack("/shop/?a=1") != "/shop/?a=1" {
		t.Fatal("a normal path is kept")
	}
}

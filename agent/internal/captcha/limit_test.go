package captcha

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// A flood of other addresses does not reset an address's attempt count,
// and an IPv6 visitor is counted per /64 (A5 F14).
func TestAttemptLimitSurvivesFlood(t *testing.T) {
	s, _ := newServer(t)
	for i := 0; i < 10; i++ {
		s.tooMany("203.0.113.1")
	}
	for i := 0; i < 12000; i++ {
		s.tooMany(fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255))
	}
	if !s.tooMany("203.0.113.1") {
		t.Fatal("the flood reset the limit")
	}
	for i := 0; i < 10; i++ {
		if s.tooMany(fmt.Sprintf("2001:db8:1:2::%x", i+1)) {
			t.Fatalf("limited after %d", i)
		}
	}
	if !s.tooMany("2001:db8:1:2::ffff") {
		t.Fatal("another address in the same /64 is not limited")
	}
}

// A challenge image is good for one answer: after a wrong guess, the right
// digits for the same image are refused (A5 F14).
func TestChallengeSingleUse(t *testing.T) {
	s, solved := newServer(t)
	srv := httptest.NewServer(s)
	defer srv.Close()
	id, digits := s.newChallenge("127.0.0.1")
	wrong := "00000"
	if wrong == digits {
		wrong = "11111"
	}
	for _, a := range []string{wrong, digits} {
		res, err := http.PostForm(srv.URL+"/.xpguard/verify", url.Values{"id": {id}, "answer": {a}, "back": {"/"}})
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
	}
	if len(*solved) != 0 {
		t.Fatal("a challenge was answered twice")
	}
	id, digits = s.newChallenge("127.0.0.1")
	res, _ := http.PostForm(srv.URL+"/.xpguard/verify", url.Values{"id": {id}, "answer": {digits}, "back": {"/"}})
	res.Body.Close()
	if len(*solved) != 1 {
		t.Fatal("a new challenge does not work")
	}
}

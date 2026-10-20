package captcha

import (
	"fmt"
	"net"
	"testing"
	"time"
)

func freePort(t *testing.T) (int, net.Listener) {
	t.Helper()
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	return l.Addr().(*net.TCPAddr).Port, l
}

// A listener that fails to bind is retried on the next sync, so banned
// visitors are not left with "connection refused" until a restart (A5 F9).
func TestSyncRetriesFailedBind(t *testing.T) {
	s, _ := newServer(t)
	httpPort, busy := freePort(t)
	httpsPort, l2 := freePort(t)
	l2.Close()
	if _, err := s.Settings.Patch([]byte(fmt.Sprintf(`{"firewall":{"enabled":true,"captcha":true},"captcha":{"http_port":%d,"https_port":%d}}`, httpPort, httpsPort))); err != nil {
		t.Fatal(err)
	}
	if !Wanted(s.Settings.Get()) {
		t.Fatal("captcha not wanted")
	}
	defer s.stop()
	s.sync() // the HTTP port is taken
	if s.running[0] != nil {
		t.Fatal("marked running without a listener")
	}
	// The HTTPS port was not left bound by the failed attempt.
	if l, err := net.Listen("tcp", fmt.Sprintf(":%d", httpsPort)); err != nil {
		t.Fatalf("https port left bound: %v", err)
	} else {
		l.Close()
	}
	busy.Close()
	s.sync()
	if s.running[0] == nil {
		t.Fatal("not retried")
	}
	for _, p := range []int{httpPort, httpsPort} {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", p), 2*time.Second)
		if err != nil {
			t.Fatalf("port %d: %v", p, err)
		}
		c.Close()
	}
}

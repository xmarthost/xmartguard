package firewall

import (
	"bufio"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A browser keeps its connection to the website open between page loads.
// When its address is listed on the IPDB (or banned) while that connection
// is open, the next page load went over it: dropped packets hung the page
// until the browser gave up (yamalcustompackaging.co.uk: 403s, then a page
// that would not load, then the CAPTCHA). The connection is reset now, so
// the browser reconnects at once and the new connection is redirected to
// the CAPTCHA.
func TestListedVisitorKeepAliveIsReset(t *testing.T) {
	if os.Getenv("XG_DESTRUCTIVE_TESTS") != "1" {
		t.Skip("adds a network namespace and nat rules on this machine; set XG_DESTRUCTIVE_TESTS=1")
	}
	providers(t, func(t *testing.T, provider string) {
		m := newManager(t, provider)
		ns := "xgka" + provider[:3]
		host, peer := "xgka0"+provider[:1], "xgka1"+provider[:1]
		sh := func(args ...string) error { return exec.Command("ip", args...).Run() }
		_ = sh("netns", "del", ns)
		if sh("netns", "add", ns) != nil {
			t.Skip("network namespaces not available")
		}
		t.Cleanup(func() { _ = sh("netns", "del", ns); _ = sh("link", "del", host) })
		for _, c := range [][]string{
			{"link", "add", host, "type", "veth", "peer", "name", peer}, {"link", "set", peer, "netns", ns},
			{"addr", "add", "10.211.7.1/24", "dev", host}, {"link", "set", host, "up"},
			{"netns", "exec", ns, "ip", "addr", "add", "10.211.7.2/24", "dev", peer}, {"netns", "exec", ns, "ip", "link", "set", peer, "up"},
		} {
			if err := sh(c...); err != nil {
				t.Fatalf("ip %v: %v", c, err)
			}
		}
		ln, err := net.Listen("tcp", "10.211.7.1:80")
		if err != nil {
			t.Skipf("port 80: %v", err)
		}
		srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("site")) })}
		go srv.Serve(ln)
		t.Cleanup(func() { srv.Close() })
		// The CAPTCHA server's port, where new connections are sent.
		cport := m.Settings.Get().Captcha.HTTPPort
		cln, err := net.Listen("tcp", "10.211.7.1:"+strconv.Itoa(cport))
		if err != nil {
			t.Skipf("port %d: %v", cport, err)
		}
		csrv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("captcha")) })}
		go csrv.Serve(cln)
		t.Cleanup(func() { csrv.Close() })

		if _, err := m.Settings.Patch([]byte(`{"firewall":{"enabled":true},"ipdb":{"enabled":true,"captcha":true}}`)); err != nil {
			t.Fatal(err)
		}
		m.IPDB = &IPDB{}
		if err := m.Apply(); err != nil {
			t.Fatal(err)
		}
		// The visitor: one request, then (after the listing) a second one
		// over the same connection.
		client := exec.Command("ip", "netns", "exec", ns, "python3", "-c", `
import socket, sys, time
s = socket.create_connection(("10.211.7.1", 80), timeout=3)
req = b"GET / HTTP/1.1\r\nHost: shop.example.com\r\n\r\n"
s.sendall(req); s.recv(4096)
print("first", flush=True)
sys.stdin.readline()
s.settimeout(8)
t = time.time()
try:
    s.sendall(req)
    d = s.recv(4096)
    print("answer" if d else "closed", flush=True)
except ConnectionResetError:
    # The browser reconnects: the new connection reaches the CAPTCHA.
    n = socket.create_connection(("10.211.7.1", 80), timeout=3)
    n.sendall(req)
    body = n.recv(4096).split(b"\r\n\r\n", 1)[-1].decode()
    print("reset %.1f then %s" % (time.time() - t, body), flush=True)
except socket.timeout:
    print("hung", flush=True)
`)
		in, _ := client.StdinPipe()
		out, _ := client.StdoutPipe()
		if err := client.Start(); err != nil {
			t.Fatal(err)
		}
		defer client.Process.Kill()
		r := bufio.NewReader(out)
		if l, _ := r.ReadString('\n'); strings.TrimSpace(l) != "first" {
			t.Fatalf("first request: %q", l)
		}
		if _, err := m.ApplyIPDB("v1", []string{"10.211.7.2 ZZ"}); err != nil {
			t.Fatal(err)
		}
		in.Write([]byte("go\n"))
		done := make(chan string, 1)
		go func() { l, _ := r.ReadString('\n'); done <- strings.TrimSpace(l) }()
		select {
		case l := <-done:
			if !strings.HasPrefix(l, "reset") || !strings.HasSuffix(l, "then captcha") {
				t.Fatalf("open connection after the listing: %q (want a reset, then the CAPTCHA)", l)
			}
		case <-time.After(12 * time.Second):
			t.Fatal("client did not finish")
		}
	})
}

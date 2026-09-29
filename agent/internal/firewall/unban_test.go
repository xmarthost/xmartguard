package firewall

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/captcha"
)

// An unblocked address reaches the sites at once, even with DoS
// protection recording kernel bans and the CAPTCHA redirect on.
func TestUnbanIsImmediateOnKernel(t *testing.T) {
	if os.Getenv("XG_DESTRUCTIVE_TESTS") != "1" {
		t.Skip("set XG_DESTRUCTIVE_TESTS=1")
	}
	providers(t, func(t *testing.T, provider string) {
		m := newManager(t, provider)
		in := netns(t)
		web, err := net.Listen("tcp", "0.0.0.0:8081")
		if err != nil {
			t.Skip("port busy")
		}
		defer web.Close()
		go http.Serve(web, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "site") }))
		if _, err := m.Settings.Patch([]byte(`{"firewall":{"enabled":true,"dos":true,"captcha":true}}`)); err != nil {
			t.Fatal(err)
		}
		if err := m.Apply(); err != nil {
			t.Fatal(err)
		}
		get := func() string { o, _ := in("curl", "-s", "-m", "2", "http://10.99.0.1:8081/"); return string(o) }
		if g := get(); g != "site" {
			t.Fatalf("before ban: %q", g)
		}
		m.AutoBan("10.99.0.2", "test", "waf")
		if g := get(); g == "site" {
			t.Fatalf("not banned\n%s", kernelDump(m))
		}
		m.syncDoSBans()
		start := time.Now()
		if err := m.Unblock("10.99.0.2"); err != nil {
			t.Fatal(err)
		}
		t.Logf("unblock took %s", time.Since(start))
		// The kernel's copy of a ban being lifted is not recorded as a new DoS ban.
		if err := m.Backend().AddTempBan("10.99.0.2", 60); err != nil {
			t.Fatal(err)
		}
		m.syncDoSBans()
		if r, _ := m.rules(KindTempBan); len(r) != 0 {
			t.Fatalf("lifted ban recorded again: %+v", r)
		}
		if err := m.Apply(); err != nil {
			t.Fatal(err)
		}
		if g := get(); g != "site" {
			t.Fatalf("still blocked after unblock: %q\n%s", g, kernelDump(m))
		}
	})
}

const keepAliveClient = `
import http.client, sys
c = http.client.HTTPConnection("10.99.0.1", 80, timeout=3)
for line in sys.stdin:
    try:
        c.request("GET", "/")
        print(c.getresponse().read().decode(), flush=True)
    except Exception as e:
        print("ERR", e, flush=True)
        c = http.client.HTTPConnection("10.99.0.1", 80, timeout=3)
`

// A browser's kept-alive connection that was redirected to the CAPTCHA
// reaches the site right after the unblock.
func TestUnbanKeepAliveOnKernel(t *testing.T) {
	if os.Getenv("XG_DESTRUCTIVE_TESTS") != "1" {
		t.Skip("set XG_DESTRUCTIVE_TESTS=1")
	}
	providers(t, func(t *testing.T, provider string) {
		m := newManager(t, provider)
		_ = netns(t)
		cap, err := net.Listen("tcp", "0.0.0.0:7780")
		if err != nil {
			t.Skip("busy")
		}
		defer cap.Close()
		capSrv := captcha.HTTPServer(0, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "captcha-page") }))
		go capSrv.Serve(cap)
		web, err := net.Listen("tcp", "0.0.0.0:80")
		if err != nil {
			t.Skip("busy 80")
		}
		defer web.Close()
		go http.Serve(web, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "site") }))
		if _, err := m.Settings.Patch([]byte(`{"firewall":{"enabled":true,"captcha":true}}`)); err != nil {
			t.Fatal(err)
		}
		m.AutoBan("10.99.0.2", "test", "waf")
		cmd := exec.Command("ip", "netns", "exec", "xgtest", "python3", "-c", keepAliveClient)
		stdin, _ := cmd.StdinPipe()
		stdout, _ := cmd.StdoutPipe()
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		defer cmd.Process.Kill()
		r := bufio.NewReader(stdout)
		ask := func() string { io.WriteString(stdin, "x\n"); l, _ := r.ReadString('\n'); return strings.TrimSpace(l) }
		if g := ask(); g != "captcha-page" {
			t.Fatalf("banned: %q", g)
		}
		if err := m.Unblock("10.99.0.2"); err != nil {
			t.Fatal(err)
		}
		if g := ask(); g != "site" {
			t.Fatalf("same connection after unblock: %q", g)
		}
	})
}

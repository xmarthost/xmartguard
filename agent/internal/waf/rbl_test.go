package waf

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/settings"
	"github.com/xmarthost/xmartguard/agent/internal/store"
)

func TestRBLRender(t *testing.T) {
	c := settings.Defaults().WAF
	out := Render(c, Options{Dir: "/r"})
	for _, id := range []int{IDIPDBPost, IDIPDBPost + 1000, IDTorPost, IDTorPost + 1000} {
		if !strings.Contains(out, fmt.Sprintf("id:%d,", id)) {
			t.Errorf("rule %d missing", id)
		}
	}
	if strings.Contains(out, fmt.Sprintf("id:%d,", IDTorBlock)) {
		t.Error("Tor block rule with action post")
	}
	c.TorAction = "block"
	if !strings.Contains(Render(c, Options{Dir: "/r"}), fmt.Sprintf("id:%d,", IDTorBlock)) {
		t.Error("Tor block rule missing")
	}
	// CAPTCHA mode: no rule while the portal's page takes Tor visitors.
	c.TorAction = "captcha"
	central := &Central{URL: "https://captcha.xpguard.org/v", ServerID: "15d69a72-653a-47b6-90f6-fde737bce061"}
	if strings.Contains(Render(c, Options{Dir: "/r", Central: central}), "Tor exit") {
		t.Error("Tor rule although the CAPTCHA page handles Tor visitors")
	}
	if !strings.Contains(Render(c, Options{Dir: "/r"}), fmt.Sprintf("id:%d,", IDTorPost)) {
		t.Error("CAPTCHA mode without the CAPTCHA page must block POST")
	}
	c.IPDBPost, c.TorAction = false, "off"
	if out := Render(c, Options{Dir: "/r"}); strings.Contains(out, "xpguard/rbl") {
		t.Error("IPDB/Tor rules while off")
	}
	if f := AddrFile([]string{"198.51.100.7/32", "bad", "198.51.100.7", "2001:db8::/32"}); f != "198.51.100.7\n2001:db8::/32\n" {
		t.Errorf("addr file %q", f)
	}
	if AddrFile(nil) != placeholderIP+"\n" {
		t.Error("empty list not loadable")
	}
}

// On a real Apache: POSTs from IPDB addresses and Tor exits are blocked,
// directly and behind a proxy; reading pages and exempt addresses pass.
func TestRBLOnApache(t *testing.T) {
	if os.Getenv("XG_DESTRUCTIVE_TESTS") != "1" || os.Geteuid() != 0 {
		t.Skip("set XG_DESTRUCTIVE_TESTS=1 (as root) to run")
	}
	tg := Detect()
	if tg.Name != "debian" || !tg.ModSec || exists(tg.IncludeFile) {
		t.Skipf("needs Debian Apache with mod_security2 and no include, detected %+v", tg)
	}
	dir := t.TempDir()
	os.Chmod(dir, 0o755)
	os.Chmod(filepath.Dir(dir), 0o755)
	t.Setenv("XG_STATE_DIR", filepath.Join(dir, "state"))
	t.Setenv("XG_CONFIG_DIR", filepath.Join(dir, "conf"))
	db, _ := store.Open()
	defer db.Close()
	st, _ := settings.Load()
	st.Patch([]byte(`{"waf":{"upload_scan":false,"tor_action":"post"}}`))
	ipdb := []string{"203.0.113.0/24"}
	exempt := []string{"203.0.113.50"}
	m := &Manager{DB: db, Settings: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), RulesDir: filepath.Join(dir, "waf"), NoSelfTest: true,
		IPDBIPs: func() []string { return ipdb }, TorIPs: func() []string { return []string{"198.51.100.66"} }, RBLExempt: func() []string { return exempt }}
	os.MkdirAll("/var/www/html", 0o755)
	os.WriteFile("/var/www/html/xg-ok.html", []byte("ok"), 0o644)
	defer os.Remove("/var/www/html/xg-ok.html")
	exec.Command("apache2ctl", "start").Run()
	defer exec.Command("apache2ctl", "stop").Run()
	defer func() {
		st.Patch([]byte(`{"waf":{"enabled":false}}`))
		m.Apply()
		exec.Command("a2disconf", "xpguard-waf").Run()
	}()
	apply := func() {
		if err := m.Apply(); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Second)
	}
	apply()
	send := func(method string, hdr ...string) int {
		c, err := net.DialTimeout("tcp", "127.0.0.1:80", 3*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		req := method + " /xg-ok.html HTTP/1.1\r\nHost: shop.example.com\r\nUser-Agent: " + browserUA + "\r\n"
		for _, h := range hdr {
			req += h + "\r\n"
		}
		if method == "POST" {
			req += "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 3\r\n"
		}
		req += "Connection: close\r\n\r\n"
		if method == "POST" {
			req += "a=1"
		}
		io.WriteString(c, req)
		line, _ := bufio.NewReader(c).ReadString('\n')
		var code int
		fmt.Sscanf(line, "HTTP/1.1 %d", &code)
		return code
	}
	check := func(what string, want bool, code int) {
		t.Helper()
		if (code == 403) != want {
			t.Errorf("%s: %d", what, code)
		}
	}
	// 127.0.0.1 is a local proxy: the real address is in the headers.
	check("POST from an IPDB address behind the proxy", true, send("POST", "X-Forwarded-For: 203.0.113.9"))
	check("GET from an IPDB address", false, send("GET", "X-Forwarded-For: 203.0.113.9"))
	check("POST from an exempt address", false, send("POST", "X-Forwarded-For: 203.0.113.50"))
	check("POST from a clean address", false, send("POST", "X-Forwarded-For: 192.0.2.10"))
	check("POST from a Tor exit behind the proxy", true, send("POST", "X-Forwarded-For: 198.51.100.66"))
	check("POST from Tor behind Cloudflare (T1)", true, send("POST", "CF-IPCountry: T1"))
	check("GET from Tor with action post", false, send("GET", "CF-IPCountry: T1"))
	check("POST without proxy headers", false, send("POST"))
	// The visitor's own address on the list.
	ipdb = []string{"127.0.0.1"}
	apply()
	check("POST from a listed address", true, send("POST"))
	exempt = []string{"127.0.0.1"}
	apply()
	check("POST from a listed but exempt address", false, send("POST"))
	// Tor: block every request.
	st.Patch([]byte(`{"waf":{"tor_action":"block","ipdb_post":false}}`))
	apply()
	check("GET from Tor with action block", true, send("GET", "CF-IPCountry: T1"))
	check("GET from a normal visitor", false, send("GET", "CF-IPCountry: PK"))
}

// apacheWith starts Apache with xPGuard's rules for the given settings and
// returns the manager and a raw request sender.
func apacheWith(t *testing.T, patch string) (*Manager, func(method, uri string, hdr ...string) int) {
	t.Helper()
	if os.Getenv("XG_DESTRUCTIVE_TESTS") != "1" || os.Geteuid() != 0 {
		t.Skip("set XG_DESTRUCTIVE_TESTS=1 (as root) to run")
	}
	tg := Detect()
	if tg.Name != "debian" || !tg.ModSec || exists(tg.IncludeFile) {
		t.Skipf("needs Debian Apache with mod_security2 and no include, detected %+v", tg)
	}
	dir := t.TempDir()
	os.Chmod(dir, 0o755)
	os.Chmod(filepath.Dir(dir), 0o755)
	t.Setenv("XG_STATE_DIR", filepath.Join(dir, "state"))
	t.Setenv("XG_CONFIG_DIR", filepath.Join(dir, "conf"))
	db, _ := store.Open()
	t.Cleanup(func() { db.Close() })
	st, _ := settings.Load()
	st.Patch([]byte(patch))
	m := &Manager{DB: db, Settings: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), RulesDir: filepath.Join(dir, "waf"), NoSelfTest: true}
	exec.Command("apache2ctl", "start").Run()
	t.Cleanup(func() {
		st.Patch([]byte(`{"waf":{"enabled":false}}`))
		m.Apply()
		exec.Command("a2disconf", "xpguard-waf").Run()
		exec.Command("apache2ctl", "stop").Run()
	})
	send := func(method, uri string, hdr ...string) int {
		c, err := net.DialTimeout("tcp", "127.0.0.1:80", 3*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		req := method + " " + uri + " HTTP/1.1\r\nHost: shop.example.com\r\nUser-Agent: " + browserUA + "\r\n"
		for _, h := range hdr {
			req += h + "\r\n"
		}
		if method == "POST" {
			req += "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 3\r\n"
		}
		req += "Connection: close\r\n\r\n"
		if method == "POST" {
			req += "a=1"
		}
		io.WriteString(c, req)
		line, _ := bufio.NewReader(c).ReadString('\n')
		var code int
		fmt.Sscanf(line, "HTTP/1.1 %d", &code)
		return code
	}
	return m, send
}

func waitApache() { time.Sleep(time.Second) }

func TestTorRuleActiveState(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XG_STATE_DIR", filepath.Join(dir, "state"))
	t.Setenv("XG_CONFIG_DIR", filepath.Join(dir, "conf"))
	db, _ := store.Open()
	defer db.Close()
	st, _ := settings.Load()
	m := &Manager{DB: db, Settings: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	state := func() (post, block bool) {
		for _, r := range m.RuleCatalog() {
			switch r.ID {
			case IDTorPost:
				post = r.Enabled
			case IDTorBlock:
				block = r.Enabled
			}
		}
		return
	}
	if p, b := state(); !p || b {
		t.Errorf("action post: %v %v", p, b)
	}
	st.Patch([]byte(`{"waf":{"tor_action":"block"}}`))
	if p, b := state(); p || !b {
		t.Errorf("action block: %v %v", p, b)
	}
}

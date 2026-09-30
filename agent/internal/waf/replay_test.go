package waf

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/settings"
	"github.com/xmarthost/xmartguard/agent/internal/store"
)

// Replays the requests of a WAF Logs export on a real Apache with our rules
// and reports, per rule of the export, how many our rules block.
// XG_REPLAY_CSV=<export> XG_DESTRUCTIVE_TESTS=1 go test -run TestReplay -v
func TestReplay(t *testing.T) {
	path := os.Getenv("XG_REPLAY_CSV")
	if path == "" || os.Getenv("XG_DESTRUCTIVE_TESTS") != "1" || os.Geteuid() != 0 {
		t.Skip("set XG_REPLAY_CSV and XG_DESTRUCTIVE_TESTS=1 (as root)")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	recs, err := csv.NewReader(f).ReadAll()
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	os.Chmod(dir, 0o755)
	os.Chmod(filepath.Dir(dir), 0o755)
	t.Setenv("XG_STATE_DIR", filepath.Join(dir, "state"))
	t.Setenv("XG_CONFIG_DIR", filepath.Join(dir, "conf"))
	db, _ := store.Open()
	defer db.Close()
	st, _ := settings.Load()
	st.Patch([]byte(`{"waf":{"upload_scan":false}}`))
	if p := os.Getenv("XG_REPLAY_PATCH"); p != "" {
		st.Patch([]byte(p))
	}
	m := &Manager{DB: db, Settings: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), RulesDir: filepath.Join(dir, "waf"), NoSelfTest: true}
	exec.Command("apache2ctl", "start").Run()
	defer exec.Command("apache2ctl", "stop").Run()
	defer func() {
		st.Patch([]byte(`{"waf":{"enabled":false}}`))
		m.Apply()
		exec.Command("a2disconf", "xpguard-waf").Run()
	}()
	if err := m.Apply(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second)

	send := func(uri, host string, ua bool) int {
		c, err := net.DialTimeout("tcp", "127.0.0.1:80", 3*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		req := "GET " + uri + " HTTP/1.1\r\nHost: " + host + "\r\n"
		if ua {
			req += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36\r\nReferer: https://" + host + "/\r\nAccept: text/html\r\n"
		}
		req += "Connection: close\r\n\r\n"
		io.WriteString(c, req)
		line, _ := bufio.NewReader(c).ReadString('\n')
		var code int
		fmt.Sscanf(line, "HTTP/1.1 %d", &code)
		return code
	}
	type res struct {
		n, bare, full int
		miss          []string
	}
	byRule := map[string]*res{}
	seen := map[string][2]bool{}
	for _, r := range recs[1:] {
		id, uri, host, reason := r[0], r[3], r[4], r[6]
		if !strings.Contains(reason, "Malware.Expert") && !strings.HasPrefix(id, "400") {
			continue
		}
		if uri == "" || strings.ContainsAny(uri, " \r\n") {
			continue
		}
		key := id + " " + reason
		if byRule[key] == nil {
			byRule[key] = &res{}
		}
		x := byRule[key]
		x.n++
		v, ok := seen[uri]
		if !ok {
			v = [2]bool{send(uri, host, false) == 403, send(uri, host, true) == 403}
			seen[uri] = v
		}
		if v[0] {
			x.bare++
		}
		if v[1] {
			x.full++
		} else if len(x.miss) < 6 && !contains(x.miss, uri) {
			x.miss = append(x.miss, uri)
		}
	}
	keys := make([]string, 0, len(byRule))
	for k := range byRule {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return byRule[keys[i]].n > byRule[keys[j]].n })
	var tot, tb, tf int
	for _, k := range keys {
		x := byRule[k]
		tot, tb, tf = tot+x.n, tb+x.bare, tf+x.full
		fmt.Printf("%4d  bare %3d%%  browser %3d%%  %s\n", x.n, 100*x.bare/x.n, 100*x.full/x.n, k)
		for _, u := range x.miss {
			fmt.Printf("        miss %s\n", u)
		}
	}
	fmt.Printf("TOTAL %d  bare %d (%d%%)  browser %d (%d%%)\n", tot, tb, 100*tb/tot, tf, 100*tf/tot)
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

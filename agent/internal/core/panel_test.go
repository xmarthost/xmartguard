package core

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/config"
	"github.com/xmarthost/xmartguard/agent/internal/local"
)

// When re-executed as another user, the test binary acts as a socket client.
func TestMain(m *testing.M) {
	if req := os.Getenv("XG_HELPER_CALL"); req != "" {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		data, err := local.CallRaw(ctx, []byte(req))
		resp := local.Response{OK: err == nil, Data: data}
		if err != nil {
			resp.Error = err.Error()
		}
		json.NewEncoder(os.Stdout).Encode(resp)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func mkUser(t *testing.T, name string) *user.User {
	t.Helper()
	exec.Command("userdel", "-r", name).Run()
	if out, err := exec.Command("useradd", "-m", "-d", "/home/"+name, name).CombinedOutput(); err != nil {
		t.Skipf("useradd: %v %s", err, out)
	}
	t.Cleanup(func() { exec.Command("userdel", "-r", name).Run() })
	u, err := user.Lookup(name)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestPanelSocketIsolatesAccounts(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if _, err := exec.LookPath("useradd"); err != nil {
		t.Skip("no useradd")
	}
	dir := t.TempDir()
	os.Chmod(dir, 0o755)
	os.Chmod(filepath.Dir(dir), 0o755)
	t.Setenv("XG_STATE_DIR", filepath.Join(dir, "state"))
	t.Setenv("XG_CONFIG_DIR", filepath.Join(dir, "conf"))
	t.Setenv("XG_SOCKET", filepath.Join(dir, "run", "agent.sock"))
	os.MkdirAll(filepath.Join(dir, "conf"), 0o700)
	os.WriteFile(filepath.Join(dir, "conf", "settings.json"), []byte(`{"firewall":{"enabled":false},"scanner":{"realtime":false}}`), 0o600)

	alice, bob := mkUser(t, "xgpanela"), mkUser(t, "xgpanelb")
	shell := strings.Join([]string{"<?php sys", "tem($_GET['c']); ?>"}, "")
	for _, u := range []*user.User{alice, bob} {
		web := filepath.Join(u.HomeDir, "public_html")
		os.MkdirAll(web, 0o755)
		os.WriteFile(filepath.Join(web, "shell.php"), []byte(shell), 0o644)
		os.WriteFile(filepath.Join(web, "index.php"), []byte("<?php echo 'hi';"), 0o644)
		uid, _ := strconv.Atoi(u.Uid)
		gid, _ := strconv.Atoi(u.Gid)
		filepath.Walk(u.HomeDir, func(p string, _ os.FileInfo, _ error) error { return os.Chown(p, uid, gid) })
	}

	a, err := New(&config.Config{ServerURL: "https://portal.example", ServerID: "x"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer a.DB.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.LocalServer().Run(ctx)
	time.Sleep(300 * time.Millisecond)

	helper := filepath.Join(dir, "helper")
	if b, err := os.ReadFile(os.Args[0]); err == nil {
		os.WriteFile(helper, b, 0o755)
	}
	as := func(u *user.User, action string, params any) local.Response {
		t.Helper()
		req, _ := json.Marshal(map[string]any{"action": action, "params": params})
		cmd := exec.Command(helper)
		cmd.Env = append(os.Environ(), "XG_HELPER_CALL="+string(req))
		if u != nil {
			uid, _ := strconv.Atoi(u.Uid)
			gid, _ := strconv.Atoi(u.Gid)
			cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}}
		}
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("helper %s: %v %s", action, err, out)
		}
		var r local.Response
		if err := json.Unmarshal(out, &r); err != nil {
			t.Fatalf("bad helper output %q", out)
		}
		return r
	}

	// Alice scans her website.
	r := as(alice, "overview", nil)
	if !r.OK || !strings.Contains(string(r.Data), `"user":"xgpanela"`) {
		t.Fatalf("overview: %+v %s", r, r.Data)
	}
	if r := as(alice, "scan.start", map[string]any{}); !r.OK {
		t.Fatalf("scan: %+v", r)
	}
	var findings struct {
		Findings []struct {
			ID   int64
			Path string
		}
		Total int
	}
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		r = as(alice, "findings.list", map[string]any{})
		json.Unmarshal(r.Data, &findings)
		if findings.Total > 0 {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if findings.Total != 1 || findings.Findings[0].Path != filepath.Join(alice.HomeDir, "public_html/shell.php") {
		t.Fatalf("alice findings: %+v", findings)
	}
	aliceFinding := findings.Findings[0].ID

	// Alice cannot scan Bob's home, nor act on his files; she cannot use admin commands.
	if r := as(alice, "scan.start", map[string]any{"path": bob.HomeDir}); r.OK || !strings.Contains(r.Error, "only scan files inside") {
		t.Fatalf("cross-account scan allowed: %+v", r)
	}
	if r := as(alice, "scan.start", map[string]any{"path": "../xgpanelb"}); r.OK {
		t.Fatalf("relative escape allowed: %+v", r)
	}
	os.Symlink(bob.HomeDir, filepath.Join(alice.HomeDir, "bob"))
	if r := as(alice, "scan.start", map[string]any{"path": "bob"}); r.OK {
		t.Fatalf("symlink escape allowed: %+v", r)
	}
	for _, act := range []string{"fw.add", "settings.set", "fw.events", "agent.update"} {
		if r := as(alice, act, map[string]any{}); r.OK || !strings.Contains(r.Error, "unknown action") {
			t.Fatalf("%s allowed for a user: %+v", act, r)
		}
	}

	// Root sees and scans everything; Bob's finding is invisible to Alice.
	if r := as(nil, "scan.start", map[string]any{"kind": "path", "path": filepath.Join(bob.HomeDir, "public_html")}); !r.OK {
		t.Fatalf("root scan: %+v", r)
	}
	var all struct {
		Findings []struct {
			ID   int64
			Path string
		}
		Total int
	}
	deadline = time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		json.Unmarshal(as(nil, "findings.list", map[string]any{}).Data, &all)
		if all.Total >= 2 {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if all.Total != 2 {
		t.Fatalf("root findings: %+v", all)
	}
	var bobFinding int64
	for _, f := range all.Findings {
		if strings.HasPrefix(f.Path, bob.HomeDir) {
			bobFinding = f.ID
		}
	}
	r = as(alice, "finding.action", map[string]any{"ids": []int64{bobFinding}, "action": "delete"})
	if !strings.Contains(string(r.Data), `"done":0`) {
		t.Fatalf("alice acted on bob's file: %+v %s", r, r.Data)
	}
	if _, err := os.Stat(filepath.Join(bob.HomeDir, "public_html/shell.php")); err != nil {
		t.Fatal("bob's file was touched")
	}
	// Alice quarantines and restores her own file.
	r = as(alice, "finding.action", map[string]any{"ids": []int64{aliceFinding}, "action": "quarantine"})
	if !strings.Contains(string(r.Data), `"done":1`) {
		t.Fatalf("quarantine: %+v %s", r, r.Data)
	}
	if _, err := os.Stat(filepath.Join(alice.HomeDir, "public_html/shell.php")); !os.IsNotExist(err) {
		t.Fatal("file still in place after quarantine")
	}
	// A system account with no hosting account gets nothing.
	nobody, err := user.Lookup("nobody")
	if err == nil {
		if r := as(nobody, "overview", nil); r.OK || !strings.Contains(r.Error, "cannot use") {
			t.Fatalf("nobody: %+v", r)
		}
	}
}

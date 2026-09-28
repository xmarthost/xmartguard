package hostfw

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeCSF simulates csf -a / -ar on files under root; other tools are absent.
func fakeHost(t *testing.T) (*Host, *[]string) {
	root := t.TempDir()
	for _, f := range []string{"/etc/csf/csf.conf", "/usr/sbin/csf", "/etc/csf/csf.allow", "/etc/csf/csf.ignore"} {
		os.MkdirAll(filepath.Dir(root+f), 0o755)
		os.WriteFile(root+f, nil, 0o600)
	}
	var calls []string
	h := &Host{Root: root, State: filepath.Join(root, "state.json")}
	h.Run = func(_ context.Context, name string, args ...string) (string, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		if name == "/usr/sbin/csf" && len(args) >= 2 && args[0] == "-a" {
			f, _ := os.OpenFile(root+"/etc/csf/csf.allow", os.O_APPEND|os.O_WRONLY, 0o600)
			f.WriteString(args[1] + " # " + args[2] + " - Mon Sep 28\n")
			f.Close()
		}
		return "", os.ErrNotExist // every other tool reports "not running"
	}
	for _, tl := range DefaultTools() {
		if tl.Name == "csf" || tl.Name == "firewalld" {
			h.Tools = append(h.Tools, tl)
		}
	}
	// firewalld Present fails because Run returns an error for firewall-cmd.
	h.Run = wrapCSFOK(h.Run)
	return h, &calls
}

// wrapCSFOK makes csf commands succeed.
func wrapCSFOK(r Runner) Runner {
	return func(ctx context.Context, name string, args ...string) (string, error) {
		out, err := r(ctx, name, args...)
		if name == "/usr/sbin/csf" {
			return out, nil
		}
		return out, err
	}
}

func TestSyncCSF(t *testing.T) {
	h, calls := fakeHost(t)
	res := h.Sync([]string{"162.55.6.159", "127.0.0.1"})
	var csf Result
	for _, r := range res {
		if r.Tool == "csf" {
			csf = r
		}
		if r.Tool == "firewalld" && r.Present {
			t.Fatal("firewalld should be absent")
		}
	}
	if !csf.Present || len(csf.Allowed) != 1 || csf.Allowed[0] != "162.55.6.159" {
		t.Fatalf("csf result: %+v", csf)
	}
	allow, _ := os.ReadFile(h.Root + "/etc/csf/csf.allow")
	ignore, _ := os.ReadFile(h.Root + "/etc/csf/csf.ignore")
	if !strings.Contains(string(allow), "162.55.6.159 # xPGuard portal") || !strings.Contains(string(ignore), "162.55.6.159 # xPGuard portal") {
		t.Fatalf("allow=%q ignore=%q", allow, ignore)
	}
	// Second sync: nothing to do.
	n := len(*calls)
	h.Sync([]string{"162.55.6.159"})
	for _, c := range (*calls)[n:] {
		if strings.Contains(c, " -a ") {
			t.Fatalf("re-added: %s", c)
		}
	}
	// Portal moved: old address withdrawn, new one added.
	h.Sync([]string{"203.0.113.9"})
	allow, _ = os.ReadFile(h.Root + "/etc/csf/csf.allow")
	if strings.Contains(string(allow), "162.55.6.159") || !strings.Contains(string(allow), "203.0.113.9") {
		t.Fatalf("after move: %q", allow)
	}
	if h.RemoveAll() != 1 {
		t.Fatal("RemoveAll should withdraw one entry")
	}
	allow, _ = os.ReadFile(h.Root + "/etc/csf/csf.allow")
	ignore, _ = os.ReadFile(h.Root + "/etc/csf/csf.ignore")
	if strings.TrimSpace(string(allow)+string(ignore)) != "" {
		t.Fatalf("left behind: %q %q", allow, ignore)
	}
}

func TestAdminEntryKept(t *testing.T) {
	h, _ := fakeHost(t)
	os.WriteFile(h.Root+"/etc/csf/csf.allow", []byte("162.55.6.159 # my portal\n"), 0o600)
	os.WriteFile(h.Root+"/etc/csf/csf.ignore", []byte("162.55.6.159\n"), 0o600)
	h.Sync([]string{"162.55.6.159"})
	h.RemoveAll()
	allow, _ := os.ReadFile(h.Root + "/etc/csf/csf.allow")
	if !strings.Contains(string(allow), "# my portal") {
		t.Fatalf("admin entry removed: %q", allow)
	}
}

func TestLegacyCommentRenamed(t *testing.T) {
	h, _ := fakeHost(t)
	allow := h.Root + "/etc/csf/csf.allow"
	_ = os.WriteFile(allow, []byte("1.2.3.4 # admin\n162.55.6.159 # XMart Guard portal\n"), 0o600)
	h.renameLegacy("/etc/csf/csf.allow")
	b, _ := os.ReadFile(allow)
	if strings.Contains(string(b), "XMart") || !strings.Contains(string(b), "162.55.6.159 # xPGuard portal") || !strings.Contains(string(b), "1.2.3.4 # admin") {
		t.Fatalf("%s", b)
	}
	if !h.hasOurLine("/etc/csf/csf.allow", "162.55.6.159") {
		t.Fatal("renamed line not ours")
	}
	_ = os.WriteFile(allow, []byte("162.55.6.159 # XMart Guard portal\n"), 0o600)
	if !h.hasOurLine("/etc/csf/csf.allow", "162.55.6.159") {
		t.Fatal("legacy line not recognised")
	}
}

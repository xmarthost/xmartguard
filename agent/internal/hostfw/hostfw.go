// Package hostfw keeps the xPGuard portal reachable through the other
// firewalls a server may run (CSF/LFD, firewalld, UFW, APF, cPHulk,
// Imunify360). The agent only talks to the portal outbound, but a deny list
// or an automatic ban of the portal's address would still cut the link, so
// the portal's addresses are allowed in every firewall found.
//
// Only entries this package added are recorded (state file) and removed
// again, so an administrator's own allow entries are never touched.
package hostfw

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Comment marks every entry xPGuard adds.
const Comment = "xPGuard portal"

// legacyComment marked the entries of versions before the xPGuard name;
// they are still recognised as ours (and replaced or removed).
const legacyComment = "XMart Guard portal"

func ownComment(line string) bool {
	return strings.Contains(line, Comment) || strings.Contains(line, legacyComment)
}

// Runner runs a command (replaced in tests).
type Runner func(ctx context.Context, name string, args ...string) (string, error)

func execRunner(ctx context.Context, name string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err
}

// Tool is one firewall integration.
type Tool struct {
	Name string
	// Present reports whether the firewall is installed and active.
	Present func(h *Host) bool
	// Has reports whether ip is already allowed (by anyone); nil = unknown.
	Has    func(h *Host, ip string) bool
	Allow  func(h *Host, ip string) error
	Remove func(h *Host, ip string) error
}

// Entry is an allow entry this package added.
type Entry struct {
	Tool  string `json:"tool"`
	IP    string `json:"ip"`
	Added int64  `json:"added"`
}

// Host holds the environment (paths and command runner are overridable).
type Host struct {
	Root  string // prefix for config files ("" = /)
	Run   Runner
	State string // state file
	Tools []Tool

	mu sync.Mutex
}

// New returns a Host for the real system.
func New(stateFile string) *Host {
	return &Host{Run: execRunner, State: stateFile, Tools: DefaultTools()}
}

func (h *Host) path(p string) string { return filepath.Join(h.Root, p) }

func (h *Host) exists(p string) bool {
	_, err := os.Stat(h.path(p))
	return err == nil
}

func (h *Host) run(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	return h.Run(ctx, name, args...)
}

// fileHasIP reports whether a CSF/APF style list file allows ip on a line
// of its own ("1.2.3.4", "1.2.3.4 # note", "tcp|in|d=22|s=1.2.3.4" is not
// counted: that only opens one port).
func (h *Host) fileHasIP(file, ip string) bool {
	f, err := os.Open(h.path(file))
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == ip {
			return true
		}
	}
	return false
}

// appendLine adds "ip # Comment" to a list file.
func (h *Host) appendLine(file, ip string) error {
	f, err := os.OpenFile(h.path(file), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(ip + " # " + Comment + "\n")
	return err
}

// hasOurLine reports whether file has a line this package wrote for ip.
func (h *Host) hasOurLine(file, ip string) bool {
	b, err := os.ReadFile(h.path(file))
	if err != nil {
		return false
	}
	for _, l := range strings.Split(string(b), "\n") {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, ip+" ") && ownComment(t) {
			return true
		}
	}
	return false
}

// renameLegacy rewrites "# XMart Guard portal" comments to the current one.
func (h *Host) renameLegacy(file string) {
	p := h.path(file)
	b, err := os.ReadFile(p)
	if err != nil || !strings.Contains(string(b), legacyComment) {
		return
	}
	_ = os.WriteFile(p, []byte(strings.ReplaceAll(string(b), "# "+legacyComment, "# "+Comment)), 0o600)
}

// removeLine deletes the lines this package wrote for ip.
func (h *Host) removeLine(file, ip string) error {
	p := h.path(file)
	b, err := os.ReadFile(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	var out []string
	for _, l := range strings.SplitAfter(string(b), "\n") {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, ip+" ") && ownComment(t) {
			continue
		}
		out = append(out, l)
	}
	return os.WriteFile(p, []byte(strings.Join(out, "")), 0o600)
}

// DefaultTools lists the supported firewalls.
func DefaultTools() []Tool {
	return []Tool{
		{
			// CSF: csf.allow (never blocked, even when listed in csf.deny) and
			// csf.ignore (LFD never bans it).
			Name:    "csf",
			Present: func(h *Host) bool { return h.exists("/etc/csf/csf.conf") && h.exists("/usr/sbin/csf") },
			Has: func(h *Host, ip string) bool {
				return h.fileHasIP("/etc/csf/csf.allow", ip) && h.fileHasIP("/etc/csf/csf.ignore", ip)
			},
			Allow: func(h *Host, ip string) error {
				if !h.fileHasIP("/etc/csf/csf.allow", ip) {
					// csf -a writes csf.allow and loads the rule at once.
					if out, err := h.run("/usr/sbin/csf", "-a", ip, Comment); err != nil {
						return errors.New(strings.TrimSpace(out))
					}
				}
				if !h.fileHasIP("/etc/csf/csf.ignore", ip) {
					if err := h.appendLine("/etc/csf/csf.ignore", ip); err != nil {
						return err
					}
					_, _ = h.run("/usr/sbin/csf", "--lfd", "restart")
				}
				return nil
			},
			Remove: func(h *Host, ip string) error {
				// Only our own lines: an administrator's entry for the same
				// address stays.
				if h.hasOurLine("/etc/csf/csf.allow", ip) {
					_, _ = h.run("/usr/sbin/csf", "-ar", ip)
					_ = h.removeLine("/etc/csf/csf.allow", ip)
				}
				if h.hasOurLine("/etc/csf/csf.ignore", ip) {
					if err := h.removeLine("/etc/csf/csf.ignore", ip); err != nil {
						return err
					}
					_, _ = h.run("/usr/sbin/csf", "--lfd", "restart")
				}
				return nil
			},
		},
		{
			Name: "firewalld",
			Present: func(h *Host) bool {
				out, err := h.run("firewall-cmd", "--state")
				return err == nil && strings.TrimSpace(out) == "running"
			},
			Has: func(h *Host, ip string) bool {
				out, _ := h.run("firewall-cmd", "--zone=trusted", "--list-sources")
				return containsField(out, ip)
			},
			Allow: func(h *Host, ip string) error {
				if out, err := h.run("firewall-cmd", "--permanent", "--zone=trusted", "--add-source="+ip); err != nil {
					return errors.New(strings.TrimSpace(out))
				}
				_, err := h.run("firewall-cmd", "--zone=trusted", "--add-source="+ip)
				return err
			},
			Remove: func(h *Host, ip string) error {
				_, _ = h.run("firewall-cmd", "--permanent", "--zone=trusted", "--remove-source="+ip)
				_, err := h.run("firewall-cmd", "--zone=trusted", "--remove-source="+ip)
				return err
			},
		},
		{
			Name: "ufw",
			Present: func(h *Host) bool {
				out, err := h.run("ufw", "status")
				return err == nil && strings.Contains(out, "Status: active")
			},
			Allow: func(h *Host, ip string) error {
				out, err := h.run("ufw", "allow", "from", ip, "comment", Comment)
				if err != nil {
					return errors.New(strings.TrimSpace(out))
				}
				return nil
			},
			Remove: func(h *Host, ip string) error {
				_, err := h.run("ufw", "delete", "allow", "from", ip)
				return err
			},
		},
		{
			Name:    "apf",
			Present: func(h *Host) bool { return h.exists("/etc/apf/allow_hosts.rules") && h.exists("/usr/local/sbin/apf") },
			Has:     func(h *Host, ip string) bool { return h.fileHasIP("/etc/apf/allow_hosts.rules", ip) },
			Allow: func(h *Host, ip string) error {
				out, err := h.run("/usr/local/sbin/apf", "-a", ip, Comment)
				if err != nil {
					return errors.New(strings.TrimSpace(out))
				}
				return nil
			},
			Remove: func(h *Host, ip string) error {
				_, err := h.run("/usr/local/sbin/apf", "-u", ip)
				return err
			},
		},
		{
			// cPHulk only guards logins, but a whitelisted portal can never be
			// caught in a cPHulk IP block.
			Name: "cphulk",
			Present: func(h *Host) bool {
				return h.exists("/usr/local/cpanel/bin/whmapi1") && h.exists("/var/cpanel/hulkd/enabled")
			},
			Allow: func(h *Host, ip string) error {
				out, err := h.run("/usr/local/cpanel/bin/whmapi1", "create_cphulk_record", "list_name=white", "ip="+ip, "comment="+Comment)
				if err != nil {
					return errors.New(strings.TrimSpace(out))
				}
				return nil
			},
			Remove: func(h *Host, ip string) error {
				_, err := h.run("/usr/local/cpanel/bin/whmapi1", "delete_cphulk_record", "list_name=white", "ip="+ip)
				return err
			},
		},
		{
			Name: "imunify360",
			Present: func(h *Host) bool {
				_, err := exec.LookPath("imunify360-agent")
				return err == nil || h.exists("/usr/bin/imunify360-agent")
			},
			Allow: func(h *Host, ip string) error {
				out, err := h.run("imunify360-agent", "whitelist", "ip", "add", ip, "--comment", Comment)
				if err != nil {
					return errors.New(strings.TrimSpace(out))
				}
				return nil
			},
			Remove: func(h *Host, ip string) error {
				_, err := h.run("imunify360-agent", "whitelist", "ip", "delete", ip)
				return err
			},
		},
	}
}

func containsField(out, ip string) bool {
	for _, f := range strings.Fields(out) {
		if f == ip {
			return true
		}
	}
	return false
}

func (h *Host) load() []Entry {
	var e []Entry
	if b, err := os.ReadFile(h.State); err == nil {
		_ = json.Unmarshal(b, &e)
	}
	return e
}

func (h *Host) save(e []Entry) error {
	sort.Slice(e, func(i, j int) bool { return e[i].Tool+e[i].IP < e[j].Tool+e[j].IP })
	b, _ := json.MarshalIndent(e, "", "  ")
	if err := os.MkdirAll(filepath.Dir(h.State), 0o700); err != nil {
		return err
	}
	return os.WriteFile(h.State, b, 0o600)
}

// Result reports one firewall's state for the portal.
type Result struct {
	Tool    string   `json:"tool"`
	Present bool     `json:"present"`
	Allowed []string `json:"allowed"`
	Error   string   `json:"error,omitempty"`
}

// Sync allows ips in every firewall found and withdraws entries this
// package added for addresses that are no longer the portal's.
func (h *Host) Sync(ips []string) []Result {
	h.mu.Lock()
	defer h.mu.Unlock()
	want := map[string]bool{}
	for _, ip := range ips {
		if p := net.ParseIP(ip); p != nil && !p.IsLoopback() && !p.IsUnspecified() {
			want[p.String()] = true
		}
	}
	// Lines written under the old product name get the current comment.
	for _, f := range []string{"/etc/csf/csf.allow", "/etc/csf/csf.ignore"} {
		h.renameLegacy(f)
	}
	state := h.load()
	mine := map[string]bool{}
	for _, e := range state {
		mine[e.Tool+" "+e.IP] = true
	}
	var keep []Entry
	var res []Result
	for _, t := range h.Tools {
		r := Result{Tool: t.Name, Allowed: []string{}}
		r.Present = t.Present(h)
		for _, e := range state {
			if e.Tool != t.Name {
				continue
			}
			if want[e.IP] && r.Present {
				keep = append(keep, e)
				r.Allowed = append(r.Allowed, e.IP)
				continue
			}
			if r.Present {
				_ = t.Remove(h, e.IP)
			}
		}
		if !r.Present {
			res = append(res, r)
			continue
		}
		for ip := range want {
			if mine[t.Name+" "+ip] {
				continue
			}
			if t.Has != nil && t.Has(h, ip) {
				r.Allowed = append(r.Allowed, ip) // allowed by the administrator already
				continue
			}
			if err := t.Allow(h, ip); err != nil {
				r.Error = err.Error()
				continue
			}
			keep = append(keep, Entry{Tool: t.Name, IP: ip, Added: time.Now().Unix()})
			r.Allowed = append(r.Allowed, ip)
		}
		sort.Strings(r.Allowed)
		res = append(res, r)
	}
	_ = h.save(keep)
	return res
}

// RemoveAll withdraws every entry this package added (uninstall).
func (h *Host) RemoveAll() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, e := range h.load() {
		for _, t := range h.Tools {
			if t.Name == e.Tool && t.Present(h) {
				if t.Remove(h, e.IP) == nil {
					n++
				}
			}
		}
	}
	_ = os.Remove(h.State)
	return n
}

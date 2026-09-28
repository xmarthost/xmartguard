package firewall

import (
	"bufio"
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// CSF (ConfigServer Security & Firewall) compatibility.
//
// When CSF is active the two firewalls share the work:
//   - CSF keeps the port filter (TCP_IN/TCP_OUT...); ours is not loaded so a
//     port open in CSF is never closed by xPGuard.
//   - Addresses in csf.allow and csf.ignore are exempt from xPGuard's
//     blocks (IPDB, bans, country blocks), as they are in CSF.
//   - csfpost.sh reloads our rules right after `csf -r` flushes iptables.
//   - LFD ignores the agent process (csf.pignore, set by the installer).

// csfRoot prefixes CSF paths (tests).
var csfRoot = ""

const (
	csfConf    = "/etc/csf/csf.conf"
	csfDisable = "/etc/csf/csf.disable"
	csfAllow   = "/etc/csf/csf.allow"
	csfIgnore  = "/etc/csf/csf.ignore"
	csfPost    = "/usr/local/csf/bin/csfpost.sh"
	csfHookTag = "# xPGuard: reload rules after csf -r"
	// legacyHookTag is the hook line of versions before the xPGuard name.
	legacyHookTag = "# XMart Guard: reload rules after csf -r"
)

// AgentBinary is the command csfpost.sh calls.
var AgentBinary = "/opt/xpguard/bin/xpguard-agent"

func csfPath(p string) string { return filepath.Join(csfRoot, p) }

// CSFInfo describes CSF on this server.
type CSFInfo struct {
	Installed bool `json:"installed"`
	Enabled   bool `json:"enabled"` // installed and not disabled with csf -x
	Testing   bool `json:"testing"` // TESTING = "1": CSF flushes its rules every few minutes
	// Exempt is the number of csf.allow/csf.ignore addresses our blocks skip.
	Exempt int  `json:"exempt"`
	Hook   bool `json:"hook"` // csfpost.sh reloads our rules
	// PortFilter reports that CSF, not xPGuard, filters ports.
	PortFilter bool `json:"port_filter"`
}

// DetectCSF reads CSF's state.
func DetectCSF() CSFInfo {
	var c CSFInfo
	b, err := os.ReadFile(csfPath(csfConf))
	if err != nil {
		return c
	}
	c.Installed = true
	_, disabled := os.Stat(csfPath(csfDisable))
	c.Enabled = disabled != nil
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if k, v, ok := strings.Cut(l, "="); ok && strings.TrimSpace(k) == "TESTING" {
			c.Testing = strings.Trim(strings.TrimSpace(v), `"'`) == "1"
		}
	}
	if hb, err := os.ReadFile(csfPath(csfPost)); err == nil {
		c.Hook = strings.Contains(string(hb), csfHookTag) || strings.Contains(string(hb), legacyHookTag)
	}
	c.PortFilter = c.Enabled
	return c
}

// CSFExempt returns the plain addresses and CIDRs in csf.allow and
// csf.ignore (including their Include files). Port-specific entries such
// as "tcp|in|d=22|s=1.2.3.4" only open one port and are not included.
func CSFExempt() []string {
	seen := map[string]bool{}
	var out []string
	var read func(p string, depth int)
	read = func(p string, depth int) {
		f, err := os.Open(csfPath(p))
		if err != nil {
			return
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			l := strings.TrimSpace(sc.Text())
			if i := strings.IndexByte(l, '#'); i >= 0 {
				l = strings.TrimSpace(l[:i])
			}
			if l == "" {
				continue
			}
			if strings.HasPrefix(l, "Include ") {
				if depth < 2 {
					read(strings.TrimSpace(strings.TrimPrefix(l, "Include ")), depth+1)
				}
				continue
			}
			f := strings.Fields(l)[0]
			if ip := net.ParseIP(f); ip != nil {
				f = ip.String()
			} else if _, n, err := net.ParseCIDR(f); err == nil {
				f = n.String()
			} else {
				continue
			}
			if !seen[f] {
				seen[f] = true
				out = append(out, f)
			}
		}
	}
	read(csfAllow, 0)
	read(csfIgnore, 0)
	return out
}

func hookLine() string {
	return "(sleep 3; " + AgentBinary + " call fw.apply) >/dev/null 2>&1 & " + csfHookTag
}

// EnsureCSFHook makes csfpost.sh reload xPGuard's rules after CSF
// restarts. An existing csfpost.sh is kept; one line is added.
func EnsureCSFHook() error {
	p := csfPath(csfPost)
	b, err := os.ReadFile(p)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if strings.Contains(string(b), hookLine()) {
		return nil
	}
	// Replace our line of another version (older program path or name).
	b = []byte(dropLines(string(b), csfHookTag))
	// Replace the hook line of an older version.
	s := dropLines(string(b), legacyHookTag)
	if s == "" {
		s = "#!/bin/sh\n"
	} else if !strings.HasSuffix(s, "\n") {
		s += "\n"
	}
	s += hookLine() + "\n"
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	return os.WriteFile(p, []byte(s), 0o700)
}

// RemoveCSFHook takes our line out of csfpost.sh (and removes a file that
// only held it).
func RemoveCSFHook() {
	p := csfPath(csfPost)
	b, err := os.ReadFile(p)
	if err != nil || (!strings.Contains(string(b), csfHookTag) && !strings.Contains(string(b), legacyHookTag)) {
		return
	}
	rest := strings.TrimSpace(dropLines(dropLines(string(b), csfHookTag), legacyHookTag))
	if rest == "" || rest == "#!/bin/sh" || rest == "#!/bin/bash" {
		_ = os.Remove(p)
		return
	}
	_ = os.WriteFile(p, []byte(rest+"\n"), 0o700)
}

// CSF returns CSF's state for the portal.
func (m *Manager) CSF() CSFInfo {
	c := DetectCSF()
	if c.Enabled {
		c.Exempt = len(CSFExempt())
	}
	return c
}

// csfGateComment marks the rules that open the CAPTCHA ports under CSF.
const csfGateComment = "xpguard-captcha"

// legacyGateComment marked the same rules before the xPGuard name.
const legacyGateComment = "xmartguard-captcha"

// syncCSFGatePorts opens the CAPTCHA server's ports in front of CSF's own
// chains while the login-page CAPTCHA is on (CSF keeps the port filter, so
// the ports would otherwise be closed), and removes the rules when it is off.
// csfpost.sh runs fw.apply after `csf -r`, which calls this again.
var syncCSFGatePorts = func(ports []int) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for _, bin := range []string{"iptables", "ip6tables"} {
		if _, err := exec.LookPath(bin); err != nil {
			continue
		}
		// Remove ours first (also any with old ports), then add the current ones.
		out, _ := run(ctx, "", bin, "-w", "-S", "INPUT")
		for _, l := range strings.Split(string(out), "\n") {
			if !(strings.Contains(l, csfGateComment) || strings.Contains(l, legacyGateComment)) || !strings.HasPrefix(l, "-A INPUT ") {
				continue
			}
			args := append([]string{"-w", "-D", "INPUT"}, splitRule(strings.TrimPrefix(l, "-A INPUT "))...)
			_, _ = run(ctx, "", bin, args...)
		}
		if len(ports) == 0 {
			continue
		}
		var ps []string
		for _, p := range ports {
			ps = append(ps, strconv.Itoa(p))
		}
		_, _ = run(ctx, "", bin, "-w", "-I", "INPUT", "1", "-p", "tcp", "-m", "multiport", "--dports", strings.Join(ps, ","),
			"-m", "comment", "--comment", csfGateComment, "-j", "ACCEPT")
	}
}

// splitRule splits an iptables -S rule, keeping quoted words together.
func splitRule(s string) []string {
	var out []string
	var cur strings.Builder
	quoted := false
	for _, r := range s {
		switch {
		case r == '"':
			quoted = !quoted
		case r == ' ' && !quoted:
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// dropLines removes the lines containing tag.
func dropLines(s, tag string) string {
	if !strings.Contains(s, tag) {
		return s
	}
	var keep []string
	for _, l := range strings.Split(s, "\n") {
		if !strings.Contains(l, tag) {
			keep = append(keep, l)
		}
	}
	return strings.Join(keep, "\n")
}

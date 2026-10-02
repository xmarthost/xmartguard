package core

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/xmarthost/xmartguard/agent/internal/scanner"
)

// onReinfection is called when a quarantined file keeps being written
// again (the 3rd return, then every thousandth). Quarantine alone cannot
// stop that: something of the account writes it — a running process, a
// cron job, or (on WordPress) a malicious plugin, theme or database entry
// that re-creates it on page loads. The alert says what to look at.
func (a *Agent) onReinfection(f scanner.Finding) {
	hints := reinfectionHints(f.Owner, f.Path)
	a.Log.Warn("quarantined file keeps coming back", "path", f.Path, "times", f.Repeats, "owner", f.Owner)
	n := a.Settings.Get().Notifications
	if n.OnVirus || n.OnSuspicious {
		a.alertAdmin("malware keeps coming back",
			fmt.Sprintf("%s was quarantined and written again %d times (owner %s, %s).\n"+
				"Something in the account re-creates it; quarantining the file again does not stop that.\n\n%s",
				f.Path, f.Repeats, f.Owner, f.Signature, hints))
	}
}

// reinfectionHints lists where a re-created file most likely comes from.
func reinfectionHints(owner, path string) string {
	var b strings.Builder
	if owner == "" || owner == "root" {
		return ""
	}
	uid := -1
	if u, err := user.Lookup(owner); err == nil {
		uid, _ = strconv.Atoi(u.Uid)
	}
	if procs := userProcesses(uid); len(procs) > 0 {
		b.WriteString("Processes of " + owner + " now (a long-running one is the likely writer):\n")
		for _, p := range procs {
			b.WriteString("  " + p + "\n")
		}
	} else {
		b.WriteString("No process of " + owner + " is running now: the file is re-created by requests to the website or by a cron job.\n")
	}
	if out, err := exec.Command("crontab", "-u", owner, "-l").Output(); err == nil {
		var lines []string
		for _, l := range strings.Split(string(out), "\n") {
			if t := strings.TrimSpace(l); t != "" && !strings.HasPrefix(t, "#") && !strings.Contains(t, "xpguard-wp-cron") {
				lines = append(lines, "  "+t)
			}
		}
		if len(lines) > 0 {
			b.WriteString("Cron jobs of " + owner + ":\n" + strings.Join(lines, "\n") + "\n")
		}
	}
	if strings.Contains(path, "/wp-content/") {
		b.WriteString("WordPress: look for a plugin or theme you did not install (wp-content/plugins, mu-plugins), " +
			"code added to the active theme's functions.php, and new administrator users; then change the passwords. " +
			"The DB Scanner shows injected database entries.\n")
	}
	return b.String()
}

// userProcesses lists the processes of a uid: pid, run time, program and
// command line (at most 15).
func userProcesses(uid int) []string {
	if uid < 0 {
		return nil
	}
	type proc struct {
		pid   int
		start uint64
		line  string
	}
	var out []proc
	dirs, _ := filepath.Glob("/proc/[0-9]*")
	for _, d := range dirs {
		st, err := os.Stat(d)
		if err != nil {
			continue
		}
		if s, ok := st.Sys().(*syscall.Stat_t); !ok || int(s.Uid) != uid {
			continue
		}
		pid, _ := strconv.Atoi(filepath.Base(d))
		cmd, _ := os.ReadFile(filepath.Join(d, "cmdline"))
		exe, _ := os.Readlink(filepath.Join(d, "exe"))
		c := strings.TrimSpace(strings.ReplaceAll(string(cmd), "\x00", " "))
		if len(c) > 160 {
			c = c[:160] + "…"
		}
		var start uint64
		if raw, err := os.ReadFile(filepath.Join(d, "stat")); err == nil {
			if i := strings.LastIndexByte(string(raw), ')'); i > 0 {
				if f := strings.Fields(string(raw[i+1:])); len(f) > 19 {
					start, _ = strconv.ParseUint(f[19], 10, 64)
				}
			}
		}
		out = append(out, proc{pid, start, fmt.Sprintf("pid %d  %s  (%s)", pid, c, exe)})
	}
	// Oldest first: a dropper usually runs long.
	sort.Slice(out, func(i, j int) bool { return out[i].start < out[j].start })
	var lines []string
	for i, p := range out {
		if i == 15 {
			lines = append(lines, fmt.Sprintf("… and %d more", len(out)-15))
			break
		}
		lines = append(lines, p.line)
	}
	return lines
}

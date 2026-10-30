package audit

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// ---- Kernel and tenant isolation ----

// A tenant's web shell becomes root through a kernel bug (Copy Fail
// CVE-2026-31431 and others in 2026, public exploits for Alma and
// CloudLinux 8/9), and without the link protections a tenant links or
// races its way to another account's wp-config.php. Read-only: the
// owner changes kernel settings (same policy as php.ini).

func (a *Auditor) kernel() []Item {
	var out []Item
	running := strings.TrimSpace(a.stackFile("proc/sys/kernel/osrelease"))
	if running != "" {
		newest := ""
		ents, _ := os.ReadDir(filepath.Join(a.StackRoot, "lib/modules"))
		for _, e := range ents {
			if e.IsDir() && (newest == "" || cmpKernel(e.Name(), newest) > 0) {
				newest = e.Name()
			}
		}
		if newest != "" && cmpKernel(newest, running) > 0 {
			// KernelCare patches the running kernel in place.
			sev := "high"
			if isFile(filepath.Join(a.StackRoot, "usr/bin/kcarectl")) {
				sev = "low"
			}
			out = append(out, Item{Check: "kernel", Severity: sev, Title: "Kernel update installed, reboot pending",
				Detail: "Running " + running + ", installed " + newest + ". Kernel fixes (local root holes such as Copy Fail, CVE-2026-31431) only apply after a reboot (or a live patch: KernelCare)."})
		}
	}
	for _, s := range []struct{ file, name string }{
		{"proc/sys/fs/protected_symlinks", "fs.protected_symlinks"},
		{"proc/sys/fs/protected_hardlinks", "fs.protected_hardlinks"},
		// CloudLinux SecureLinks.
		{"proc/sys/fs/enforce_symlinksifowner", "fs.enforce_symlinksifowner"},
		{"proc/sys/fs/protected_symlinks_create", "fs.protected_symlinks_create"},
		{"proc/sys/fs/protected_hardlinks_create", "fs.protected_hardlinks_create"},
	} {
		v := strings.TrimSpace(a.stackFile(s.file))
		if v == "0" {
			out = append(out, Item{Check: "isolation", Severity: "medium", Title: s.name + " is off",
				Detail: "An account can follow or make links to other accounts' files (wp-config.php theft kits). Set " + s.name + " = 1 in /etc/sysctl.d/ and run sysctl --system."})
		}
	}
	// Without CageFS, hidepid keeps tenants from seeing each other's
	// processes (and their command lines).
	if !isFile(filepath.Join(a.StackRoot, "usr/sbin/cagefsctl")) {
		if mounts := a.stackFile("proc/mounts"); mounts != "" && !reProcHidden.MatchString(mounts) {
			out = append(out, Item{Check: "isolation", Severity: "low", Title: "/proc shows every account's processes",
				Detail: "Mount /proc with hidepid=2 (or hidepid=invisible) so an account sees only its own processes; give monitoring tools a gid= exception."})
		}
	}
	return append(out, a.syncookies()...)
}

var (
	reProcHidden = regexp.MustCompile(`(?m)^\S+\s+/proc\s+proc\s+\S*hidepid=(?:2|invisible)`)
	reKernelNum  = regexp.MustCompile(`\d+`)
)

// cmpKernel compares kernel release names by their numbers in order
// (5.14.0-570.12.1.el9_6.x86_64).
func cmpKernel(a, b string) int {
	na, nb := reKernelNum.FindAllString(a, -1), reKernelNum.FindAllString(b, -1)
	for i := 0; i < min(len(na), len(nb)); i++ {
		x, _ := strconv.Atoi(na[i])
		y, _ := strconv.Atoi(nb[i])
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(na) < len(nb):
		return -1
	case len(na) > len(nb):
		return 1
	}
	return 0
}

// ---- PHP's command functions ----

var reDisableFns = regexp.MustCompile(`(?mi)^[ \t]*disable_functions[ \t]*=[ \t]*"?([^"\r\n;]*)`)

// disableFunctions reports a php.ini where scripts may run commands (a web
// shell then runs anything as the account), and one that blocks the
// command functions but leaves putenv: with mail() it loads a library
// and runs commands anyway (the LD_PRELOAD bypass).
func disableFunctions(file, ini string) []Item {
	m := reDisableFns.FindAllStringSubmatch(ini, -1)
	list := ""
	if len(m) > 0 {
		list = strings.ToLower(m[len(m)-1][1]) // the last one counts
	}
	set := map[string]bool{}
	for _, f := range strings.FieldsFunc(list, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		set[f] = true
	}
	if !set["exec"] && !set["shell_exec"] && !set["system"] && !set["passthru"] && !set["proc_open"] && !set["popen"] {
		return []Item{{Check: "php", Severity: "medium", Title: "PHP may run commands (disable_functions does not list them)", Path: file,
			Detail: "A web shell then runs any command as the account. Add exec, shell_exec, system, passthru, proc_open, popen, pcntl_exec to disable_functions (and putenv), and allow them per account where a tool needs them."}}
	}
	if !set["putenv"] && !set["mail"] {
		return []Item{{Check: "php", Severity: "low", Title: "putenv is allowed while the command functions are not", Path: file,
			Detail: "putenv with mail() loads a library and runs commands despite disable_functions (LD_PRELOAD bypass). Add putenv to disable_functions."}}
	}
	return nil
}

// syncookies reports a kernel without SYN cookies (a SYN flood fills the
// connection queue).
func (a *Auditor) syncookies() []Item {
	if v := strings.TrimSpace(a.stackFile("proc/sys/net/ipv4/tcp_syncookies")); v == "0" {
		return []Item{{Check: "isolation", Severity: "medium", Title: "net.ipv4.tcp_syncookies is off",
			Detail: "A SYN flood fills the connection queue and the websites stop answering. Set net.ipv4.tcp_syncookies = 1 (sysctl.d). Large floods need filtering upstream (the provider's DDoS protection)."}}
	}
	return nil
}

// realtimeCoverage reports folders realtime protection does not watch (the
// kernel's inotify limit): a file dropped there waits for a sweep or the
// nightly scan.
func (a *Auditor) realtimeCoverage() []Item {
	if a.Realtime == nil {
		return nil
	}
	un, lost := a.Realtime()
	var out []Item
	if un > 0 {
		out = append(out, Item{Check: "realtime", Severity: "medium", Title: strconv.Itoa(un) + " folders are not watched in realtime",
			Detail: "The kernel's inotify limit is reached: new files there are found by the sweep (every few minutes, slowly) or the nightly scan. Raise fs.inotify.max_user_watches (sysctl.d), e.g. to 4194304, and restart xpguard-agent."})
	}
	if lost > 0 {
		out = append(out, Item{Check: "realtime", Severity: "low", Title: "Realtime protection lost events " + strconv.FormatInt(lost, 10) + " times",
			Detail: "The event queue overflowed and a catch-up walk covered the gap. Raise fs.inotify.max_queued_events (sysctl.d) if this keeps growing."})
	}
	return out
}

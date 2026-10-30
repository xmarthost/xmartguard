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
	return out
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

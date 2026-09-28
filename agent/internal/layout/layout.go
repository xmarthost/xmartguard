// Package layout owns the agent's directories on the server:
//
//	/etc/xpguard         agent.json, identity.key, settings.json, WAF rules
//	/opt/xpguard/bin     the agent program
//	/opt/xpguard/data    local database, signatures, IPDB list, quarantine
//	/opt/xpguard/logs    agent and install logs
//
// Installs from before the xPGuard name used /etc/xmartguard and
// /opt/xmartguard. Migrate moves them once (a rename on the same file
// system, so nothing is copied) and leaves a symbolic link at the old path
// until nothing on the server refers to it any more; DropLinks then removes
// the links. Until a move has happened, Pick keeps using the old directory.
package layout

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	ConfDir    = "/etc/xpguard"
	HomeDir    = "/opt/xpguard"
	OldConfDir = "/etc/xmartguard"
	OldHomeDir = "/opt/xmartguard"

	unitDir       = "/etc/systemd/system"
	oldUnit       = "xmartguard-agent.service"
	newUnit       = "xpguard-agent.service"
	sysctlFile    = "/etc/sysctl.d/xpguard.conf"
	oldSysctlFile = "/etc/sysctl.d/xmartguard.conf"
)

// Root prefixes every path (tests).
var Root = ""

func rp(p string) string { return Root + p }

// Pick returns dir, or old when only old holds marker (a server whose
// directories have not been moved yet).
func Pick(dir, old, marker string) string {
	if _, err := os.Stat(rp(filepath.Join(dir, marker))); err == nil {
		return dir
	}
	if _, err := os.Stat(rp(filepath.Join(old, marker))); err == nil {
		return old
	}
	return dir
}

// Pending reports whether an old directory still has to be moved.
func Pending() bool {
	for _, d := range []string{OldConfDir, OldHomeDir} {
		if fi, err := os.Lstat(rp(d)); err == nil && fi.IsDir() {
			return true
		}
	}
	return false
}

// Migrate moves the old directories to the new ones. It is safe to run on
// every start: once moved, it has nothing to do. force skips the check
// that the service of older versions is gone (the installer stops it
// itself); the agent never moves the program it is running from under
// that service.
func Migrate(force bool) (notes []string, err error) {
	if !Pending() {
		return nil, nil
	}
	if !force {
		if _, err := os.Stat(rp(filepath.Join(unitDir, oldUnit))); err == nil {
			return nil, nil // the service is renamed first (core.maybeMoveUnit)
		}
	}
	var errs []string
	for _, m := range [][2]string{{OldConfDir, ConfDir}, {OldHomeDir, HomeDir}} {
		moved, err := moveDir(rp(m[0]), rp(m[1]))
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		if moved {
			notes = append(notes, "moved "+m[0]+" to "+m[1])
		}
	}
	notes = append(notes, fixReferences()...)
	if len(errs) > 0 {
		return notes, errors.New(strings.Join(errs, "; "))
	}
	return notes, nil
}

// moveDir renames old to dir, or moves old's entries into dir when both
// exist (0.10.1 already created /opt/xpguard/bin), then links old to dir.
func moveDir(old, dir string) (bool, error) {
	fi, err := os.Lstat(old)
	if err != nil || !fi.IsDir() {
		return false, nil // gone, or already a link
	}
	if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
			return false, err
		}
		if err := os.Rename(old, dir); err != nil {
			return false, fmt.Errorf("move %s: %w", old, err)
		}
		return true, os.Symlink(filepath.Base(dir), old)
	}
	if err := merge(old, dir); err != nil {
		return false, fmt.Errorf("move %s: %w", old, err)
	}
	if left := leftovers(old); left != "" {
		return false, fmt.Errorf("move %s: %s exists in both places; kept both", old, left)
	}
	if err := os.RemoveAll(old); err != nil {
		return false, err
	}
	return true, os.Symlink(filepath.Base(dir), old)
}

// merge moves every entry of src that dst does not have; directories both
// have are merged recursively. A file both have stays in src.
func merge(src, dst string) error {
	ents, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	fi, _ := os.Stat(src)
	for _, e := range ents {
		s, d := filepath.Join(src, e.Name()), filepath.Join(dst, e.Name())
		dfi, err := os.Lstat(d)
		switch {
		case errors.Is(err, os.ErrNotExist):
			if err := os.Rename(s, d); err != nil {
				return err
			}
		case e.IsDir() && e.Type()&os.ModeSymlink == 0 && dfi.IsDir():
			if err := merge(s, d); err != nil {
				return err
			}
		case e.Type()&os.ModeSymlink != 0 && sameFile(s, d):
			_ = os.Remove(s) // a link to the file dst already has
		case e.Type().IsRegular() && dfi.Mode().IsRegular() && strings.HasSuffix(e.Name(), ".log"):
			// A log both have (the installer started a new one): old lines first.
			if err := joinLogs(s, d); err != nil {
				return err
			}
		}
	}
	if fi != nil {
		_ = os.Chmod(dst, fi.Mode().Perm())
	}
	return nil
}

func joinLogs(old, cur string) error {
	a, err := os.ReadFile(old)
	if err != nil {
		return err
	}
	b, err := os.ReadFile(cur)
	if err != nil {
		return err
	}
	fi, _ := os.Stat(cur)
	tmp := cur + ".xgtmp"
	if err := os.WriteFile(tmp, append(a, b...), fi.Mode().Perm()); err != nil {
		return err
	}
	if err := os.Rename(tmp, cur); err != nil {
		return err
	}
	return os.Remove(old)
}

func sameFile(a, b string) bool {
	x, err1 := os.Stat(a)
	y, err2 := os.Stat(b)
	return err1 == nil && err2 == nil && os.SameFile(x, y)
}

// leftovers names a file still in dir (after a merge), or "".
func leftovers(dir string) string {
	found := ""
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && found == "" {
			found = p
		}
		return nil
	})
	return found
}

// fixReferences points files outside the two directories at the new paths.
func fixReferences() (notes []string) {
	swap := strings.NewReplacer(OldHomeDir+"/", HomeDir+"/", OldConfDir+"/", ConfDir+"/")
	// The service writes its log under /opt/xpguard/logs.
	if p := rp(filepath.Join(unitDir, newUnit)); rewrite(p, swap) {
		notes = append(notes, "updated "+newUnit)
		if Root == "" {
			_ = exec.Command("systemctl", "daemon-reload").Run()
		}
	}
	// Links in /usr/local/bin.
	for _, l := range []string{"xpguard-agent", "xgcli", "xmartguard-agent", "xmartguard"} {
		p := rp("/usr/local/bin/" + l)
		if t, err := os.Readlink(p); err == nil && strings.HasPrefix(t, OldHomeDir+"/") {
			nt := swap.Replace(t)
			if strings.HasSuffix(t, "/bin/xmartguard-agent") {
				nt = HomeDir + "/bin/xpguard-agent"
			}
			_ = os.Remove(p)
			_ = os.Symlink(nt, p)
		}
	}
	// The uninstaller's record of what was installed.
	rewrite(rp(HomeDir+"/manifest"), strings.NewReplacer(OldHomeDir, HomeDir, OldConfDir, ConfDir, oldSysctlFile, sysctlFile))
	// inotify limit file.
	if _, err := os.Stat(rp(oldSysctlFile)); err == nil {
		if _, err := os.Stat(rp(sysctlFile)); err != nil {
			if os.Rename(rp(oldSysctlFile), rp(sysctlFile)) == nil {
				notes = append(notes, "renamed "+oldSysctlFile)
			}
		} else {
			_ = os.Remove(rp(oldSysctlFile))
		}
	}
	// CSF/LFD process ignore list: the old program path is not used any more.
	dropLine(rp("/etc/csf/csf.pignore"), "exe:"+OldHomeDir+"/bin/xmartguard-agent")
	// The local control socket moved to /run/xpguard.
	_ = os.RemoveAll(rp("/run/xmartguard"))
	return notes
}

func rewrite(p string, r *strings.Replacer) bool {
	b, err := os.ReadFile(p)
	if err != nil {
		return false
	}
	nb := r.Replace(string(b))
	if nb == string(b) {
		return false
	}
	fi, _ := os.Stat(p)
	tmp := p + ".xgtmp"
	if os.WriteFile(tmp, []byte(nb), fi.Mode().Perm()) != nil {
		return false
	}
	return os.Rename(tmp, p) == nil
}

func dropLine(p, line string) {
	b, err := os.ReadFile(p)
	if err != nil {
		return
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(l) != line {
			out = append(out, l)
		}
	}
	if nb := strings.Join(out, "\n"); nb != string(b) {
		fi, _ := os.Stat(p)
		_ = os.WriteFile(p, []byte(nb), fi.Mode().Perm())
	}
}

// refFiles are the files outside the agent's directories that may name
// them: web server includes, services and cron.
var refFiles = []string{
	"/etc/apache2/conf.d/modsec/modsec2.user.conf",
	"/etc/apache2/conf.d/*.conf",
	"/etc/apache2/conf.d/includes/*.conf",
	"/etc/httpd/conf.d/*.conf",
	"/etc/apache2/conf-enabled/*.conf",
	"/usr/local/lsws/conf/httpd_config.xml",
	"/usr/local/lsws/conf/*.conf",
	"/etc/systemd/system/*.service",
	"/etc/cron.d/*",
	"/var/spool/cron/root",
	"/etc/csf/csfpost.sh",
}

// References lists the files that still name an old directory.
func References() []string {
	var out []string
	for _, g := range refFiles {
		files, _ := filepath.Glob(rp(g))
		for _, f := range files {
			if fi, err := os.Lstat(f); err != nil || !fi.Mode().IsRegular() || fi.Size() > 4<<20 {
				continue
			}
			b, _ := os.ReadFile(f)
			if strings.Contains(string(b), OldConfDir+"/") || strings.Contains(string(b), OldHomeDir+"/") ||
				strings.HasSuffix(strings.TrimSpace(string(b)), OldConfDir) {
				out = append(out, strings.TrimPrefix(f, Root))
			}
		}
	}
	return out
}

// DropLinks removes the links at the old paths once nothing refers to them.
// It returns true when no old path is left.
func DropLinks() bool {
	if Pending() {
		return false
	}
	if len(References()) > 0 {
		return false
	}
	for _, d := range []string{OldConfDir, OldHomeDir} {
		if fi, err := os.Lstat(rp(d)); err == nil && fi.Mode()&os.ModeSymlink != 0 {
			_ = os.Remove(rp(d))
		}
	}
	for _, l := range []string{"/usr/local/bin/xmartguard-agent", "/usr/local/bin/xmartguard"} {
		if t, err := os.Readlink(rp(l)); err == nil && strings.HasPrefix(t, HomeDir+"/") {
			_ = os.Remove(rp(l))
		}
	}
	// The program's name before the xPGuard name (kept for the old service).
	if fi, err := os.Lstat(rp(HomeDir + "/bin/xmartguard-agent")); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		_ = os.Remove(rp(HomeDir + "/bin/xmartguard-agent"))
	}
	return true
}

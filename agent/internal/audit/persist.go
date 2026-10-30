package audit

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// ---- Ways back in that are not cron jobs ----

// After a site is taken over, a kit with a shell keeps a way back in that
// survives the cleanup of the website: an SSH key of its own, a systemd
// user timer, an at job, or a line in a shell profile that starts a
// download. Read-only: the owner decides (a developer's own key is
// normal).

// keyRecent is how long a changed authorized_keys is reported.
const keyRecent = 7 * 24 * time.Hour

// reProfileLoader: a profile line that downloads and runs something, or
// decodes and runs it, or opens a connection back.
var reProfileLoader = regexp.MustCompile(`(?i)(?:curl|wget)\b[^\n|;]*\|\s*(?:ba|z)?sh\b|base64\s+(?:-d|--decode)[^\n]*\|\s*(?:ba|z)?sh\b|/dev/tcp/|\bnohup\b[^\n]*&\s*$|\beval\s+"?\$\((?:curl|wget)`)

var profileFiles = []string{".bashrc", ".bash_profile", ".profile", ".zshrc", ".bash_login"}

func (a *Auditor) persistence() []Item {
	if a.Accounts == nil {
		return nil
	}
	var out []Item
	now := a.now()
	for _, acc := range a.Accounts() {
		if acc.Home == "" {
			continue
		}
		keys := filepath.Join(acc.Home, ".ssh", "authorized_keys")
		if st, err := os.Lstat(keys); err == nil && st.Mode().IsRegular() && now.Sub(st.ModTime()) < keyRecent {
			b, _ := os.ReadFile(keys)
			var names []string
			n := 0
			for _, l := range strings.Split(string(b), "\n") {
				f := strings.Fields(l)
				if len(f) < 2 || strings.HasPrefix(f[0], "#") {
					continue
				}
				n++
				if len(f) >= 3 && len(names) < 5 {
					names = append(names, f[len(f)-1]) // the key's comment, not the key
				}
			}
			if n > 0 {
				out = append(out, Item{Check: "persistence", Severity: "medium", Title: "SSH key added or changed in the last 7 days", Owner: acc.Name, Path: keys,
					Detail: strconv.Itoa(n) + " key(s), changed " + st.ModTime().UTC().Format("2006-01-02 15:04") + " UTC" + commentList(names) +
						". If the owner did not add it, remove it: an attacker's key logs in without a password."})
			}
		}
		units, _ := filepath.Glob(filepath.Join(acc.Home, ".config", "systemd", "user", "*.timer"))
		services, _ := filepath.Glob(filepath.Join(acc.Home, ".config", "systemd", "user", "*.service"))
		if all := append(units, services...); len(all) > 0 {
			var names []string
			for _, u := range all[:min(len(all), 10)] {
				names = append(names, filepath.Base(u))
			}
			out = append(out, Item{Check: "persistence", Severity: "medium", Title: "systemd user units in a hosting account", Owner: acc.Name, Path: filepath.Dir(all[0]),
				Detail: strings.Join(names, ", ") + ". Hosting accounts rarely need them; malware uses them to start again after cleanup."})
		}
		for _, pf := range profileFiles {
			p := filepath.Join(acc.Home, pf)
			st, err := os.Lstat(p)
			if err != nil || !st.Mode().IsRegular() || st.Size() > 256<<10 {
				continue
			}
			b, _ := os.ReadFile(p)
			for _, l := range strings.Split(string(b), "\n") {
				t := strings.TrimSpace(l)
				if t == "" || strings.HasPrefix(t, "#") || !reProfileLoader.MatchString(t) {
					continue
				}
				out = append(out, Item{Check: "persistence", Severity: "high", Title: "Shell profile starts a download or hidden program", Owner: acc.Name, Path: p,
					Detail: maskCron(t) + "\nIt runs at every login of the account. Remove the line if the owner did not add it."})
				break
			}
		}
	}
	out = append(out, a.atJobs()...)
	return out
}

func commentList(names []string) string {
	if len(names) == 0 {
		return ""
	}
	return " (" + strings.Join(names, ", ") + ")"
}

// atJobs reports at jobs of hosting accounts (root's are the admin's).
func (a *Auditor) atJobs() []Item {
	dirs := []string{"/var/spool/at", "/var/spool/cron/atjobs"}
	if a.AtDir != "" {
		dirs = []string{a.AtDir}
	}
	owners := map[uint32]string{}
	if a.Accounts != nil {
		for _, acc := range a.Accounts() {
			if st, err := os.Stat(acc.Home); err == nil {
				if sys, ok := st.Sys().(*syscall.Stat_t); ok {
					owners[sys.Uid] = acc.Name
				}
			}
		}
	}
	var out []Item
	for _, d := range dirs {
		ents, _ := os.ReadDir(d)
		for _, e := range ents {
			if e.IsDir() || strings.HasPrefix(e.Name(), ".") {
				continue
			}
			info, err := e.Info()
			if err != nil {
				continue
			}
			sys, ok := info.Sys().(*syscall.Stat_t)
			if !ok {
				continue
			}
			if user, ok := owners[sys.Uid]; ok {
				out = append(out, Item{Check: "persistence", Severity: "medium", Title: "at job of a hosting account", Owner: user, Path: filepath.Join(d, e.Name()),
					Detail: "A one-time job waiting to run as " + user + ". Check it (atq, at -c) and remove it if the owner did not plan it (atrm)."})
			}
		}
	}
	return out
}

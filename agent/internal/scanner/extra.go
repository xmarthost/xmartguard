package scanner

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/config"
)

// homes maps hosting-account uids to their home directories.
func homes() map[uint32]string {
	out := map[uint32]string{}
	for _, u := range Users() {
		if st, err := os.Stat(u.Home); err == nil {
			if sys, ok := st.Sys().(*syscall.Stat_t); ok {
				out[sys.Uid] = filepath.Clean(u.Home)
			}
		}
	}
	return out
}

// InsecureSymlink reports whether the link at path lets its owner reach a
// file they could not read otherwise: a target in another account's home,
// or a file that is not world-readable and owned by someone else (a common
// way to read other sites' wp-config.php on shared hosting).
func InsecureSymlink(path string, homesByUID map[uint32]string) (string, bool) {
	li, err := os.Lstat(path)
	if err != nil || li.Mode()&fs.ModeSymlink == 0 {
		return "", false
	}
	ls, ok := li.Sys().(*syscall.Stat_t)
	if !ok {
		return "", false
	}
	target, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", false // dangling links are harmless
	}
	ti, err := os.Stat(target)
	if err != nil {
		return "", false
	}
	ts, ok := ti.Sys().(*syscall.Stat_t)
	if !ok || ts.Uid == ls.Uid {
		return "", false
	}
	for uid, home := range homesByUID {
		if uid != ls.Uid && (target == home || strings.HasPrefix(target, home+"/")) {
			return target, true
		}
	}
	if ti.Mode().IsRegular() && ti.Mode().Perm()&0o004 == 0 {
		return target, true
	}
	return "", false
}

// YARABin locates the yara binary ("" when not installed).
func YARABin() string {
	for _, p := range []string{"/usr/bin/yara", "/usr/local/bin/yara", "/bin/yara"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// YARADir holds administrator-supplied YARA rules (*.yar, *.yara).
func YARADir() string { return filepath.Join(config.Dir(), "yara") }

// YARARules lists the rule files: the administrator's own (namespace
// "admin") and those from public feeds (namespace "feed").
func YARARules() []string {
	var out []string
	for _, d := range []struct{ ns, dir string }{{"admin", YARADir()}, {"feed", FeedYARADir()}} {
		for _, pat := range []string{"*.yar", "*.yara"} {
			m, _ := filepath.Glob(filepath.Join(d.dir, pat))
			for _, f := range m {
				out = append(out, d.ns+":"+f)
			}
		}
	}
	return out
}

// ValidYARA reports whether a rule file compiles with the installed yara.
func ValidYARA(path string) error {
	bin := YARABin()
	if bin == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "-w", path, os.DevNull).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", bytes.TrimSpace(out))
	}
	return nil
}

// yaraScan runs the rules over a list of files and returns path -> rule.
func yaraScan(ctx context.Context, files []string) map[string]string {
	bin, rules := YARABin(), YARARules()
	out := map[string]string{}
	if bin == "" || len(rules) == 0 || len(files) == 0 {
		return out
	}
	list, err := os.CreateTemp("", "xg-yara-*.lst")
	if err != nil {
		return out
	}
	defer os.Remove(list.Name())
	w := bufio.NewWriter(list)
	for _, f := range files {
		w.WriteString(f + "\n")
	}
	w.Flush()
	list.Close()
	cctx, cancel := context.WithTimeout(ctx, 2*time.Hour)
	defer cancel()
	args := append([]string{"-w", "-e", "--scan-list"}, rules...)
	args = append(args, list.Name())
	raw, _ := exec.CommandContext(cctx, bin, args...).Output()
	for _, line := range bytes.Split(raw, []byte("\n")) {
		rule, path, ok := strings.Cut(string(line), " ")
		if ok && rule != "" && path != "" {
			if _, seen := out[path]; !seen {
				out[path] = rule
			}
		}
	}
	return out
}

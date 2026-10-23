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
	"strconv"
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
		// A dangling link is harmless, except one waiting for another
		// account's secrets to appear: credential theft kits make one for
		// every account and every CMS (server1: 265,000 links, most to
		// files that do not exist).
		if t, ok := lexicalTarget(path); ok && SecretFileName(filepath.Base(t)) {
			for uid, home := range homesByUID {
				if uid != ls.Uid && strings.HasPrefix(t, home+"/") {
					return t, true
				}
			}
		}
		return "", false
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
// It runs with the scan's thread count, at the lowest CPU and disk
// priority.
func yaraScan(ctx context.Context, files []string, threads int) map[string]string {
	bin, rules := YARABin(), YARARules()
	out := map[string]string{}
	if bin == "" || len(rules) == 0 || len(files) == 0 {
		return out
	}
	// The scan list is one name per line: a name holding a newline would
	// be read as two (another file scanned, the real one missed), so such
	// files are scanned one by one.
	var listed, odd []string
	for _, f := range files {
		if strings.ContainsAny(f, "\n\r") {
			odd = append(odd, f)
		} else {
			listed = append(listed, f)
		}
	}
	cctx, cancel := context.WithTimeout(ctx, 2*time.Hour)
	defer cancel()
	run := func(target ...string) []byte {
		args := append([]string{"-w", "-e", "-p", strconv.Itoa(max(threads, 1))}, target[:len(target)-1]...)
		args = append(append(args, rules...), target[len(target)-1])
		cmd := bin
		if p, err := exec.LookPath("ionice"); err == nil {
			args = append([]string{"-c3", cmd}, args...)
			cmd = p
		}
		if p, err := exec.LookPath("nice"); err == nil {
			args = append([]string{"-n", "19", cmd}, args...)
			cmd = p
		}
		raw, _ := exec.CommandContext(cctx, cmd, args...).Output()
		return raw
	}
	if len(listed) > 0 {
		list, err := os.CreateTemp("", "xg-yara-*.lst")
		if err != nil {
			return out
		}
		defer os.Remove(list.Name())
		w := bufio.NewWriter(list)
		for _, f := range listed {
			w.WriteString(f + "\n")
		}
		w.Flush()
		list.Close()
		for _, line := range bytes.Split(run("--scan-list", list.Name()), []byte("\n")) {
			rule, path, ok := strings.Cut(string(line), " ")
			if ok && rule != "" && path != "" {
				if _, seen := out[path]; !seen {
					out[path] = rule
				}
			}
		}
	}
	for _, f := range odd {
		if rule, _, ok := strings.Cut(string(run(f)), " "); ok && rule != "" {
			out[f] = rule
		}
	}
	return out
}

// lexicalTarget is where a link points, made absolute, without following
// any link on the way.
func lexicalTarget(path string) (string, bool) {
	t, err := os.Readlink(path)
	if err != nil {
		return "", false
	}
	if !filepath.IsAbs(t) {
		t = filepath.Join(filepath.Dir(path), t)
	}
	return filepath.Clean(t), true
}

// secretNames are files holding database passwords, API tokens or login
// hashes; a link to another account's copy is only made to read them.
var secretNames = map[string]bool{
	"wp-config.php": true, "config.php": true, "configuration.php": true, "settings.php": true,
	"local.xml": true, "env.php": true, ".env": true, "parameters.yml": true, "database.php": true,
	"config.inc.php": true, "conf.php": true, "db.php": true, "connect.php": true, "connection.php": true,
	".accesshash": true, ".my.cnf": true, ".pgpass": true, "shadow": true, "passwd": true, ".lastlogin": true,
	"id_rsa": true, "authorized_keys": true, ".htpasswd": true, "web.config": true,
}

// SecretFileName reports a file name that holds secrets.
func SecretFileName(name string) bool { return secretNames[strings.ToLower(name)] }

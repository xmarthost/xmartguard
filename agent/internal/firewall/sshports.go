package firewall

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// SSHConfig is the sshd configuration read for the port filter when
// `sshd -T` cannot run.
var SSHConfig = "/etc/ssh/sshd_config"

// sshdTest prints sshd's effective configuration (`sshd -T`); tests
// replace it.
var sshdTest = func() ([]byte, error) {
	bin, err := exec.LookPath("sshd")
	if err != nil {
		bin = "/usr/sbin/sshd"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, bin, "-T").Output()
}

// procRoot is where the running sshd's sockets are looked up (tests
// replace it).
var procRoot = "/proc"

// SSHPorts returns the ports sshd listens on, so the port filter never
// drops them: the effective configuration (`sshd -T`, which includes the
// sshd_config.d drop-ins; the files themselves, following Include, when
// it cannot run) and, as a safety net, the TCP ports the running sshd
// listens on. 22 when nothing is found.
func SSHPorts() []int {
	set := map[int]bool{}
	if out, err := sshdTest(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			sshPortLine(strings.Fields(line), set)
		}
	}
	if len(set) == 0 {
		sshConfigPorts(SSHConfig, set, 0)
	}
	for _, p := range sshdListening(procRoot) {
		set[p] = true
	}
	if len(set) == 0 {
		return []int{22}
	}
	out := make([]int, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

// sshPortLine records the port of a "Port N" or "ListenAddress host:N"
// line (keywords in any case, as in sshd_config and `sshd -T`).
func sshPortLine(f []string, set map[int]bool) {
	if len(f) < 2 {
		return
	}
	v := f[1]
	switch strings.ToLower(f[0]) {
	case "port":
	case "listenaddress":
		// "1.2.3.4:2222", "[::1]:2222"; a bare address uses the Port lines.
		i := strings.LastIndex(v, ":")
		if i < 0 || (strings.Count(v, ":") > 1 && !strings.Contains(v, "]:")) {
			return
		}
		v = v[i+1:]
	default:
		return
	}
	if p, err := strconv.Atoi(v); err == nil && p > 0 && p < 65536 {
		set[p] = true
	}
}

// sshConfigPorts reads an sshd configuration file and the files its
// Include lines name (relative to /etc/ssh, like sshd).
func sshConfigPorts(path string, set map[int]bool, depth int) {
	raw, err := os.ReadFile(path)
	if err != nil || depth > 8 {
		return
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.FieldsFunc(line, func(r rune) bool { return r == ' ' || r == '\t' || r == '=' })
		if len(f) >= 2 && strings.EqualFold(f[0], "Include") {
			for _, pat := range f[1:] {
				if !filepath.IsAbs(pat) {
					pat = filepath.Join(filepath.Dir(SSHConfig), pat)
				}
				files, _ := filepath.Glob(pat)
				sort.Strings(files)
				for _, inc := range files {
					sshConfigPorts(inc, set, depth+1)
				}
			}
			continue
		}
		sshPortLine(f, set)
	}
}

// sshdListening returns the TCP ports the running sshd processes listen on.
func sshdListening(proc string) []int {
	inodes := map[string]bool{}
	dirs, _ := os.ReadDir(proc)
	for _, d := range dirs {
		if _, err := strconv.Atoi(d.Name()); err != nil {
			continue
		}
		comm, err := os.ReadFile(filepath.Join(proc, d.Name(), "comm"))
		if err != nil || strings.TrimSpace(string(comm)) != "sshd" {
			continue
		}
		fds, _ := os.ReadDir(filepath.Join(proc, d.Name(), "fd"))
		for _, fd := range fds {
			l, err := os.Readlink(filepath.Join(proc, d.Name(), "fd", fd.Name()))
			if err == nil && strings.HasPrefix(l, "socket:[") {
				inodes[strings.TrimSuffix(strings.TrimPrefix(l, "socket:["), "]")] = true
			}
		}
	}
	if len(inodes) == 0 {
		return nil
	}
	var out []int
	for _, name := range []string{"tcp", "tcp6"} {
		f, err := os.Open(filepath.Join(proc, "net", name))
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			// sl local_address rem_address st ... uid timeout inode
			x := strings.Fields(sc.Text())
			if len(x) < 10 || x[3] != "0A" || !inodes[x[9]] {
				continue
			}
			if i := strings.LastIndex(x[1], ":"); i >= 0 {
				if p, err := strconv.ParseUint(x[1][i+1:], 16, 16); err == nil && p > 0 {
					out = append(out, int(p))
				}
			}
		}
		f.Close()
	}
	return out
}

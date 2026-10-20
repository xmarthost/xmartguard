package firewall

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func fakeSSH(t *testing.T, sshdT string) (dir string) {
	t.Helper()
	dir = t.TempDir()
	oldCfg, oldT, oldProc := SSHConfig, sshdTest, procRoot
	t.Cleanup(func() { SSHConfig, sshdTest, procRoot = oldCfg, oldT, oldProc })
	SSHConfig = filepath.Join(dir, "sshd_config")
	procRoot = filepath.Join(dir, "proc")
	sshdTest = func() ([]byte, error) {
		if sshdT == "" {
			return nil, errors.New("sshd not installed")
		}
		return []byte(sshdT), nil
	}
	return dir
}

// The port filter keeps every port sshd really listens on: ports set in
// sshd_config.d drop-ins (AlmaLinux/CloudLinux 9) or by ListenAddress,
// and the ports of the running sshd, so turning it on cannot lock SSH out.
func TestSSHPortsDropIns(t *testing.T) {
	// The effective configuration from `sshd -T`.
	fakeSSH(t, "port 22\nlistenaddress [::]:2200\nlistenaddress 0.0.0.0:22\npermitrootlogin yes\n")
	if got := SSHPorts(); !reflect.DeepEqual(got, []int{22, 2200}) {
		t.Fatalf("sshd -T: %v", got)
	}

	// Without sshd -T: the main file and the drop-ins it includes.
	dir := fakeSSH(t, "")
	os.MkdirAll(filepath.Join(dir, "sshd_config.d"), 0o700)
	os.WriteFile(SSHConfig, []byte("# Port 1\nInclude sshd_config.d/*.conf\nPermitRootLogin no\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "sshd_config.d", "50-port.conf"), []byte("Port 2222\nListenAddress 192.0.2.1:2223\nListenAddress ::1\n"), 0o600)
	if got := SSHPorts(); !reflect.DeepEqual(got, []int{2222, 2223}) {
		t.Fatalf("drop-ins: %v", got)
	}

	// Safety net: the running sshd listens on 2244 (only its own LISTEN
	// sockets count).
	dir = fakeSSH(t, "port 22\n")
	pid := filepath.Join(dir, "proc", "321")
	other := filepath.Join(dir, "proc", "400")
	for _, p := range []string{pid, other} {
		os.MkdirAll(filepath.Join(p, "fd"), 0o700)
	}
	os.WriteFile(filepath.Join(pid, "comm"), []byte("sshd\n"), 0o600)
	os.WriteFile(filepath.Join(other, "comm"), []byte("mysqld\n"), 0o600)
	os.Symlink("socket:[5551]", filepath.Join(pid, "fd", "3"))
	os.Symlink("socket:[5552]", filepath.Join(pid, "fd", "4"))
	os.Symlink("socket:[5553]", filepath.Join(other, "fd", "3"))
	os.MkdirAll(filepath.Join(dir, "proc", "net"), 0o700)
	row := func(sl int, local, st, inode string) string {
		return fmt.Sprintf("  %d: %s 00000000:0000 %s 00000000:00000000 00:00000000 00000000     0        0 %s 1 0000000000000000 100 0 0 10 0\n", sl, local, st, inode)
	}
	hdr := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	os.WriteFile(filepath.Join(dir, "proc", "net", "tcp"), []byte(hdr+row(0, "00000000:08C4", "0A", "5551")+row(1, "00000000:0CEA", "0A", "5553")+row(2, "0100007F:0016", "01", "5552")), 0o600)
	if got := SSHPorts(); !reflect.DeepEqual(got, []int{22, 2244}) {
		t.Fatalf("running sshd: %v", got)
	}

	// Nothing found: 22.
	fakeSSH(t, "")
	if got := SSHPorts(); !reflect.DeepEqual(got, []int{22}) {
		t.Fatalf("default: %v", got)
	}
}

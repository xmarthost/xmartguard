package sysinfo

import (
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func write(t *testing.T, root, rel, content string) {
	t.Helper()
	path := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func withRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	old := Root
	Root = root
	t.Cleanup(func() { Root = old })
	return root
}

func TestOSFamily(t *testing.T) {
	cases := map[string]map[string]string{
		"rhel":   {"ID": "cloudlinux", "ID_LIKE": "rhel fedora centos"},
		"debian": {"ID": "ubuntu", "ID_LIKE": "debian"},
		"other":  {"ID": "arch"},
	}
	for want, rel := range cases {
		if got := OSFamily(rel); got != want {
			t.Errorf("OSFamily(%v) = %s, want %s", rel, got, want)
		}
	}
	// AlmaLinux has ID_LIKE "rhel centos fedora".
	if OSFamily(map[string]string{"ID": "almalinux"}) != "rhel" {
		t.Error("almalinux should be rhel")
	}
}

func TestOSRelease(t *testing.T) {
	root := withRoot(t)
	write(t, root, "etc/os-release", "NAME=\"AlmaLinux\"\nVERSION_ID=\"9.4\"\nID=\"almalinux\"\n# comment\n")
	rel := OSRelease()
	if rel["NAME"] != "AlmaLinux" || rel["VERSION_ID"] != "9.4" || rel["ID"] != "almalinux" {
		t.Fatalf("unexpected: %v", rel)
	}
}

func TestControlPanel(t *testing.T) {
	cases := map[string]string{
		"usr/local/cpanel/cpanel":           "cpanel",
		"usr/local/directadmin/directadmin": "directadmin",
		"usr/local/psa/version":             "plesk",
		"usr/local/CyberCP/x":               "cyberpanel",
		"usr/local/cwpsrv/x":                "cwp",
	}
	for file, want := range cases {
		root := withRoot(t)
		write(t, root, file, "")
		if got := ControlPanel(); got != want {
			t.Errorf("%s: got %s want %s", file, got, want)
		}
	}
	withRoot(t)
	if got := ControlPanel(); got != "standalone" {
		t.Errorf("empty root: got %s", got)
	}
}

func TestWebServer(t *testing.T) {
	root := withRoot(t)
	write(t, root, "usr/sbin/httpd", "")
	if got := WebServer(); got != "apache" {
		t.Errorf("got %s", got)
	}
	root = withRoot(t)
	write(t, root, "usr/local/lsws/bin/lshttpd", "")
	if got := WebServer(); got != "litespeed" {
		t.Errorf("got %s", got)
	}
}

func TestReadMemory(t *testing.T) {
	root := withRoot(t)
	write(t, root, "proc/meminfo", "MemTotal:       1000 kB\nMemFree:  100 kB\nMemAvailable:    400 kB\nSwapTotal: 200 kB\nSwapFree: 50 kB\n")
	m, err := ReadMemory()
	if err != nil {
		t.Fatal(err)
	}
	want := Memory{Total: 1000 * 1024, Available: 400 * 1024, Used: 600 * 1024, SwapTotal: 200 * 1024, SwapUsed: 150 * 1024}
	if m != want {
		t.Fatalf("got %+v want %+v", m, want)
	}
}

func TestLoadAvgAndCPU(t *testing.T) {
	root := withRoot(t)
	write(t, root, "proc/loadavg", "8.33 8.76 9.45 3/1200 4242\n")
	a, b, c := LoadAvg()
	if a != 8.33 || b != 8.76 || c != 9.45 {
		t.Fatalf("loadavg %v %v %v", a, b, c)
	}
	write(t, root, "proc/cpuinfo", "processor\t: 0\nmodel name\t: AMD EPYC 7402P\n\nprocessor\t: 1\nmodel name\t: AMD EPYC 7402P\n")
	model, n := CPU()
	if model != "AMD EPYC 7402P" || n != 2 {
		t.Fatalf("cpu %q %d", model, n)
	}
}

func TestEstablished(t *testing.T) {
	root := withRoot(t)
	hdr := "  sl  local_address rem_address   st\n"
	write(t, root, "proc/net/tcp", hdr+"0: 0100007F:0CEA 00000000:0000 0A\n1: 0100007F:0CEA 0100007F:D2F0 01\n")
	write(t, root, "proc/net/tcp6", hdr+"0: x y 01\n")
	if n := Established(); n != 2 {
		t.Fatalf("got %d", n)
	}
}

func TestSortIPs(t *testing.T) {
	in := []net.IP{net.ParseIP("10.0.0.5"), net.ParseIP("2001:db8::1"), net.ParseIP("74.50.90.186"), net.ParseIP("fd00::1")}
	got := SortIPs(in)
	want := []string{"74.50.90.186", "10.0.0.5", "2001:db8::1", "fd00::1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestCollectorLive(t *testing.T) {
	// Runs against the real /proc of the test machine.
	c := NewCollector()
	s := c.Collect(5)
	if s.MemTotal == 0 || s.TS == 0 {
		t.Fatalf("empty sample: %+v", s)
	}
	if len(s.TopProcesses) == 0 || len(s.TopProcesses) > 5 {
		t.Fatalf("unexpected process count %d", len(s.TopProcesses))
	}
}

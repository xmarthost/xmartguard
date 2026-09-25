// Package sysinfo detects host inventory (OS, control panel, web server) and
// collects runtime metrics from /proc. All filesystem access goes through
// Root so tests can point it at a fixture tree.
package sysinfo

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
)

// Root is the filesystem root used for detection ("/" in production).
var Root = "/"

func p(parts ...string) string { return filepath.Join(append([]string{Root}, parts...)...) }

func exists(parts ...string) bool {
	_, err := os.Stat(p(parts...))
	return err == nil
}

// Inventory is static-ish host information sent on connect.
type Inventory struct {
	Hostname      string   `json:"hostname"`
	OSID          string   `json:"os_id"`
	OSName        string   `json:"os_name"`
	OSVersion     string   `json:"os_version"`
	OSFamily      string   `json:"os_family"` // rhel | debian | other
	Kernel        string   `json:"kernel"`
	Arch          string   `json:"arch"`
	CPUModel      string   `json:"cpu_model"`
	CPUCores      int      `json:"cpu_cores"`
	MemTotalBytes uint64   `json:"mem_total_bytes"`
	ControlPanel  string   `json:"control_panel"`
	WebServer     string   `json:"web_server"`
	PrimaryIP     string   `json:"primary_ip"`
	IPs           []string `json:"ips"`
	Virtualization string  `json:"virtualization,omitempty"`
}

// OSRelease parses /etc/os-release.
func OSRelease() map[string]string {
	out := map[string]string{}
	f, err := os.Open(p("etc", "os-release"))
	if err != nil {
		return out
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		k, v, ok := strings.Cut(s.Text(), "=")
		if !ok {
			continue
		}
		out[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"'`)
	}
	return out
}

// OSFamily maps an os-release to rhel/debian/other.
func OSFamily(rel map[string]string) string {
	ids := strings.ToLower(rel["ID"] + " " + rel["ID_LIKE"])
	switch {
	case strings.Contains(ids, "rhel"), strings.Contains(ids, "centos"),
		strings.Contains(ids, "fedora"), strings.Contains(ids, "cloudlinux"),
		strings.Contains(ids, "almalinux"), strings.Contains(ids, "rocky"),
		strings.Contains(ids, "amzn"):
		return "rhel"
	case strings.Contains(ids, "debian"), strings.Contains(ids, "ubuntu"):
		return "debian"
	}
	return "other"
}

// ControlPanel detects the installed hosting control panel.
func ControlPanel() string {
	switch {
	case exists("usr", "local", "cpanel", "cpanel"):
		return "cpanel"
	case exists("usr", "local", "directadmin", "directadmin"):
		return "directadmin"
	case exists("usr", "local", "psa", "version"):
		return "plesk"
	case exists("usr", "local", "CyberCP"):
		return "cyberpanel"
	case exists("usr", "local", "cwpsrv"):
		return "cwp"
	case exists("usr", "local", "webuzo"):
		return "webuzo"
	case exists("usr", "local", "interworx"):
		return "interworx"
	case exists("opt", "enhance") || exists("var", "local", "enhance"):
		return "enhance"
	case exists("etc", "webmin", "miniserv.conf"):
		return "webmin"
	}
	return "standalone"
}

// WebServer detects the primary web server.
func WebServer() string {
	switch {
	case exists("usr", "local", "lsws", "bin", "lshttpd"):
		if exists("usr", "local", "lsws", "bin", "openlitespeed") {
			return "openlitespeed"
		}
		return "litespeed"
	case exists("usr", "sbin", "httpd"), exists("usr", "sbin", "apache2"),
		exists("usr", "local", "apache", "bin", "httpd"):
		return "apache"
	case exists("usr", "sbin", "nginx"):
		return "nginx"
	}
	return "none"
}

// CPU returns the CPU model and logical core count.
func CPU() (string, int) {
	f, err := os.Open(p("proc", "cpuinfo"))
	if err != nil {
		return "", runtime.NumCPU()
	}
	defer f.Close()
	model, cores := "", 0
	s := bufio.NewScanner(f)
	for s.Scan() {
		k, v, ok := strings.Cut(s.Text(), ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "model name":
			if model == "" {
				model = strings.TrimSpace(v)
			}
		case "processor":
			cores++
		}
	}
	if cores == 0 {
		cores = runtime.NumCPU()
	}
	return model, cores
}

// Kernel returns the running kernel release.
func Kernel() string {
	var u syscall.Utsname
	if err := syscall.Uname(&u); err != nil {
		return ""
	}
	b := make([]byte, 0, len(u.Release))
	for _, c := range u.Release {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b)
}

// Virtualization gives a best-effort hypervisor/container hint.
func Virtualization() string {
	if exists("proc", "vz") && !exists("proc", "bc") {
		return "openvz"
	}
	if exists(".dockerenv") {
		return "docker"
	}
	if raw, err := os.ReadFile(p("sys", "class", "dmi", "id", "product_name")); err == nil {
		s := strings.ToLower(string(raw))
		switch {
		case strings.Contains(s, "kvm"), strings.Contains(s, "qemu"):
			return "kvm"
		case strings.Contains(s, "vmware"):
			return "vmware"
		case strings.Contains(s, "virtualbox"):
			return "virtualbox"
		}
	}
	return ""
}

// virtualIface reports interfaces created by container runtimes.
func virtualIface(name string) bool {
	for _, pre := range []string{"docker", "veth", "br-", "virbr", "cni", "flannel", "lxc"} {
		if strings.HasPrefix(name, pre) {
			return true
		}
	}
	return false
}

// SortIPs orders public IPv4, private IPv4, public IPv6, private IPv6.
func SortIPs(ips []net.IP) []string {
	rank := func(ip net.IP) int {
		r := 0
		if ip.To4() == nil {
			r += 2
		}
		if ip.IsPrivate() {
			r++
		}
		return r
	}
	sort.SliceStable(ips, func(a, b int) bool {
		ra, rb := rank(ips[a]), rank(ips[b])
		if ra != rb {
			return ra < rb
		}
		return ips[a].String() < ips[b].String()
	})
	out := make([]string, len(ips))
	for i, ip := range ips {
		out[i] = ip.String()
	}
	return out
}

// IPs returns global unicast addresses of physical interfaces.
func IPs() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var ips []net.IP
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || virtualIface(ifc.Name) {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.IsGlobalUnicast() {
				ips = append(ips, ipn.IP)
			}
		}
	}
	return SortIPs(ips)
}

// Collect gathers the full inventory.
func Collect() Inventory {
	rel := OSRelease()
	model, cores := CPU()
	mem, _ := ReadMemory()
	host, _ := os.Hostname()
	ips := IPs()
	primary := ""
	if len(ips) > 0 {
		primary = ips[0]
	}
	return Inventory{
		Hostname:       host,
		OSID:           rel["ID"],
		OSName:         rel["NAME"],
		OSVersion:      rel["VERSION_ID"],
		OSFamily:       OSFamily(rel),
		Kernel:         Kernel(),
		Arch:           runtime.GOARCH,
		CPUModel:       model,
		CPUCores:       cores,
		MemTotalBytes:  mem.Total,
		ControlPanel:   ControlPanel(),
		WebServer:      WebServer(),
		PrimaryIP:      primary,
		IPs:            ips,
		Virtualization: Virtualization(),
	}
}

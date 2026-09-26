package waf

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Target describes how ModSecurity is wired into the local web server.
type Target struct {
	Name        string   `json:"name"` // cpanel | rhel | debian | ""
	ModSec      bool     `json:"modsecurity"`
	IncludeFile string   `json:"include_file"` // file that Includes our rules
	WebServer   string   `json:"web_server"`
	ErrorLogs   []string `json:"error_logs"`

	configTest []string   // command that validates the config
	reload     []string   // command that reloads the web server
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

func firstExisting(paths ...string) string {
	for _, p := range paths {
		if exists(p) {
			return p
		}
	}
	return ""
}

func firstBin(names ...string) string {
	for _, n := range names {
		if filepath.IsAbs(n) {
			if exists(n) {
				return n
			}
			continue
		}
		if p, err := exec.LookPath(n); err == nil {
			return p
		}
	}
	return ""
}

// hasModule reports whether Apache has mod_security2 available.
func hasModule(httpd string) bool {
	if httpd == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, httpd, "-M").CombinedOutput()
	return strings.Contains(string(out), "security2")
}

// Detect finds the local web server and how to hook ModSecurity into it.
func Detect() Target {
	// LiteSpeed / OpenLiteSpeed read ModSecurity rules too.
	switch {
	case exists("/usr/local/cpanel/version"):
		httpd := firstBin("/usr/local/apache/bin/httpd", "/usr/sbin/httpd", "httpd", "apachectl")
		t := Target{
			Name:        "cpanel",
			ModSec:      hasModule(httpd) || exists("/etc/apache2/conf.d/modsec/modsec2.conf") || exists("/etc/apache2/conf.d/modsec2.user.conf"),
			IncludeFile: "/etc/apache2/conf.d/includes/xmartguard-waf.conf",
			WebServer:   "Apache (cPanel EA4)",
			ErrorLogs:   []string{"/etc/apache2/logs/error_log", "/usr/local/apache/logs/error_log"},
			configTest:  []string{firstBin("/scripts/restartsrv_httpd"), "--check"},
			reload:      []string{firstBin("/scripts/restartsrv_httpd")},
		}
		if t.configTest[0] == "" {
			t.configTest = []string{firstBin("/usr/local/apache/bin/httpd", "httpd"), "-t"}
			t.reload = []string{firstBin("/usr/local/apache/bin/apachectl", "apachectl"), "graceful"}
		}
		return t
	case exists("/etc/httpd/conf.d") && hasModule(firstBin("/usr/sbin/httpd", "httpd")):
		return Target{Name: "rhel", ModSec: true, IncludeFile: "/etc/httpd/conf.d/xmartguard-waf.conf",
			WebServer: "Apache", ErrorLogs: []string{"/var/log/httpd/error_log"},
			configTest: []string{firstBin("/usr/sbin/httpd", "httpd"), "-t"},
			reload:     []string{firstBin("apachectl", "/usr/sbin/apachectl"), "graceful"}}
	case exists("/etc/apache2/conf-available") && hasModule(firstBin("/usr/sbin/apache2", "apache2ctl")):
		return Target{Name: "debian", ModSec: true, IncludeFile: "/etc/apache2/conf-available/xmartguard-waf.conf",
			WebServer: "Apache", ErrorLogs: []string{"/var/log/apache2/error.log"},
			configTest: []string{firstBin("apache2ctl", "/usr/sbin/apache2ctl"), "-t"},
			reload:     []string{firstBin("apache2ctl", "/usr/sbin/apache2ctl"), "graceful"}}
	}
	// Apache present but ModSecurity module missing: report so the portal can say so.
	if httpd := firstBin("/usr/local/apache/bin/httpd", "/usr/sbin/httpd", "/usr/sbin/apache2", "httpd", "apache2"); httpd != "" {
		logs := firstExisting("/var/log/httpd/error_log", "/var/log/apache2/error.log", "/etc/apache2/logs/error_log")
		return Target{Name: "", ModSec: false, WebServer: "Apache (mod_security2 not installed)", ErrorLogs: []string{logs}}
	}
	return Target{Name: "", WebServer: "unknown"}
}

// InspectScript writes the small PHP approver ModSecurity calls for uploads.
// It returns "" when it cannot be created; the caller then omits the upload rule.
func InspectScript(dir, agentBin string) string {
	path := filepath.Join(dir, "upload-scan")
	script := "#!/bin/sh\n# XMart Guard ModSecurity upload approver. Exit non-zero rejects the file.\nexec " + agentBin + " scan-upload \"$1\"\n"
	if writeIfChanged(path, script, 0o755) != nil {
		return ""
	}
	return path
}

// dvhosts is the marker span the agent owns inside a shared include file.
const (
	markBegin = "# >>> xmartguard-waf >>>"
	markEnd   = "# <<< xmartguard-waf <<<"
)

func writeIfChanged(path, content string, mode os.FileMode) error {
	if cur, err := os.ReadFile(path); err == nil && string(cur) == content {
		return os.Chmod(path, mode)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".xgtmp"
	if err := os.WriteFile(tmp, []byte(content), mode); err != nil {
		return err
	}
	_ = os.Chmod(tmp, mode)
	return os.Rename(tmp, path)
}

// Install writes the rules and reloads the web server if the config is valid.
// It returns the include file written, or an error explaining what failed.
func (m *Manager) install(t Target, rules string, botFiles map[string]string) error {
	if t.IncludeFile == "" || !t.ModSec {
		return nil // nothing to hook into; the portal shows WAF unavailable
	}
	dir := m.RulesDir
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for name, body := range botFiles {
		if err := writeIfChanged(filepath.Join(dir, name), body, 0o644); err != nil {
			return err
		}
	}
	rulesFile := filepath.Join(dir, "rules.conf")
	if err := writeIfChanged(rulesFile, rules, 0o644); err != nil {
		return err
	}
	include := fmt.Sprintf("%s\n# Managed by xmartguard-agent. Configure in the XMart Guard portal.\n<IfModule security2_module>\nInclude %s\n</IfModule>\n%s\n", markBegin, rulesFile, markEnd)
	prev, _ := os.ReadFile(t.IncludeFile)
	if string(prev) == include {
		return nil // already current; don't reload
	}
	if err := writeIfChanged(t.IncludeFile, include, 0o644); err != nil {
		return err
	}
	// Debian keeps includes under conf-available; enable it once.
	if t.Name == "debian" {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		_ = exec.CommandContext(ctx, firstBin("a2enconf", "/usr/sbin/a2enconf"), "xmartguard-waf").Run()
		cancel()
	}
	if out, err := m.runTimeout(t.configTest, 60*time.Second); err != nil {
		// Roll back so a bad rule never takes the web server down.
		if len(prev) > 0 {
			_ = os.WriteFile(t.IncludeFile, prev, 0o644)
		} else {
			_ = os.Remove(t.IncludeFile)
		}
		return fmt.Errorf("web server rejected the WAF rules (rolled back): %s", strings.TrimSpace(out))
	}
	if out, err := m.runTimeout(t.reload, 120*time.Second); err != nil {
		return fmt.Errorf("WAF rules written but reload failed: %s", strings.TrimSpace(out))
	}
	return nil
}

// remove deletes the include and rules and reloads.
func (m *Manager) uninstall(t Target) error {
	if t.IncludeFile != "" {
		if exists(t.IncludeFile) {
			_ = os.Remove(t.IncludeFile)
			_, _ = m.runTimeout(t.reload, 120*time.Second)
		}
	}
	return os.RemoveAll(m.RulesDir)
}

func (m *Manager) runTimeout(argv []string, d time.Duration) (string, error) {
	if len(argv) == 0 || argv[0] == "" {
		return "", nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	out, err := exec.CommandContext(ctx, argv[0], argv[1:]...).CombinedOutput()
	return string(out), err
}

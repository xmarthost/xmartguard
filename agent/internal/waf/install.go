package waf

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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

	// Engine is the SecRuleEngine the server configures itself: On,
	// DetectionOnly, Off, or "" when nothing sets it (ModSecurity then
	// defaults to Off, so XMart Guard turns it on for its own include).
	Engine string `json:"engine"`
	// LiteSpeed is set when LiteSpeed Web Server serves the sites.
	LiteSpeed bool `json:"litespeed"`
	// Plain: IncludeFile holds the rules themselves (LiteSpeed's native WAF
	// rule set includes it), and Hint says how to hook it in if Hooked is false.
	Plain  bool   `json:"plain"`
	Hooked bool   `json:"hooked"`
	Hint   string `json:"hint"`

	configTest []string // command that validates the config
	reload     []string // command that reloads the web server
}

var reEngine = regexp.MustCompile(`(?mi)^\s*SecRuleEngine\s+(On|Off|DetectionOnly)\b`)

// engineSetting finds the SecRuleEngine configured in the given files/globs.
func engineSetting(globs ...string) string {
	engine := ""
	for _, g := range globs {
		files, _ := filepath.Glob(g)
		for _, f := range files {
			if strings.Contains(f, "xmartguard") {
				continue
			}
			b, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			if m := reEngine.FindAllStringSubmatch(string(b), -1); m != nil {
				engine = m[len(m)-1][1]
			}
		}
	}
	return engine
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
		t.Engine = engineSetting("/etc/apache2/conf.d/modsec2.conf", "/etc/apache2/conf.d/modsec/*.conf")
		// LiteSpeed Enterprise on cPanel reads the same Apache includes but
		// logs ModSecurity to its own error log and must be restarted to
		// load changed rules.
		if exists("/usr/local/lsws/bin/lswsctrl") {
			t.WebServer = "LiteSpeed (cPanel)"
			t.LiteSpeed = true
			t.ErrorLogs = append([]string{"/usr/local/lsws/logs/error.log"}, t.ErrorLogs...)
		}
		if t.configTest[0] == "" {
			t.configTest = []string{firstBin("/usr/local/apache/bin/httpd", "httpd"), "-t"}
			t.reload = []string{firstBin("/usr/local/apache/bin/apachectl", "apachectl"), "graceful"}
		}
		return t
	case exists("/usr/local/lsws/bin/lswsctrl"):
		// Stand-alone LiteSpeed (Enhance, CyberPanel, plain LSWS): LiteSpeed
		// loads ModSecurity rules from a WAF rule set defined in WebAdmin.
		conf, _ := os.ReadFile("/usr/local/lsws/conf/httpd_config.xml")
		return Target{Name: "litespeed", ModSec: true, LiteSpeed: true, Plain: true,
			IncludeFile: "/usr/local/lsws/conf/xmartguard-waf.conf",
			Hooked:      strings.Contains(string(conf), "xmartguard-waf.conf"),
			Hint: "In LiteSpeed WebAdmin (https://SERVER_IP:7080) » Configuration » Server » Security: Enable WAF: Yes, Scan Request Body: Yes. " +
				"Then add a WAF Rule Set: Name: XMartGuard, Action: deny,log,status:403, Enabled: Yes, Rules Definition: Include $SERVER_ROOT/conf/xmartguard-waf.conf — and restart LiteSpeed.",
			WebServer: "LiteSpeed", ErrorLogs: []string{"/usr/local/lsws/logs/error.log"}, Engine: "On",
			reload: []string{"/usr/local/lsws/bin/lswsctrl", "restart"}}
	case exists("/etc/httpd/conf.d") && hasModule(firstBin("/usr/sbin/httpd", "httpd")):
		return Target{Name: "rhel", ModSec: true, IncludeFile: "/etc/httpd/conf.d/xmartguard-waf.conf",
			WebServer: "Apache", ErrorLogs: []string{"/var/log/httpd/error_log"},
			Engine:     engineSetting("/etc/httpd/conf.d/mod_security.conf", "/etc/httpd/modsecurity.d/*.conf"),
			configTest: []string{firstBin("/usr/sbin/httpd", "httpd"), "-t"},
			reload:     []string{firstBin("apachectl", "/usr/sbin/apachectl"), "graceful"}}
	// Debian/Ubuntu: apache2ctl loads /etc/apache2/envvars; plain "apache2 -M" fails without them.
	case exists("/etc/apache2/conf-available") && hasModule(firstBin("apache2ctl", "/usr/sbin/apache2ctl")):
		return Target{Name: "debian", ModSec: true, IncludeFile: "/etc/apache2/conf-available/xmartguard-waf.conf",
			WebServer: "Apache", ErrorLogs: []string{"/var/log/apache2/error.log"},
			Engine:     engineSetting("/etc/modsecurity/*.conf", "/etc/apache2/mods-enabled/security2.conf"),
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
	script := "#!/bin/sh\n# XMart Guard ModSecurity upload approver: prints 1/0 (Apache) and exits 1/0 (LiteSpeed); 0 rejects the file.\nexec " + agentBin + " scan-upload \"$1\"\n"
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
	engine := ""
	if t.Engine == "" {
		// Nothing turns ModSecurity on (Debian/Ubuntu without modsecurity.conf):
		// enable it with body access, which the upload and XML-RPC rules need.
		engine = "SecRuleEngine On\nSecRequestBodyAccess On\n"
	}
	rulesFile := filepath.Join(dir, "rules.conf")
	include := fmt.Sprintf("%s\n# Managed by xmartguard-agent. Configure in the XMart Guard portal.\n<IfModule security2_module>\n%sIncludeOptional %s\n</IfModule>\n%s\n", markBegin, engine, rulesFile, markEnd)
	if t.Plain {
		// LiteSpeed WAF rule set: the file is plain ModSecurity rules.
		include = rules
	}

	// Every file the web server loads, with its previous content for a
	// rollback. Nothing changed: no test, no reload.
	files := map[string]string{rulesFile: rules, t.IncludeFile: include}
	for name, body := range botFiles {
		files[filepath.Join(dir, name)] = body
	}
	prev := map[string][]byte{}
	changed := false
	for path, body := range files {
		old, err := os.ReadFile(path)
		if err == nil {
			prev[path] = old
		}
		if err != nil || string(old) != body {
			changed = true
		}
	}
	if !changed {
		return nil
	}
	rollback := func() {
		for path := range files {
			if old, ok := prev[path]; ok {
				_ = os.WriteFile(path, old, 0o644)
			} else {
				_ = os.Remove(path)
			}
		}
	}
	for path, body := range files {
		if err := writeIfChanged(path, body, 0o644); err != nil {
			rollback()
			return err
		}
	}
	// Debian keeps includes under conf-available; enable it once.
	if t.Name == "debian" {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		_ = exec.CommandContext(ctx, firstBin("a2enconf", "/usr/sbin/a2enconf"), "xmartguard-waf").Run()
		cancel()
	}
	if out, err := m.runTimeout(t.configTest, 60*time.Second); err != nil {
		// Roll back so a bad rule never takes the web server down.
		rollback()
		return fmt.Errorf("web server rejected the WAF rules (rolled back): %s", strings.TrimSpace(out))
	}
	if out, err := m.runTimeout(t.reload, 120*time.Second); err != nil {
		return fmt.Errorf("WAF rules written but reload failed: %s", strings.TrimSpace(out))
	}
	// LiteSpeed only loads changed ModSecurity rules on a (graceful) restart.
	if t.LiteSpeed && !t.Plain {
		if out, err := m.runTimeout([]string{"/usr/local/lsws/bin/lswsctrl", "restart"}, 120*time.Second); err != nil {
			return fmt.Errorf("WAF rules written but LiteSpeed restart failed: %s", strings.TrimSpace(out))
		}
	}
	return nil
}

// remove deletes the include and rules and reloads.
func (m *Manager) uninstall(t Target) error {
	RemoveInclude(t)
	return os.RemoveAll(m.RulesDir)
}

// RemoveInclude unhooks the rules from the web server and reloads it. The
// uninstaller calls it (through "xmartguard-agent cleanup") before deleting
// /etc/xmartguard, so Apache never references a missing file.
func RemoveInclude(t Target) {
	if t.IncludeFile == "" || !exists(t.IncludeFile) {
		return
	}
	if t.Name == "debian" {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		_ = exec.CommandContext(ctx, firstBin("a2disconf", "/usr/sbin/a2disconf"), "-q", "xmartguard-waf").Run()
		cancel()
	}
	_ = os.Remove(t.IncludeFile)
	m := &Manager{}
	_, _ = m.runTimeout(t.reload, 120*time.Second)
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

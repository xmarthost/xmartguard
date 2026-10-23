package waf

import (
	"context"
	"errors"
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
	// defaults to Off, so xPGuard turns it on for its own include).
	Engine string `json:"engine"`
	// LiteSpeed is set when LiteSpeed Web Server serves the sites.
	LiteSpeed bool `json:"litespeed"`
	// Plain: IncludeFile holds the rules themselves (LiteSpeed's native WAF
	// rule set includes it), and Hint says how to hook it in if Hooked is false.
	Plain  bool   `json:"plain"`
	Hooked bool   `json:"hooked"`
	Hint   string `json:"hint"`
	// ModSecCheck says why ModSecurity was not found (what "httpd -M"
	// answered), shown in the portal.
	ModSecCheck string `json:"modsec_check,omitempty"`
	// HookFile, when set, gets an "Include IncludeFile" line (cPanel's
	// modsec2.user.conf, where cPGuard hooks its rules in too).
	HookFile string `json:"hook_file,omitempty"`
	// OldIncludes are include files of earlier versions (before the xPGuard
	// name): removed when the current one is written.
	OldIncludes []string `json:"-"`

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
			if strings.Contains(f, "xpguard") || strings.Contains(f, "xmartguard") {
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
	ok, _ := moduleCheck(httpd)
	return ok
}

// moduleCheck runs "httpd -M"; without security2 in the answer it also
// returns why (a config error, a timeout, LiteSpeed's httpd wrapper).
func moduleCheck(httpd string) (bool, string) {
	if httpd == "" {
		return false, "no httpd program found"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, httpd, "-M").CombinedOutput()
	if strings.Contains(string(out), "security2") {
		return true, ""
	}
	why := strings.TrimSpace(string(out))
	if ctx.Err() != nil {
		why = httpd + " -M took longer than 30 seconds"
	} else if i := strings.IndexByte(why, '\n'); i > 0 && !strings.Contains(strings.ToLower(why[:i]), "error") {
		// The module list itself: keep its first line only.
		why = why[:i]
	}
	if why == "" && err != nil {
		why = err.Error()
	}
	if len(why) > 300 {
		why = why[:300] + "…"
	}
	return false, httpd + " -M: " + why
}

// cpanelModSecFiles are what EasyApache's ea-apache24-mod_security2
// installs: the module and its config with WHM's user rules file.
var cpanelModSecFiles = []string{
	"/etc/apache2/modules/mod_security2.so", "/usr/local/apache/modules/mod_security2.so",
	"/etc/apache2/conf.d/modsec2.conf", "/etc/apache2/conf.d/modsec/modsec2.conf", "/etc/apache2/conf.d/modsec2.user.conf",
}

// procRoot is /proc (tests point it elsewhere).
var procRoot = "/proc"

// LiteSpeedRunning reports whether LiteSpeed Web Server is running (its
// processes are named litespeed or lshttpd; Apache's are httpd).
func LiteSpeedRunning() bool {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.Name()[0] < '0' || e.Name()[0] > '9' {
			continue
		}
		b, err := os.ReadFile(filepath.Join(procRoot, e.Name(), "comm"))
		if err != nil {
			continue
		}
		switch strings.TrimSpace(string(b)) {
		case "litespeed", "lshttpd", "openlitespeed":
			return true
		}
	}
	return false
}

// Detect finds the local web server and how to hook ModSecurity into it.
func Detect() Target {
	// LiteSpeed / OpenLiteSpeed read ModSecurity rules too.
	switch {
	case exists("/usr/local/cpanel/version"):
		httpd := firstBin("/usr/local/apache/bin/httpd", "/usr/sbin/httpd", "httpd", "apachectl")
		// The installed module and its config decide; "httpd -M" can fail
		// for other reasons (LiteSpeed's httpd wrapper, a slow start, an
		// error in another config file) and is only asked without them.
		modsec, why := false, ""
		for _, f := range cpanelModSecFiles {
			if exists(f) {
				modsec = true
				break
			}
		}
		if !modsec {
			modsec, why = moduleCheck(httpd)
		}
		t := Target{
			Name:        "cpanel",
			ModSec:      modsec,
			ModSecCheck: why,
			// Hooked in through WHM's ModSecurity user rules file, which
			// modsec2.conf includes inside its IfModule block (Apache and
			// LiteSpeed read it).
			IncludeFile: CPanelInclude,
			HookFile:    CPanelHookFile,
			OldIncludes: oldCPanelIncludes,
			WebServer:   "Apache (cPanel EA4)",
			ErrorLogs:   []string{"/etc/apache2/logs/error_log", "/usr/local/apache/logs/error_log"},
			configTest:  []string{firstBin("/scripts/restartsrv_httpd"), "--check"},
			reload:      []string{firstBin("/scripts/restartsrv_httpd")},
		}
		t.Engine = engineSetting("/etc/apache2/conf.d/modsec2.conf", "/etc/apache2/conf.d/modsec/*.conf")
		// LiteSpeed Enterprise on cPanel reads the same Apache includes but
		// logs ModSecurity to its own error log and must be restarted to
		// load changed rules. Installed is not enough: a server switched
		// back to Apache (an expired LiteSpeed licence) keeps the files.
		if exists("/usr/local/lsws/bin/lswsctrl") && LiteSpeedRunning() {
			t.WebServer = "LiteSpeed (cPanel)"
			t.LiteSpeed = true
			t.ErrorLogs = append([]string{"/usr/local/lsws/logs/error.log"}, t.ErrorLogs...)
		}
		// restartsrv_httpd --check reports whether the service runs, not
		// whether the new rules parse: on Apache the syntax test is httpd -t
		// (LiteSpeed's httpd wrapper does not take it; there restartsrv's own
		// check stays).
		if !t.LiteSpeed && httpd != "" {
			t.configTest = []string{httpd, "-t"}
		}
		if t.configTest[0] == "" {
			t.configTest = []string{firstBin("/usr/local/apache/bin/httpd", "httpd"), "-t"}
			t.reload = []string{firstBin("/usr/local/apache/bin/apachectl", "apachectl"), "graceful"}
		}
		return t
	case exists("/usr/local/lsws/bin/lswsctrl"):
		// Stand-alone LiteSpeed (Enhance, CyberPanel, plain LSWS): LiteSpeed
		// loads ModSecurity rules from a WAF rule set defined in WebAdmin.
		// The rule set is defined by hand in WebAdmin: a server set up
		// before the xPGuard name keeps the file name it refers to.
		conf, _ := os.ReadFile("/usr/local/lsws/conf/httpd_config.xml")
		name := "xpguard-waf.conf"
		if strings.Contains(string(conf), "xmartguard-waf.conf") {
			name = "xmartguard-waf.conf"
		}
		return Target{Name: "litespeed", ModSec: true, LiteSpeed: true, Plain: true,
			IncludeFile: "/usr/local/lsws/conf/" + name,
			Hooked:      strings.Contains(string(conf), name),
			Hint: "In LiteSpeed WebAdmin (https://SERVER_IP:7080) » Configuration » Server » Security: Enable WAF: Yes, Scan Request Body: Yes. " +
				"Then add a WAF Rule Set: Name: xPGuard, Action: deny,log,status:403, Enabled: Yes, Rules Definition: Include $SERVER_ROOT/conf/xpguard-waf.conf — and restart LiteSpeed.",
			WebServer: "LiteSpeed", ErrorLogs: []string{"/usr/local/lsws/logs/error.log"}, Engine: "On",
			reload: []string{"/usr/local/lsws/bin/lswsctrl", "restart"}}
	case exists("/etc/httpd/conf.d") && hasModule(firstBin("/usr/sbin/httpd", "httpd")):
		return Target{Name: "rhel", ModSec: true, IncludeFile: "/etc/httpd/conf.d/xpguard-waf.conf",
			OldIncludes: []string{"/etc/httpd/conf.d/xmartguard-waf.conf"},
			WebServer:   "Apache", ErrorLogs: []string{"/var/log/httpd/error_log"},
			Engine:     engineSetting("/etc/httpd/conf.d/mod_security.conf", "/etc/httpd/modsecurity.d/*.conf"),
			configTest: []string{firstBin("/usr/sbin/httpd", "httpd"), "-t"},
			reload:     []string{firstBin("apachectl", "/usr/sbin/apachectl"), "graceful"}}
	// Debian/Ubuntu: apache2ctl loads /etc/apache2/envvars; plain "apache2 -M" fails without them.
	case exists("/etc/apache2/conf-available") && hasModule(firstBin("apache2ctl", "/usr/sbin/apache2ctl")):
		return Target{Name: "debian", ModSec: true, IncludeFile: "/etc/apache2/conf-available/xpguard-waf.conf",
			OldIncludes: []string{"/etc/apache2/conf-available/xmartguard-waf.conf"},
			WebServer:   "Apache", ErrorLogs: []string{"/var/log/apache2/error.log"},
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

// On cPanel the agent's ModSecurity file is included from WHM's user rules
// file, like other security products do.
const (
	CPanelInclude  = "/etc/xpguard/waf/xpguard_modsec.conf"
	CPanelHookFile = "/etc/apache2/conf.d/modsec/modsec2.user.conf"
)

// Earlier hook files: conf.d/includes/ (before 0.7.7, never loaded),
// conf.d/zz-xmartguard-waf.conf (0.7.7-0.7.8) and the WHM user rules
// include of 0.7.9-0.10 (under /etc/xmartguard, moved to /etc/xpguard).
var oldCPanelIncludes = []string{"/etc/apache2/conf.d/includes/xmartguard-waf.conf", "/etc/apache2/conf.d/zz-xmartguard-waf.conf",
	"/etc/xmartguard/waf/xmartguard_modsec.conf", "/etc/xpguard/waf/xmartguard_modsec.conf"}

// legacyHook matches Include lines of earlier versions.
func legacyHook(l string) bool {
	return strings.Contains(l, "xmartguard-waf.conf") || strings.Contains(l, "xmartguard_modsec.conf")
}

func hookLine(include string) string { return `Include "` + include + `"` }

// withHook returns content with exactly one Include line for include.
func withHook(content, include string) string {
	var out []string
	for _, l := range strings.Split(strings.TrimRight(content, "\n"), "\n") {
		if strings.Contains(l, include) || legacyHook(l) {
			continue
		}
		out = append(out, l)
	}
	for len(out) > 0 && out[len(out)-1] == "" {
		out = out[:len(out)-1]
	}
	out = append(out, hookLine(include))
	return strings.TrimLeft(strings.Join(out, "\n"), "\n") + "\n"
}

// withoutHook removes the agent's Include line (and those of earlier versions).
func withoutHook(content, include string) string {
	var out []string
	for _, l := range strings.Split(content, "\n") {
		if strings.Contains(l, include) || legacyHook(l) {
			continue
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

// InspectScript writes the small PHP approver ModSecurity calls for uploads.
// It returns "" when it cannot be created; the caller then omits the upload rule.
func InspectScript(dir, agentBin string) string {
	path := filepath.Join(dir, "upload-scan")
	script := "#!/bin/sh\n# xPGuard ModSecurity upload approver: prints 1/0 (Apache) and exits 1/0 (LiteSpeed); 0 rejects the file.\nexec " + agentBin + " scan-upload \"$1\"\n"
	if writeIfChanged(path, script, 0o755) != nil {
		return ""
	}
	return path
}

// dvhosts is the marker span the agent owns inside a shared include file.
const (
	markBegin = "# >>> xpguard-waf >>>"
	markEnd   = "# <<< xpguard-waf <<<"
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
	return m.installMode(t, rules, botFiles, modeNormal)
}

func (m *Manager) installMode(t Target, rules string, botFiles map[string]string, mode applyMode) error {
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
	include := fmt.Sprintf("%s\n# Managed by the xPGuard agent. Configure in the xPGuard portal.\n<IfModule security2_module>\n%sIncludeOptional %s\n</IfModule>\n%s\n", markBegin, engine, rulesFile, markEnd)
	if t.Plain {
		// LiteSpeed WAF rule set: the file is plain ModSecurity rules.
		include = rules
	}

	// Every file the web server loads, with its previous content for a
	// rollback. Nothing changed: no test, no reload.
	files := map[string]string{rulesFile: rules, t.IncludeFile: include}
	if t.HookFile != "" {
		cur, _ := os.ReadFile(t.HookFile)
		files[t.HookFile] = withHook(string(cur), t.IncludeFile)
	}
	for name, body := range botFiles {
		files[filepath.Join(dir, name)] = body
	}
	if t.LiteSpeed && !t.Plain {
		if p := staleRuleSetFile(); p != "" {
			files[p] = staleRuleSetStub
		}
	}
	prev := map[string][]byte{}
	// Include files of earlier versions: removed with the same rollback.
	var stale []string
	for _, o := range t.OldIncludes {
		if o == t.IncludeFile {
			continue
		}
		if fi, err := os.Lstat(o); err == nil && fi.Mode().IsRegular() {
			if b, err := os.ReadFile(o); err == nil {
				prev[o] = b
				stale = append(stale, o)
			}
		}
	}
	m.reloadMu.Lock()
	defer m.reloadMu.Unlock()
	// A reload that failed last time is tried again even when nothing
	// changed since: the files on disk are newer than what runs.
	changed := len(stale) > 0 || m.reloadPending
	listsOnly, urgent := !m.reloadPending, false
	for path, body := range files {
		old, err := os.ReadFile(path)
		if err == nil {
			prev[path] = old
		}
		if err != nil || string(old) != body {
			changed = true
			base := filepath.Base(path)
			if filepath.Dir(path) != filepath.Clean(dir) || !addressLists[base] {
				listsOnly = false
			} else if base == FileCaptchaPass && addsLines(string(old), body) {
				urgent = true // a visitor just solved the CAPTCHA
			}
		}
	}
	if !changed {
		return nil
	}
	// Every change reloads the web server, and LiteSpeed restarts for it.
	// Address lists change all day (bans, the IPDB, CAPTCHA suspects), and
	// periodic refreshes (learned exclusions, fleet intelligence) come on
	// their own: they wait until the last reload is old enough, so a busy
	// server is not restarted every few minutes. Changes someone made apply
	// at once. A visitor who solved the CAPTCHA is sent back when this
	// returns, so that reload is never put off: it only waits out a short
	// gap (passes arriving meanwhile share the reload).
	wait := func(gap time.Duration) time.Duration {
		if m.lastReload.IsZero() || len(stale) > 0 || mode == modeNow {
			return 0
		}
		return gap - time.Since(m.lastReload)
	}
	switch {
	case listsOnly && urgent:
		if w := wait(ListReloadGap(t.LiteSpeed, true)); w > 0 {
			time.Sleep(w)
		}
	case listsOnly || mode == modeBackground:
		if w := wait(ListReloadGap(t.LiteSpeed, false)); w > 0 {
			if m.deferred == nil {
				m.deferred = time.AfterFunc(w+time.Second, func() {
					m.reloadMu.Lock()
					m.deferred = nil
					m.reloadMu.Unlock()
					_ = m.ApplyBackground()
				})
			}
			return nil
		}
	}
	rollback := func() {
		for path := range files {
			if old, ok := prev[path]; ok {
				_ = os.WriteFile(path, old, 0o644)
			} else {
				_ = os.Remove(path)
			}
		}
		for _, o := range stale {
			_ = os.WriteFile(o, prev[o], 0o644)
		}
		if t.Name == "debian" && len(stale) > 0 {
			a2conf("a2enconf", "xmartguard-waf")
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
		a2conf("a2enconf", "xpguard-waf")
		if len(stale) > 0 {
			a2conf("a2disconf", "xmartguard-waf")
		}
	}
	for _, o := range stale {
		_ = os.Remove(o)
	}
	// On cPanel with LiteSpeed the test is restartsrv_httpd --check, which
	// only says whether the web server runs. Caught while LiteSpeed was
	// restarting ("The httpd service is down") it rolled back rules that
	// LiteSpeed had not even read yet: settings never reached business200
	// (13 times in a day). That answer is asked again; if LiteSpeed is still
	// down the new rules are not the cause (they load on the restart
	// below), so they are kept and checked once more after the restart.
	checkAfter := false
	out, err := m.runTimeout(t.configTest, 60*time.Second)
	if err != nil && t.LiteSpeed && !t.Plain && serviceDown(out) {
		out, err = m.checkUp(t)
		if err != nil && serviceDown(out) {
			err, checkAfter = nil, true
		}
	}
	if err != nil {
		// Roll back so a bad rule never takes the web server down.
		rollback()
		return fmt.Errorf("web server rejected the WAF rules (rolled back): %s", strings.TrimSpace(out))
	}
	m.lastReload = time.Now()
	// LiteSpeed only loads changed ModSecurity rules on a (graceful)
	// restart, and on cPanel restartsrv_httpd restarts LiteSpeed too: one
	// restart, never two in a row (a second restart while the first is
	// still starting can leave LiteSpeed down).
	reload := t.reload
	if t.LiteSpeed && !t.Plain {
		reload = liteSpeedRestart
	}
	if out, err := m.runTimeout(reload, 120*time.Second); err != nil {
		m.reloadPending = true
		return fmt.Errorf("WAF rules written but reload failed (retried on the next apply): %s", strings.TrimSpace(out))
	}
	if checkAfter {
		if out, err := m.checkUp(t); err != nil {
			// Down after loading the new rules: put the old ones back.
			rollback()
			_, _ = m.runTimeout(reload, 120*time.Second)
			return fmt.Errorf("web server did not start with the WAF rules (rolled back): %s", strings.TrimSpace(out))
		}
	}
	m.reloadPending = false
	// A visitor who solved the CAPTCHA is sent back when this returns:
	// give LiteSpeed's new server processes a moment to take over.
	if urgent && t.LiteSpeed {
		time.Sleep(PassSettle)
	}
	return nil
}

// PassSettle is how long a LiteSpeed restart for a solved CAPTCHA is given
// to start its new server processes before the visitor is sent back.
var PassSettle = 3 * time.Second

// passRefreshGap is the least time between two reloads RefreshPasses asks for.
const passRefreshGap = 20 * time.Second

// RefreshPasses reloads the web server for an address that solved the
// CAPTCHA again although it is already on the pass list: the earlier
// reload has not reached it (LiteSpeed's old server processes keep a
// visitor's open connections for a while after a graceful restart), and
// the visitor is sent to the CAPTCHA page again and again. Reloads at most
// every 20 seconds.
func (m *Manager) RefreshPasses() error {
	m.mu.Lock()
	t := m.target
	m.mu.Unlock()
	if !t.ModSec || len(t.reload) == 0 {
		return nil
	}
	m.reloadMu.Lock()
	defer m.reloadMu.Unlock()
	if !m.lastReload.IsZero() && time.Since(m.lastReload) < passRefreshGap {
		return nil
	}
	reload := t.reload
	if t.LiteSpeed && !t.Plain {
		reload = liteSpeedRestart
	}
	m.lastReload = time.Now()
	if out, err := m.runTimeout(reload, 120*time.Second); err != nil {
		return fmt.Errorf("reload failed: %s", strings.TrimSpace(out))
	}
	if t.LiteSpeed {
		time.Sleep(PassSettle)
	}
	return nil
}

// PassReloadWait is how long a solved CAPTCHA still waits for its reload
// (the rest of the gap since the last one). The agent waits it out before it
// writes the pass list, so passes that arrive meanwhile go out with the same
// reload instead of each waiting a full gap after the one before.
func (m *Manager) PassReloadWait() time.Duration {
	m.mu.Lock()
	liteSpeed := m.target.LiteSpeed
	m.mu.Unlock()
	m.reloadMu.Lock()
	defer m.reloadMu.Unlock()
	if m.lastReload.IsZero() {
		return 0
	}
	return ListReloadGap(liteSpeed, true) - time.Since(m.lastReload)
}

// serviceDown reports restartsrv's answer for a web server that is not
// running (as opposed to a configuration it refused).
func serviceDown(out string) bool {
	o := strings.ToLower(out)
	return strings.Contains(o, "service is down") || strings.Contains(o, "is not running")
}

// ServiceDownWait is how long a LiteSpeed restart is given before the
// web server check is asked again (tests set it to zero).
var ServiceDownWait = 10 * time.Second

// checkUp asks the web server check again while LiteSpeed finishes a
// restart: up to three times, ServiceDownWait apart.
func (m *Manager) checkUp(t Target) (string, error) {
	var out string
	var err error
	for i := 0; i < 3; i++ {
		time.Sleep(ServiceDownWait)
		if out, err = m.runTimeout(t.configTest, 60*time.Second); err == nil || !serviceDown(out) {
			return out, err
		}
	}
	return out, err
}

// LiteSpeedConf is LiteSpeed's server configuration (tests replace it).
var LiteSpeedConf = "/usr/local/lsws/conf/httpd_config.xml"

// staleRuleSetStub fills a WAF rule set file that only the stand-alone
// LiteSpeed setup uses.
const staleRuleSetStub = "# Managed by the xPGuard agent.\n# On cPanel, LiteSpeed loads the xPGuard rules through ModSecurity's\n# modsec2.user.conf; this WebAdmin rule set is not needed and is kept\n# empty so LiteSpeed never fails on a missing file.\n"

// staleRuleSetFile is the file of an xPGuard WAF rule set defined in
// LiteSpeed WebAdmin on a cPanel server (made by hand from the stand-alone
// instructions, or by an older setup) when that file is missing: the
// rules reach LiteSpeed through modsec2.user.conf, but a rule set naming
// a missing file fails as soon as someone switches it on (business200).
func staleRuleSetFile() string {
	conf, err := os.ReadFile(LiteSpeedConf)
	if err != nil {
		return ""
	}
	dir := filepath.Dir(LiteSpeedConf)
	for _, name := range []string{"xpguard-waf.conf", "xmartguard-waf.conf"} {
		if !strings.Contains(string(conf), name) {
			continue
		}
		p := filepath.Join(dir, name)
		if _, err := os.Lstat(p); errors.Is(err, os.ErrNotExist) {
			return p
		}
	}
	return ""
}

// liteSpeedRestart restarts LiteSpeed gracefully (tests replace it).
var liteSpeedRestart = []string{"/usr/local/lsws/bin/lswsctrl", "restart"}

// addressLists are the WAF's address files: they change on their own
// (bans, IPDB, CAPTCHA, Tor), not because rules or settings changed.
// The whitelist, trusted and exempt lists are not here: they change when
// someone edits them, and apply at once.
var addressLists = map[string]bool{FileBlockedIPs: true, FileIPDBIPs: true, FileTorIPs: true,
	FileCaptchaSuspects: true, FileCaptchaPass: true, FileStrictIPs: true}

// ListReloadGap is the least time between two reloads for address list
// changes: LiteSpeed restarts its server processes on every reload, Apache
// only re-reads its configuration. A visitor who solved the CAPTCHA waits
// the least (the portal waits 90 seconds for the server; passes that arrive
// while one waits share its reload, see PassReloadWait). Tests set it to
// zero.
var ListReloadGap = func(liteSpeed, captchaPass bool) time.Duration {
	switch {
	case captchaPass && liteSpeed:
		return 30 * time.Second
	case captchaPass:
		return 10 * time.Second
	case liteSpeed:
		return 2 * time.Hour
	default:
		return 15 * time.Minute
	}
}

// addsLines reports whether next has a line that cur does not.
func addsLines(cur, next string) bool {
	have := map[string]bool{}
	for _, l := range strings.Split(cur, "\n") {
		have[l] = true
	}
	for _, l := range strings.Split(next, "\n") {
		if l != "" && !have[l] {
			return true
		}
	}
	return false
}

// remove deletes the include and rules and reloads.
func (m *Manager) uninstall(t Target) error {
	RemoveInclude(t)
	return os.RemoveAll(m.RulesDir)
}

// a2conf runs a2enconf/a2disconf (Debian) for one include.
func a2conf(tool, name string) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	args := []string{name}
	if tool == "a2disconf" {
		args = []string{"-q", name}
	}
	_ = exec.CommandContext(ctx, firstBin(tool, "/usr/sbin/"+tool), args...).Run()
}

// RemoveInclude unhooks the rules from the web server and reloads it. The
// uninstaller calls it (through "xpguard-agent cleanup") before deleting
// /etc/xpguard, so Apache never references a missing file.
func RemoveInclude(t Target) {
	had := false
	for _, o := range t.OldIncludes {
		if exists(o) {
			had = true
			_ = os.Remove(o)
		}
	}
	if t.Name == "debian" && had {
		a2conf("a2disconf", "xmartguard-waf")
	}
	if t.HookFile != "" {
		if cur, err := os.ReadFile(t.HookFile); err == nil {
			if nb := withoutHook(string(cur), t.IncludeFile); nb != string(cur) {
				_ = os.WriteFile(t.HookFile, []byte(nb), 0o644)
			}
		}
	}
	if t.IncludeFile == "" || !exists(t.IncludeFile) {
		return
	}
	if t.Name == "debian" {
		a2conf("a2disconf", "xpguard-waf")
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

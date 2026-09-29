// Package monitor watches what runs on the server: processes started by
// hosting users (the "proactive process monitor"), their cron jobs, and a
// weekly rootkit check with rkhunter when it is installed.
package monitor

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/settings"
	"github.com/xmarthost/xmartguard/agent/internal/store"
)

// Event is one process, cron or rootkit alert.
type Event struct {
	ID      int64  `json:"id"`
	At      int64  `json:"at"`
	Kind    string `json:"kind"` // process | cron | rootkit
	User    string `json:"user"`
	Subject string `json:"subject"` // command line, cron line or check name
	Reason  string `json:"reason"`
	Action  string `json:"action"` // alerted | killed
}

// Monitor runs the checks.
type Monitor struct {
	DB       *sql.DB
	Settings *settings.Store
	Log      *slog.Logger
	// Users maps hosting user names to home directories.
	Users func() map[string]string
	// OnEvent is called for new events (notifications).
	OnEvent func(Event)

	// Overridable for tests.
	ProcRoot  string
	CronDirs  []string
	Rkhunter  string
	killed    map[int]bool
	processed map[string]bool
}

func (m *Monitor) init() {
	if m.ProcRoot == "" {
		m.ProcRoot = "/proc"
	}
	if m.CronDirs == nil {
		m.CronDirs = []string{"/var/spool/cron", "/var/spool/cron/crontabs"}
	}
	if m.Rkhunter == "" {
		for _, p := range []string{"/usr/bin/rkhunter", "/usr/local/bin/rkhunter", "/bin/rkhunter"} {
			if _, err := os.Stat(p); err == nil {
				m.Rkhunter = p
				break
			}
		}
	}
	if m.killed == nil {
		m.killed = map[int]bool{}
		m.processed = map[string]bool{}
	}
}

// Run checks processes every minute, cron every 10 minutes and rootkits weekly.
func (m *Monitor) Run(ctx context.Context) {
	m.init()
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	n := 0
	for {
		st := m.Settings.Get()
		if st.Processes.Enabled {
			m.CheckProcesses()
		}
		if st.Cron.Enabled && n%10 == 0 {
			m.CheckCron()
		}
		if st.Rootkit.Enabled && n%60 == 0 {
			m.maybeRootkit(ctx)
		}
		n++
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (m *Monitor) record(e Event) {
	e.At = store.Now()
	res, err := m.DB.Exec(`INSERT INTO monitor_events (at, kind, user, subject, reason, action) VALUES (?,?,?,?,?,?)`,
		e.At, e.Kind, e.User, truncate(e.Subject, 500), e.Reason, e.Action)
	if err == nil {
		e.ID, _ = res.LastInsertId()
	}
	m.Log.Warn("monitor alert", "kind", e.Kind, "user", e.User, "reason", e.Reason, "action", e.Action)
	if m.OnEvent != nil {
		m.OnEvent(e)
	}
}

// once reports whether key is new (alerts fire once per distinct finding).
func (m *Monitor) once(key string) bool {
	sum := sha256.Sum256([]byte(key))
	k := hex.EncodeToString(sum[:12])
	if m.processed[k] {
		return false
	}
	var n int
	_ = m.DB.QueryRow(`SELECT count(*) FROM kv WHERE key = ?`, "mon:"+k).Scan(&n)
	m.processed[k] = true
	if n > 0 {
		return false
	}
	_ = store.SetKV(m.DB, "mon:"+k, strconv.FormatInt(store.Now(), 10))
	return true
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// ------------------------------------------------------------ processes

// Indicators in a process command line (cryptominers and reverse shells).
var procBad = []struct {
	re     *regexp.Regexp
	reason string
}{
	{regexp.MustCompile(`(?i)stratum\+(?:tcp|ssl)://`), "cryptominer (mining pool connection)"},
	{regexp.MustCompile(`(?i)\b(?:xmrig|xmr-stak|minerd|cpuminer|ccminer|nbminer|t-rex|lolminer)\b`), "cryptominer"},
	{regexp.MustCompile(`(?i)--donate-level|--cpu-max-threads-hint|randomx`), "cryptominer options"},
	{regexp.MustCompile(`/dev/tcp/\d{1,3}(?:\.\d{1,3}){3}/\d+`), "reverse shell"},
	{regexp.MustCompile(`(?i)\b(?:nc|ncat|netcat)\b.*\s-(?:e|c)\s`), "reverse shell (netcat)"},
	{regexp.MustCompile(`(?i)socat\s.*exec:`), "reverse shell (socat)"},
}

// Places where hosting users have no reason to run programs from.
var tmpDirs = []string{"/tmp/", "/var/tmp/", "/dev/shm/"}

// systemExeDirs hold the programs of installed packages (distribution,
// cPanel EasyApache, CloudLinux alt-php, LiteSpeed).
var systemExeDirs = []string{"/usr", "/bin", "/sbin", "/lib", "/lib64", "/opt/cpanel", "/opt/alt", "/opt/remi", "/usr/local/lsws", "/opt/plesk"}

func underAny(p string, dirs []string) bool {
	for _, d := range dirs {
		if p == d || strings.HasPrefix(p, d+"/") {
			return true
		}
	}
	return false
}

// ProcInfo is what the monitor reads about a process.
type ProcInfo struct {
	PID     int
	UID     uint32
	User    string
	Exe     string
	Cmdline string
}

// Judge decides whether a process of a hosting user is malicious.
func Judge(p ProcInfo, home string) (string, bool) {
	for _, b := range procBad {
		if b.re.MatchString(p.Cmdline) {
			return b.reason, true
		}
	}
	exe := p.Exe
	if strings.HasSuffix(exe, " (deleted)") {
		exe = strings.TrimSuffix(exe, " (deleted)")
		// An update of a system package (PHP, LiteSpeed's lsphp) replaces
		// the program while old processes keep running: their program shows
		// as deleted. Only programs deleted from elsewhere (a temp or home
		// folder, or memory-only "memfd:" programs) are hiding.
		if !underAny(exe, systemExeDirs) {
			return "running program was deleted from disk (a common way to hide malware)", true
		}
	}
	for _, d := range tmpDirs {
		if strings.HasPrefix(exe, d) {
			return "program runs from " + strings.TrimSuffix(d, "/"), true
		}
	}
	// A compiled program inside the account's website folders.
	if home != "" && strings.HasPrefix(exe, home+"/") && strings.Contains(exe, "/public_html/") {
		return "program runs from the website folder", true
	}
	if strings.Contains(exe, "/.") && home != "" && strings.HasPrefix(exe, home+"/") {
		return "program runs from a hidden folder in the home directory", true
	}
	return "", false
}

func (m *Monitor) procs() []ProcInfo {
	entries, err := os.ReadDir(m.ProcRoot)
	if err != nil {
		return nil
	}
	names := map[uint32]string{}
	var out []ProcInfo
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		dir := filepath.Join(m.ProcRoot, e.Name())
		st, err := os.Stat(dir)
		if err != nil {
			continue
		}
		sys, ok := st.Sys().(*syscall.Stat_t)
		if !ok || sys.Uid < 500 {
			continue // system accounts
		}
		exe, _ := os.Readlink(filepath.Join(dir, "exe"))
		raw, _ := os.ReadFile(filepath.Join(dir, "cmdline"))
		cmd := strings.TrimSpace(strings.ReplaceAll(string(raw), "\x00", " "))
		if cmd == "" {
			continue // kernel thread or exited
		}
		name, ok := names[sys.Uid]
		if !ok {
			name = userName(sys.Uid)
			names[sys.Uid] = name
		}
		out = append(out, ProcInfo{PID: pid, UID: sys.Uid, User: name, Exe: exe, Cmdline: cmd})
	}
	return out
}

func userName(uid uint32) string {
	raw, err := os.ReadFile("/etc/passwd")
	if err == nil {
		for _, l := range strings.Split(string(raw), "\n") {
			f := strings.Split(l, ":")
			if len(f) > 2 && f[2] == strconv.Itoa(int(uid)) {
				return f[0]
			}
		}
	}
	return strconv.Itoa(int(uid))
}

// CheckProcesses scans running processes once.
func (m *Monitor) CheckProcesses() {
	m.init()
	cfg := m.Settings.Get().Processes
	homes := map[string]string{}
	if m.Users != nil {
		homes = m.Users()
	}
	for _, p := range m.procs() {
		if contains(cfg.WhitelistUsers, p.User) || matchesAny(p.Cmdline+" "+p.Exe, cfg.WhitelistStrings) {
			continue
		}
		home, hosting := homes[p.User]
		if !hosting && len(homes) > 0 {
			continue // only hosting accounts
		}
		reason, bad := Judge(p, home)
		if !bad {
			continue
		}
		action := "alerted"
		if cfg.Kill && !m.killed[p.PID] {
			if err := syscall.Kill(p.PID, syscall.SIGKILL); err == nil {
				action = "killed"
				m.killed[p.PID] = true
			}
		}
		if action == "killed" || m.once(fmt.Sprintf("proc|%s|%s|%s", p.User, p.Exe, p.Cmdline)) {
			m.record(Event{Kind: "process", User: p.User, Subject: fmt.Sprintf("[%d] %s", p.PID, p.Cmdline), Reason: reason, Action: action})
		}
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func matchesAny(s string, subs []string) bool {
	for _, x := range subs {
		if x != "" && strings.Contains(s, x) {
			return true
		}
	}
	return false
}

// ------------------------------------------------------------ cron

var cronBad = []struct {
	re     *regexp.Regexp
	reason string
}{
	{regexp.MustCompile(`(?i)\b(?:curl|wget|fetch)\b[^|;]*\|\s*(?:ba|z|da)?sh\b`), "downloads and runs a script"},
	{regexp.MustCompile(`(?i)\b(?:curl|wget)\b[^;|]*(?:-o|-O)\s*\S*(?:/tmp/|/dev/shm/|/var/tmp/)`), "downloads a file into a temporary folder"},
	{regexp.MustCompile(`(?i)base64\s+(?:-d|--decode)[^|]*\|\s*(?:ba)?sh`), "runs base64-encoded commands"},
	{regexp.MustCompile(`/dev/tcp/`), "opens a raw network connection"},
	{regexp.MustCompile(`(?:^|\s)(?:/tmp/|/dev/shm/|/var/tmp/)\S+`), "runs a program from a temporary folder"},
	{regexp.MustCompile(`(?i)stratum\+tcp|xmrig|minerd|\bkinsing\b|kdevtmpfsi|kthreaddi|\btsm64\b`), "cryptominer"},
	{regexp.MustCompile(`(?i)gs-netcat|\bGS_ARGS\b|gsocket|\bdefunct\.dat\b`), "backdoor (gsocket)"},
	{regexp.MustCompile(`(?i)\b(?:python[0-9.]*|perl|php)\s+-(?:c|e|r)\s+['"].*(?:base64|decode|exec|eval|socket)`), "runs inline encoded code"},
	{regexp.MustCompile(`/\.[a-z0-9_-]{1,20}/[^ ]*\s*>\s*/dev/null\s+2>&1\s*&?$`), "silently runs a program from a hidden folder"},
	{regexp.MustCompile(`(?i)^@reboot\s+(?:\S+/)?(?:nohup\s+)?\S*/\.[^/\s]+/`), "starts a program from a hidden folder at every boot"},
	{regexp.MustCompile(`(?i)/(?:wp-content/)?uploads/\S+\.(?:php\d?|phtml|sh|pl|py|cgi)\b`), "runs a script from an uploads folder"},
}

// JudgeCron returns why a crontab line is malicious, if it is.
func JudgeCron(line string) (string, bool) {
	l := strings.TrimSpace(line)
	if l == "" || strings.HasPrefix(l, "#") || strings.Contains(strings.SplitN(l, " ", 2)[0], "=") {
		return "", false
	}
	for _, b := range cronBad {
		if b.re.MatchString(l) {
			return b.reason, true
		}
	}
	return "", false
}

// DisabledPrefix marks a crontab line the monitor switched off; the rest of
// the line is the original, so removing the prefix restores it.
const DisabledPrefix = "#xpguard-disabled# "

var rePathToken = regexp.MustCompile(`/[^\s;|&'"<>]+`)

// runsMalware reports whether the line runs a file the scanner found
// malicious (still on disk or quarantined).
func (m *Monitor) runsMalware(line string) bool {
	for _, p := range rePathToken.FindAllString(line, 8) {
		if !strings.HasPrefix(p, "/home") {
			continue
		}
		var n int
		_ = m.DB.QueryRow(`SELECT count(*) FROM findings WHERE path = ? AND category = 'virus' AND status IN ('detected','quarantined','disabled')`, p).Scan(&n)
		if n > 0 {
			return true
		}
	}
	return false
}

func cronAllowKey(user, line string) string {
	sum := sha256.Sum256([]byte(user + "|" + strings.TrimSpace(line)))
	return "cron-allow:" + hex.EncodeToString(sum[:12])
}

// CheckCron reads every user crontab once; malicious lines are reported and,
// with cron.disable, commented out.
func (m *Monitor) CheckCron() {
	m.init()
	cfg := m.Settings.Get().Cron
	for _, dir := range m.CronDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || e.Name() == "root" || strings.HasPrefix(e.Name(), ".") || strings.HasPrefix(e.Name(), "tmp.") || contains(cfg.WhitelistUsers, e.Name()) {
				continue
			}
			file := filepath.Join(dir, e.Name())
			raw, err := os.ReadFile(file)
			if err != nil || len(raw) > 1<<20 {
				continue
			}
			lines := strings.Split(string(raw), "\n")
			type hit struct {
				i      int
				reason string
			}
			var hits []hit
			for i, line := range lines {
				reason, bad := JudgeCron(line)
				if !bad && strings.TrimSpace(line) != "" && !strings.HasPrefix(strings.TrimSpace(line), "#") && m.runsMalware(line) {
					reason, bad = "runs a file detected as malware", true
				}
				if !bad || store.GetKV(m.DB, cronAllowKey(e.Name(), line)) != "" {
					continue
				}
				hits = append(hits, hit{i, reason})
			}
			if len(hits) == 0 {
				continue
			}
			disabled := false
			if cfg.Disable {
				out := append([]string(nil), lines...)
				for _, h := range hits {
					out[h.i] = DisabledPrefix + strings.TrimSpace(lines[h.i])
				}
				if err := m.writeCrontab(e.Name(), file, strings.Join(out, "\n")); err != nil {
					m.Log.Warn("could not disable malicious cron job", "user", e.Name(), "err", err)
				} else {
					disabled = true
				}
			}
			for _, h := range hits {
				line := strings.TrimSpace(lines[h.i])
				if disabled {
					m.record(Event{Kind: "cron", User: e.Name(), Subject: line, Reason: h.reason, Action: "disabled"})
				} else if m.once("cron|" + e.Name() + "|" + lines[h.i]) {
					m.record(Event{Kind: "cron", User: e.Name(), Subject: line, Reason: h.reason, Action: "alerted"})
				}
			}
		}
	}
}

// Crontab is the crontab program (tests set it to "" to write files).
var Crontab = "/usr/bin/crontab"

// writeCrontab installs content as user's crontab. crontab(1) is used when
// present so the cron daemon notices the change; otherwise the spool file
// is replaced keeping its owner and mode.
func (m *Monitor) writeCrontab(user, file, content string) error {
	if !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	if Crontab != "" {
		if _, err := os.Stat(Crontab); err == nil {
			// Debian's spool files start with a header crontab(1) writes
			// itself; passing it back would add a second one.
			for strings.HasPrefix(content, "# DO NOT EDIT THIS FILE") || strings.HasPrefix(content, "# (") {
				_, content, _ = strings.Cut(content, "\n")
			}
			cmd := exec.Command(Crontab, "-u", user, "-")
			cmd.Stdin = strings.NewReader(content)
			if out, err := cmd.CombinedOutput(); err != nil {
				return fmt.Errorf("crontab: %v: %s", err, strings.TrimSpace(string(out)))
			}
			return nil
		}
	}
	fi, err := os.Stat(file)
	if err != nil {
		return err
	}
	tmp := file + ".xgtmp"
	if err := os.WriteFile(tmp, []byte(content), fi.Mode().Perm()); err != nil {
		return err
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		_ = os.Chown(tmp, int(st.Uid), int(st.Gid))
	}
	return os.Rename(tmp, file)
}

// EnableCron puts a line the monitor disabled back into user's crontab and
// remembers it as allowed, so it is not disabled again.
func (m *Monitor) EnableCron(user, line string) error {
	m.init()
	line = strings.TrimSpace(line)
	if user == "" || strings.ContainsAny(user, "/.") || line == "" {
		return fmt.Errorf("invalid cron job")
	}
	for _, dir := range m.CronDirs {
		file := filepath.Join(dir, user)
		raw, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		lines := strings.Split(string(raw), "\n")
		found := false
		for i, l := range lines {
			if strings.TrimSpace(l) == DisabledPrefix+line || strings.TrimSpace(l) == strings.TrimSpace(DisabledPrefix)+" "+line {
				lines[i], found = line, true
			}
		}
		if !found {
			continue
		}
		_ = store.SetKV(m.DB, cronAllowKey(user, line), strconv.FormatInt(store.Now(), 10))
		if err := m.writeCrontab(user, file, strings.Join(lines, "\n")); err != nil {
			_ = store.SetKV(m.DB, cronAllowKey(user, line), "")
			return err
		}
		m.Log.Info("cron job re-enabled by the administrator", "user", user)
		return nil
	}
	return fmt.Errorf("the disabled cron job was not found in %s's crontab", user)
}

// ------------------------------------------------------------ rootkits

func (m *Monitor) maybeRootkit(ctx context.Context) {
	if m.Rkhunter == "" {
		return
	}
	last, _ := strconv.ParseInt(store.GetKV(m.DB, "rkhunter_last"), 10, 64)
	if store.Now()-last < 7*86400 {
		return
	}
	_ = store.SetKV(m.DB, "rkhunter_last", strconv.FormatInt(store.Now(), 10))
	m.RunRootkit(ctx)
}

// RunRootkit runs rkhunter now and records its warnings.
func (m *Monitor) RunRootkit(ctx context.Context) (int, error) {
	m.init()
	if m.Rkhunter == "" {
		return 0, fmt.Errorf("rkhunter is not installed (dnf install rkhunter / apt install rkhunter)")
	}
	cctx, cancel := context.WithTimeout(ctx, time.Hour)
	defer cancel()
	out, _ := exec.CommandContext(cctx, m.Rkhunter, "--check", "--skip-keypress", "--nocolors", "--report-warnings-only").CombinedOutput()
	n := 0
	for _, l := range strings.Split(string(out), "\n") {
		l = strings.TrimSpace(l)
		if !strings.HasPrefix(l, "Warning:") {
			continue
		}
		n++
		if m.once("rk|" + l) {
			m.record(Event{Kind: "rootkit", User: "root", Subject: strings.TrimSpace(strings.TrimPrefix(l, "Warning:")), Reason: "rkhunter warning", Action: "alerted"})
		}
	}
	_ = store.SetKV(m.DB, "rkhunter_result", fmt.Sprintf("%d|%d", store.Now(), n))
	return n, nil
}

// Status summarises the monitors for the portal.
func (m *Monitor) Status() map[string]any {
	m.init()
	var last, warnings int64
	if v := store.GetKV(m.DB, "rkhunter_result"); v != "" {
		a, b, _ := strings.Cut(v, "|")
		last, _ = strconv.ParseInt(a, 10, 64)
		warnings, _ = strconv.ParseInt(b, 10, 64)
	}
	return map[string]any{"rkhunter": m.Rkhunter != "", "rkhunter_last": last, "rkhunter_warnings": warnings}
}

// Events lists alerts, newest first.
func (m *Monitor) Events(kind string, limit, offset int) ([]Event, int, error) {
	where, args := "1=1", []any{}
	if kind != "" {
		where, args = "kind = ?", append(args, kind)
	}
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	var total int
	_ = m.DB.QueryRow(`SELECT count(*) FROM monitor_events WHERE `+where, args...).Scan(&total)
	rows, err := m.DB.Query(`SELECT id, at, kind, user, subject, reason, action FROM monitor_events WHERE `+where+` ORDER BY id DESC LIMIT ? OFFSET ?`, append(args, limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		var e Event
		if rows.Scan(&e.ID, &e.At, &e.Kind, &e.User, &e.Subject, &e.Reason, &e.Action) == nil {
			out = append(out, e)
		}
	}
	return out, total, nil
}

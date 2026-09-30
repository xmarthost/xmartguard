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
	// cpu is the previous CPU reading of each flagged process.
	cpu map[cpuKey]cpuSample
}

type cpuKey struct {
	pid   int
	start uint64
}

type cpuSample struct {
	ticks uint64
	at    time.Time
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
		m.cpu = map[cpuKey]cpuSample{}
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

// devToolDirs are hidden folders in a home directory where developer tools
// keep their programs (Node.js through nvm, PM2, Bun, Volta, pip --user,
// Rust, Puppeteer's Chrome …): running from them is normal.
var devToolDirs = []string{".nvm", ".volta", ".fnm", ".n", ".nodenv", ".bun", ".deno", ".npm", ".npm-global", ".pm2", ".yarn",
	".pnpm", ".pnpm-store", ".local/bin", ".local/share/pnpm", ".local/share/fnm", ".local/share/uv", ".cargo", ".rustup",
	".pyenv", ".rbenv", ".rvm", ".gem", ".sdkman", ".asdf", ".jdks", ".dotnet", ".composer", ".config/composer",
	".cache/puppeteer", ".cache/ms-playwright", ".cache/node", ".vscode-server", ".cursor-server", ".linuxbrew", ".nix-profile"}

// inDevTools reports a program of a developer tool: in one of the tool
// folders of the home directory, or in a project's node_modules.
func inDevTools(exe, home string) bool {
	if strings.Contains(exe, "/node_modules/") {
		return true
	}
	if home == "" || !strings.HasPrefix(exe, home+"/") {
		return false
	}
	rel := strings.TrimPrefix(exe, home+"/")
	for _, d := range devToolDirs {
		if rel == d || strings.HasPrefix(rel, d+"/") {
			return true
		}
	}
	return false
}

// Level is how sure a finding is.
type Level int

const (
	// Clean: nothing found.
	Clean Level = iota
	// Suspicious: an unusual place to run a program from (temporary or
	// hidden folder, deleted program). Only reported, and killed only when
	// it keeps a CPU core busy for a long time (a miner).
	Suspicious
	// Malicious: a cryptominer or reverse shell by its command line.
	Malicious
)

// Kill policy for suspicious processes: running at least this long and
// using at least this share of one CPU core, over its life and since the
// previous check.
const (
	SuspectMinAge = 30 * time.Minute
	SuspectMinCPU = 0.5
)

// ShouldKill decides whether to kill a process the monitor flagged (with
// killing switched on): malicious ones at once, suspicious ones only when
// they have kept a CPU core busy for a long time.
func ShouldKill(level Level, age time.Duration, lifeCPU, recentCPU float64) bool {
	switch level {
	case Malicious:
		return true
	case Suspicious:
		return age >= SuspectMinAge && lifeCPU >= SuspectMinCPU && recentCPU >= SuspectMinCPU
	}
	return false
}

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
	// Age is how long it has run; Start its start time and CPUTicks its
	// CPU time, in clock ticks.
	Age      time.Duration
	Start    uint64
	CPUTicks uint64
}

// Judge decides whether a process of a hosting user is malicious or
// suspicious.
func Judge(p ProcInfo, home string) (string, bool) {
	r, l := Assess(p, home)
	return r, l != Clean
}

// Assess returns why a process is flagged and how sure that is.
func Assess(p ProcInfo, home string) (string, Level) {
	for _, b := range procBad {
		if b.re.MatchString(p.Cmdline) {
			return b.reason, Malicious
		}
	}
	exe := p.Exe
	deleted := strings.HasSuffix(exe, " (deleted)")
	exe = strings.TrimSuffix(exe, " (deleted)")
	// Programs of developer tools (Node.js from nvm run by PM2 …) are
	// normal, also after the tool updated itself (deleted program).
	if inDevTools(exe, home) {
		return "", Clean
	}
	// An update of a system package (PHP, LiteSpeed's lsphp) replaces the
	// program while old processes keep running: their program shows as
	// deleted. Only programs deleted from elsewhere (a temp or home folder,
	// or memory-only "memfd:" programs) are hiding.
	if deleted && !underAny(exe, systemExeDirs) {
		return "running program was deleted from disk (a common way to hide malware)", Suspicious
	}
	for _, d := range tmpDirs {
		if strings.HasPrefix(exe, d) {
			return "program runs from " + strings.TrimSuffix(d, "/"), Suspicious
		}
	}
	// A compiled program inside the account's website folders.
	if home != "" && strings.HasPrefix(exe, home+"/") && strings.Contains(exe, "/public_html/") {
		return "program runs from the website folder", Suspicious
	}
	if strings.Contains(exe, "/.") && home != "" && strings.HasPrefix(exe, home+"/") {
		return "program runs from a hidden folder in the home directory", Suspicious
	}
	return "", Clean
}

func (m *Monitor) procs() []ProcInfo {
	entries, err := os.ReadDir(m.ProcRoot)
	if err != nil {
		return nil
	}
	names := map[uint32]string{}
	uptime := readUptime(m.ProcRoot)
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
		p := ProcInfo{PID: pid, UID: sys.Uid, User: name, Exe: exe, Cmdline: cmd}
		if raw, err := os.ReadFile(filepath.Join(dir, "stat")); err == nil {
			p.Start, p.CPUTicks = parseStat(string(raw))
			if up := uptime; up > 0 && p.Start > 0 {
				p.Age = time.Duration((up - float64(p.Start)/clockTicks) * float64(time.Second))
			}
		}
		out = append(out, p)
	}
	return out
}

// clockTicks is the kernel's USER_HZ (100 on every Linux server).
const clockTicks = 100

// parseStat reads a process's start time and CPU time (utime + stime) in
// clock ticks from /proc/PID/stat.
func parseStat(stat string) (start, cpu uint64) {
	i := strings.LastIndexByte(stat, ')')
	if i < 0 {
		return 0, 0
	}
	// f[0] is field 3 (state): utime is field 14, stime 15, starttime 22.
	f := strings.Fields(stat[i+1:])
	if len(f) < 20 {
		return 0, 0
	}
	ut, _ := strconv.ParseUint(f[11], 10, 64)
	st, _ := strconv.ParseUint(f[12], 10, 64)
	start, _ = strconv.ParseUint(f[19], 10, 64)
	return start, ut + st
}

// readUptime is the seconds since boot (0 = unknown).
func readUptime(procRoot string) float64 {
	raw, err := os.ReadFile(filepath.Join(procRoot, "uptime"))
	if err != nil {
		return 0
	}
	f := strings.Fields(string(raw))
	if len(f) == 0 {
		return 0
	}
	v, _ := strconv.ParseFloat(f[0], 64)
	return v
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
	now := time.Now()
	seen := map[cpuKey]bool{}
	for _, p := range m.procs() {
		if contains(cfg.WhitelistUsers, p.User) || matchesAny(p.Cmdline+" "+p.Exe, cfg.WhitelistStrings) {
			continue
		}
		home, hosting := homes[p.User]
		if !hosting && len(homes) > 0 {
			continue // only hosting accounts
		}
		reason, level := Assess(p, home)
		if level == Clean {
			continue
		}
		// CPU use over the process's life and since the previous check.
		key := cpuKey{p.PID, p.Start}
		seen[key] = true
		life, recent := 0.0, 0.0
		if p.Age > 0 {
			life = float64(p.CPUTicks) / clockTicks / p.Age.Seconds()
		}
		if prev, ok := m.cpu[key]; ok && now.Sub(prev.at) >= 30*time.Second && p.CPUTicks >= prev.ticks {
			recent = float64(p.CPUTicks-prev.ticks) / clockTicks / now.Sub(prev.at).Seconds()
		}
		m.cpu[key] = cpuSample{p.CPUTicks, now}
		action := "alerted"
		if cfg.Kill && !m.killed[p.PID] && ShouldKill(level, p.Age, life, recent) {
			if err := syscall.Kill(p.PID, syscall.SIGKILL); err == nil {
				action = "killed"
				m.killed[p.PID] = true
				if level == Suspicious {
					reason += fmt.Sprintf(", and kept %.0f%% of a CPU core busy for %s", recent*100, p.Age.Round(time.Minute))
				}
			}
		}
		if action == "killed" || m.once(fmt.Sprintf("proc|%s|%s|%s", p.User, p.Exe, p.Cmdline)) {
			m.record(Event{Kind: "process", User: p.User, Subject: fmt.Sprintf("[%d] %s", p.PID, p.Cmdline), Reason: reason, Action: action})
		}
	}
	for k := range m.cpu {
		if !seen[k] {
			delete(m.cpu, k)
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

// cronBad are crontab patterns of malware. Weak ones (hidden folders) are
// only reported, never switched off: developer tools live in hidden
// folders too.
var cronBad = []struct {
	re     *regexp.Regexp
	reason string
	weak   bool
}{
	{regexp.MustCompile(`(?i)\b(?:curl|wget|fetch)\b[^|;]*\|\s*(?:ba|z|da)?sh\b`), "downloads and runs a script", false},
	{regexp.MustCompile(`(?i)\b(?:curl|wget)\b[^;|]*(?:-o|-O)\s*\S*(?:/tmp/|/dev/shm/|/var/tmp/)`), "downloads a file into a temporary folder", false},
	{regexp.MustCompile(`(?i)base64\s+(?:-d|--decode)[^|]*\|\s*(?:ba)?sh`), "runs base64-encoded commands", false},
	{regexp.MustCompile(`/dev/tcp/`), "opens a raw network connection", false},
	{regexp.MustCompile(`(?:^|\s)(?:/tmp/|/dev/shm/|/var/tmp/)\S+`), "runs a program from a temporary folder", false},
	{regexp.MustCompile(`(?i)stratum\+tcp|xmrig|minerd|\bkinsing\b|kdevtmpfsi|kthreaddi|\btsm64\b`), "cryptominer", false},
	{regexp.MustCompile(`(?i)gs-netcat|\bGS_ARGS\b|gsocket|\bdefunct\.dat\b`), "backdoor (gsocket)", false},
	{regexp.MustCompile(`(?i)\b(?:python[0-9.]*|perl|php)\s+-(?:c|e|r)\s+['"].*(?:base64|decode|exec|eval|socket)`), "runs inline encoded code", false},
	{regexp.MustCompile(`(?i)/(?:wp-content/)?uploads/\S+\.(?:php\d?|phtml|sh|pl|py|cgi)\b`), "runs a script from an uploads folder", false},
	{regexp.MustCompile(`/\.[a-z0-9_-]{1,20}/[^ ]*\s*>\s*/dev/null\s+2>&1\s*&?$`), "silently runs a program from a hidden folder", true},
	{regexp.MustCompile(`(?i)^@reboot\s+(?:\S+/)?(?:nohup\s+)?\S*/\.[^/\s]+/`), "starts a program from a hidden folder at every boot", true},
}

// reDevToolPath finds developer tool folders in a crontab line (PM2 or
// Node.js from nvm started at boot is normal).
var reDevToolPath = func() *regexp.Regexp {
	alt := make([]string, len(devToolDirs))
	for i, d := range devToolDirs {
		alt[i] = regexp.QuoteMeta(d)
	}
	return regexp.MustCompile(`/(?:` + strings.Join(alt, "|") + `)/|/node_modules/`)
}()

// JudgeCron returns why a crontab line is malicious or suspicious, if it is.
func JudgeCron(line string) (string, bool) {
	r, l := AssessCron(line)
	return r, l != Clean
}

// AssessCron returns why a crontab line is flagged and how sure that is:
// only malicious lines are switched off.
func AssessCron(line string) (string, Level) {
	l := strings.TrimSpace(line)
	if l == "" || strings.HasPrefix(l, "#") || strings.Contains(strings.SplitN(l, " ", 2)[0], "=") {
		return "", Clean
	}
	for _, b := range cronBad {
		if !b.re.MatchString(l) {
			continue
		}
		if !b.weak {
			return b.reason, Malicious
		}
		// Hidden folders of developer tools are not hiding anything.
		if reDevToolPath.MatchString(l) {
			continue
		}
		return b.reason, Suspicious
	}
	return "", Clean
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
				level  Level
			}
			var hits []hit
			var restore []int
			for i, line := range lines {
				t := strings.TrimSpace(line)
				// A line switched off by an older, stricter check that is not
				// malicious now: switch it back on.
				if orig, ok := strings.CutPrefix(t, strings.TrimSpace(DisabledPrefix)); ok {
					orig = strings.TrimSpace(orig)
					if _, lv := AssessCron(orig); lv != Malicious && !m.runsMalware(orig) {
						restore = append(restore, i)
					}
					continue
				}
				reason, level := AssessCron(line)
				if level == Clean && t != "" && !strings.HasPrefix(t, "#") && m.runsMalware(line) {
					reason, level = "runs a file detected as malware", Malicious
				}
				if level == Clean || store.GetKV(m.DB, cronAllowKey(e.Name(), line)) != "" {
					continue
				}
				hits = append(hits, hit{i, reason, level})
			}
			if len(hits) == 0 && len(restore) == 0 {
				continue
			}
			out := append([]string(nil), lines...)
			switchOff := 0
			for _, h := range hits {
				if cfg.Disable && h.level == Malicious {
					out[h.i] = DisabledPrefix + strings.TrimSpace(lines[h.i])
					switchOff++
				}
			}
			for _, i := range restore {
				out[i] = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(lines[i]), strings.TrimSpace(DisabledPrefix)))
			}
			written := false
			if switchOff > 0 || len(restore) > 0 {
				if err := m.writeCrontab(e.Name(), file, strings.Join(out, "\n")); err != nil {
					m.Log.Warn("could not update the crontab", "user", e.Name(), "err", err)
				} else {
					written = true
				}
			}
			if written {
				for _, i := range restore {
					m.record(Event{Kind: "cron", User: e.Name(), Subject: out[i], Reason: "switched back on: not considered malicious any more", Action: "restored"})
				}
			}
			for _, h := range hits {
				line := strings.TrimSpace(lines[h.i])
				if written && cfg.Disable && h.level == Malicious {
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

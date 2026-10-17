// Package audit checks a hosting server for risky configuration that is not
// malware: database users reachable from odd hosts, keys and backups left in
// websites, unsafe PHP settings, broken WordPress installs, stuck PHP
// processes and fragile cron jobs. It only reports; it never changes
// anything.
package audit

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Item is one thing the audit found.
type Item struct {
	Check    string `json:"check"`
	Severity string `json:"severity"` // high, medium, low
	Title    string `json:"title"`
	Detail   string `json:"detail,omitempty"`
	Path     string `json:"path,omitempty"`
	Owner    string `json:"owner,omitempty"`
}

// Report is the result of one audit run.
type Report struct {
	At       int64          `json:"at"`
	Seconds  float64        `json:"seconds"`
	Items    []Item         `json:"items"`
	Counts   map[string]int `json:"counts"`
	Checks   []string       `json:"checks"`
	Skipped  []string       `json:"skipped,omitempty"`
	Websites int            `json:"websites"`
}

// Account is a hosting account.
type Account struct{ Name, Home string }

// Auditor holds what the checks look at; empty fields use the server's
// standard places.
type Auditor struct {
	Accounts func() []Account
	// Docroots maps document roots to domains.
	Docroots func() map[string]string
	// MySQLUsers lists "user@host" of the database server.
	MySQLUsers func(ctx context.Context) ([][2]string, error)
	// Hostnames and addresses of this server (database users may connect
	// from them).
	OwnNames  func() []string
	ProcDir   string
	CronDir   string
	PHPInis   []string // glob patterns
	PHPConfs  []string // cPanel userdata files with phpversion
	Now       func() time.Time
	MaxFiles  int
	MaxPerKey int
}

func (a *Auditor) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

// Run runs every check.
func (a *Auditor) Run(ctx context.Context) Report {
	start := a.now()
	r := Report{At: start.Unix(), Counts: map[string]int{}}
	add := func(name string, items []Item, err error) {
		r.Checks = append(r.Checks, name)
		if err != nil {
			r.Skipped = append(r.Skipped, name+": "+err.Error())
		}
		r.Items = append(r.Items, items...)
	}
	items, err := a.mysqlHosts(ctx)
	add("mysql_hosts", items, err)
	web, sites, capped := a.webroots(ctx)
	r.Websites = sites
	var webErr error
	if capped {
		webErr = errCapped
	}
	add("website_files", web, webErr)
	add("php", a.phpSettings(), nil)
	add("lsphp", a.stuckPHP(), nil)
	add("cron", a.cronJobs(), nil)
	sev := map[string]int{"high": 0, "medium": 1, "low": 2}
	sort.SliceStable(r.Items, func(i, j int) bool {
		if sev[r.Items[i].Severity] != sev[r.Items[j].Severity] {
			return sev[r.Items[i].Severity] < sev[r.Items[j].Severity]
		}
		return r.Items[i].Check < r.Items[j].Check
	})
	for _, it := range r.Items {
		r.Counts[it.Severity]++
	}
	r.Seconds = a.now().Sub(start).Seconds()
	return r
}

// ---- MySQL users ----

// localHosts are where database users normally connect from.
var localHosts = map[string]bool{"localhost": true, "127.0.0.1": true, "::1": true, "localhost.localdomain": true}

var reIPHost = regexp.MustCompile(`^[0-9.%_]+$|^[0-9a-fA-F:]+$|^[0-9./]+$`)

// DefaultMySQLUsers asks the local server (root's ~/.my.cnf on cPanel).
func DefaultMySQLUsers(ctx context.Context) ([][2]string, error) {
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, "mysql", "-N", "-B", "-e", "SELECT User, Host FROM mysql.user").Output()
	if err != nil {
		return nil, err
	}
	var users [][2]string
	for _, l := range strings.Split(string(out), "\n") {
		f := strings.Split(l, "\t")
		if len(f) == 2 {
			users = append(users, [2]string{f[0], f[1]})
		}
	}
	return users, nil
}

func (a *Auditor) mysqlHosts(ctx context.Context) ([]Item, error) {
	if a.MySQLUsers == nil {
		return nil, nil
	}
	users, err := a.MySQLUsers(ctx)
	if err != nil {
		return nil, err
	}
	own := map[string]bool{}
	if a.OwnNames != nil {
		for _, n := range a.OwnNames() {
			own[strings.ToLower(n)] = true
		}
	}
	var out []Item
	for _, u := range users {
		user, host := u[0], strings.ToLower(u[1])
		if localHosts[host] || own[host] {
			continue
		}
		switch {
		case host == "%" && (user == "root" || user == ""):
			out = append(out, Item{Check: "mysql_hosts", Severity: "high", Title: "Database user " + quoteUser(user) + " can log in from any address",
				Detail: "Host '%' lets the whole internet try its password. Limit it to the addresses that need it."})
		case reIPHost.MatchString(host):
			// Remote MySQL access an account set up for an address: normal.
		default:
			// A host name: an attacker adds users with look-alike names
			// (googlevbdeo.com) to keep a way back into the database.
			out = append(out, Item{Check: "mysql_hosts", Severity: "high", Title: "Database user " + quoteUser(user) + " may log in from " + host,
				Detail: "A host name that is not this server. Attackers add such users to keep access; remove it unless an account set it up on purpose (cPanel » Remote MySQL)."})
		}
	}
	return out, nil
}

func quoteUser(u string) string {
	if u == "" {
		return "(anonymous)"
	}
	return "'" + u + "'"
}

// ---- Website files: keys, backups, WordPress ----

var (
	secretPatterns = []struct {
		name string
		re   *regexp.Regexp
	}{
		{"OpenRouter API key", regexp.MustCompile(`sk-or-v1-[0-9a-f]{40,}`)},
		{"Anthropic API key", regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{40,}`)},
		{"OpenAI API key", regexp.MustCompile(`\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{40,}`)},
		{"AWS access key", regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
		{"Stripe secret key", regexp.MustCompile(`\b(?:sk|rk)_live_[0-9A-Za-z]{20,}`)},
		{"GitHub token", regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,}`)},
		{"Slack token", regexp.MustCompile(`\bxox[abpr]-[0-9A-Za-z-]{20,}`)},
		{"Google API key", regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`)},
		{"private key", regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`)},
	}
	// Files a web server sends as they are (not run): a key in them is
	// readable by anyone who guesses the address. PHP files are run, so a
	// key in a PHP config file is not exposed.
	textExts = map[string]bool{".env": true, ".json": true, ".txt": true, ".yml": true, ".yaml": true, ".ini": true, ".log": true,
		".bak": true, ".old": true, ".conf": true, ".cfg": true, ".xml": true, ".js": true, ".map": true, ".sql": true, ".csv": true, ".md": true}
	archiveExts = []string{".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".gz", ".rar", ".7z", ".sql", ".sql.gz", ".sql.zip", ".bak", ".wpress", ".jpa", ".daf"}
	skipWebDirs = map[string]bool{"woocommerce_uploads": true, "edd": true, "node_modules": true, ".git": true, "cgi-bin": true, ".well-known": true, "wp-includes": true, "wp-admin": true,
		"cache": true, ".cache": true, "vendor": true, "bower_components": true}
	// Key look-alikes in documentation, samples and tests.
	reSampleKey = regexp.MustCompile(`(?i)x{8,}|example|sample|placeholder|your[_-]?(?:api[_-]?)?key|dummy|0{16,}`)
)

const (
	archiveMin = 1 << 20 // a backup worth reporting
	textMax    = 2 << 20 // text files read for keys
	maxPerSite = 20      // items of one kind per website
)

var errCapped = errors.New("stopped after the file limit; websites later in the list were not checked")

func (a *Auditor) webroots(ctx context.Context) ([]Item, int, bool) {
	if a.Docroots == nil {
		return nil, 0, false
	}
	roots := a.Docroots()
	owners := map[string]string{}
	var list []string
	for root := range roots {
		list = append(list, root)
	}
	sort.Strings(list)
	// A docroot inside another one is walked with its parent.
	var top []string
	for _, r := range list {
		if len(top) > 0 && strings.HasPrefix(r, top[len(top)-1]+"/") {
			continue
		}
		top = append(top, r)
	}
	if a.Accounts != nil {
		for _, acc := range a.Accounts() {
			for _, r := range top {
				if strings.HasPrefix(r, acc.Home+"/") {
					owners[r] = acc.Name
				}
			}
		}
	}
	maxFiles := a.MaxFiles
	if maxFiles == 0 {
		maxFiles = 400000
	}
	var out []Item
	seen := 0
	sites := 0
	for _, root := range top {
		if ctx.Err() != nil {
			break
		}
		owner := owners[root]
		perKind := map[string]int{}
		addItem := func(kind string, it Item) {
			if perKind[kind] >= maxPerSite {
				return
			}
			perKind[kind]++
			it.Owner = owner
			out = append(out, it)
		}
		base := strings.Count(root, "/")
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || ctx.Err() != nil {
				return nil
			}
			if d.IsDir() {
				if p != root && (skipWebDirs[d.Name()] || strings.Count(p, "/")-base > 8) {
					return filepath.SkipDir
				}
				if isWordPress(p) {
					sites++
					for _, it := range wordpressChecks(p) {
						addItem(it.Check, it)
					}
				}
				return nil
			}
			if seen >= maxFiles {
				return filepath.SkipAll
			}
			seen++
			if !d.Type().IsRegular() {
				return nil
			}
			name := strings.ToLower(d.Name())
			if ext := archiveExt(name); ext != "" {
				if info, err := d.Info(); err == nil && info.Size() >= archiveMin {
					if sev := backupSeverity(name, ext, strings.Count(p, "/")-base); sev != "" {
						addItem("backup", Item{Check: "public_backup", Severity: sev, Title: "Backup or database dump inside the website", Path: p,
							Detail: humanSize(info.Size()) + ", downloadable by anyone who guesses its name. Move it out of the website folder."})
					}
				}
				if ext != ".sql" && ext != ".bak" {
					return nil
				}
			}
			if !textExts[filepath.Ext(name)] && name != ".env" && !strings.HasPrefix(name, ".env.") {
				return nil
			}
			if name == "debug.log" || strings.HasSuffix(name, ".min.js") {
				return nil
			}
			info, err := d.Info()
			if err != nil || info.Size() > textMax || info.Size() == 0 {
				return nil
			}
			if kind, sample := findSecret(p); kind != "" {
				addItem("secret", Item{Check: "leaked_secret", Severity: "high", Title: kind + " in a public file", Path: p,
					Detail: "Starts with " + sample + "… The file is sent as text to anyone who requests it: revoke the key and move it out of the website."})
			}
			return nil
		})
	}
	return out, sites, seen >= maxFiles
}

var (
	reBackupName = regexp.MustCompile(`backup|bak|dump|\bdb\b|database|public_html|wp-content|htdocs|www|site|full|cpmove|\d{4}[-_]?\d{2}[-_]?\d{2}`)
	// Compressed copies of pages and assets that caching plugins write.
	reAssetGz = regexp.MustCompile(`\.(?:js|css|html?|svg|json|xml|txt)\.gz$`)
)

// backupSeverity: dumps and site backups are high; other archives (often
// a download offered on purpose) only when they sit at the top of the
// website and look like a backup.
func backupSeverity(name, ext string, depth int) string {
	if reAssetGz.MatchString(name) {
		return ""
	}
	switch ext {
	case ".sql", ".sql.gz", ".sql.zip", ".wpress", ".jpa", ".daf", ".bak":
		return "high"
	}
	if reBackupName.MatchString(name) {
		if depth <= 1 {
			return "high"
		}
		return "medium"
	}
	return ""
}

func archiveExt(name string) string {
	best := ""
	for _, e := range archiveExts {
		if strings.HasSuffix(name, e) && len(e) > len(best) {
			best = e
		}
	}
	return best
}

func findSecret(path string) (string, string) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", ""
	}
	for _, p := range secretPatterns {
		for _, m := range p.re.FindAll(b, 5) {
			if reSampleKey.Match(m) || !randomLooking(m) {
				continue
			}
			return p.name, masked(string(m))
		}
	}
	return "", ""
}

// randomLooking tells a real key (many different characters, mixed case
// or digits) from words that happen to fit a key's shape.
func randomLooking(m []byte) bool {
	if bytes.HasPrefix(m, []byte("-----")) {
		return true
	}
	distinct := map[byte]bool{}
	var digit, upper, lower bool
	for _, c := range m {
		distinct[c] = true
		digit = digit || c >= '0' && c <= '9'
		upper = upper || c >= 'A' && c <= 'Z'
		lower = lower || c >= 'a' && c <= 'z'
	}
	kinds := 0
	for _, k := range []bool{digit, upper, lower} {
		if k {
			kinds++
		}
	}
	return len(distinct) >= 12 && kinds >= 2
}

// masked keeps only the start of a key: the report never carries a secret.
func masked(s string) string {
	if strings.HasPrefix(s, "-----") {
		return "-----BEGIN"
	}
	n := min(len(s)/4, 8)
	return s[:n]
}

func humanSize(n int64) string {
	switch {
	case n >= 1<<30:
		return strconv.FormatFloat(float64(n)/(1<<30), 'f', 1, 64) + " GB"
	case n >= 1<<20:
		return strconv.FormatFloat(float64(n)/(1<<20), 'f', 1, 64) + " MB"
	}
	return strconv.FormatInt(n/1024, 10) + " KB"
}

func isFile(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Mode().IsRegular()
}

func isWordPress(dir string) bool {
	return isFile(filepath.Join(dir, "wp-config.php")) && dirExists(filepath.Join(dir, "wp-content"))
}

func dirExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

// coreFiles WordPress cannot run without; cleanups that delete infected
// core files leave sites half-broken (and attackers delete them so their
// own loader is used instead).
var coreFiles = []string{"wp-settings.php", "wp-load.php", "wp-blog-header.php", "wp-login.php", "index.php",
	"wp-includes/version.php", "wp-includes/functions.php", "wp-includes/plugin.php", "wp-includes/load.php",
	"wp-admin/index.php", "wp-admin/admin.php", "wp-admin/includes/admin.php"}

var (
	reWPDebugOn      = regexp.MustCompile(`(?im)^\s*define\s*\(\s*['"]WP_DEBUG['"]\s*,\s*true\s*\)`)
	reWPDebugDisplay = regexp.MustCompile(`(?im)^\s*define\s*\(\s*['"]WP_DEBUG_DISPLAY['"]\s*,\s*false\s*\)`)
)

func wordpressChecks(dir string) []Item {
	var out []Item
	var missing []string
	for _, f := range coreFiles {
		if !isFile(filepath.Join(dir, f)) {
			missing = append(missing, f)
		}
	}
	if len(missing) > 0 {
		out = append(out, Item{Check: "wp_core", Severity: "medium", Title: "WordPress core files missing", Path: dir,
			Detail: "Missing: " + strings.Join(missing, ", ") + ". Reinstall the core files (Dashboard » Updates » Re-install) after checking the site for malware."})
	}
	cfg, _ := os.ReadFile(filepath.Join(dir, "wp-config.php"))
	if reWPDebugOn.Match(cfg) && !reWPDebugDisplay.Match(cfg) {
		out = append(out, Item{Check: "wp_debug", Severity: "low", Title: "WordPress debug mode shows errors to visitors", Path: filepath.Join(dir, "wp-config.php"),
			Detail: "WP_DEBUG is on: error messages reveal paths and plugin names. Turn it off on a live site."})
	}
	if st, err := os.Stat(filepath.Join(dir, "wp-content", "debug.log")); err == nil && st.Size() > 0 {
		out = append(out, Item{Check: "wp_debug", Severity: "low", Title: "WordPress debug log inside the website", Path: filepath.Join(dir, "wp-content", "debug.log"),
			Detail: humanSize(st.Size()) + ". It can hold paths, queries and e-mail addresses; delete it and set WP_DEBUG_LOG to a path outside the website."})
	}
	return out
}

// ---- PHP settings ----

var (
	reIniOn = regexp.MustCompile(`(?im)^\s*(allow_url_include|enable_dl|display_errors|expose_php)\s*=\s*"?(on|1|true|yes)"?\s*(?:;.*)?$`)
	// PHP versions without security fixes (8.1 ended in December 2025).
	eolPHP     = map[string]bool{"5": true, "70": true, "71": true, "72": true, "73": true, "74": true, "80": true, "81": true}
	rePHPVer   = regexp.MustCompile(`(?:ea-php|alt-php|php)(\d)(\d)`)
	reUserdata = regexp.MustCompile(`(?m)^phpversion:\s*(\S+)`)
)

func (a *Auditor) phpSettings() []Item {
	inis := a.PHPInis
	if inis == nil {
		inis = []string{"/opt/cpanel/ea-php*/root/etc/php.ini", "/opt/alt/php*/etc/php.ini", "/etc/php.ini", "/usr/local/lib/php.ini"}
	}
	var out []Item
	for _, g := range inis {
		files, _ := filepath.Glob(g)
		for _, f := range files {
			b, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			for _, m := range reIniOn.FindAllStringSubmatch(string(b), -1) {
				switch strings.ToLower(m[1]) {
				case "allow_url_include":
					out = append(out, Item{Check: "php", Severity: "high", Title: "allow_url_include is on", Path: f,
						Detail: "PHP may include code from other servers: one include bug becomes remote code execution. Turn it off."})
				case "enable_dl":
					out = append(out, Item{Check: "php", Severity: "medium", Title: "enable_dl is on", Path: f,
						Detail: "Scripts may load PHP extensions at run time. Turn it off."})
				case "display_errors":
					out = append(out, Item{Check: "php", Severity: "low", Title: "display_errors is on", Path: f,
						Detail: "Error messages with paths are shown to visitors. Log them instead."})
				}
			}
		}
	}
	// Domains on PHP versions that get no more security fixes.
	confs := a.PHPConfs
	if confs == nil {
		confs = []string{"/var/cpanel/userdata/*/*"}
	}
	byVer := map[string][]string{}
	for _, g := range confs {
		files, _ := filepath.Glob(g)
		for _, f := range files {
			n := filepath.Base(f)
			if strings.HasSuffix(n, ".cache") || strings.HasSuffix(n, ".json") || strings.HasSuffix(n, "_SSL") || n == "main" || !strings.Contains(n, ".") {
				continue
			}
			b, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			m := reUserdata.FindSubmatch(b)
			if m == nil {
				continue
			}
			v := rePHPVer.FindStringSubmatch(string(m[1]))
			if v == nil {
				continue
			}
			key := v[1] + v[2]
			if v[1] == "5" {
				key = "5"
			}
			if eolPHP[key] {
				label := v[1] + "." + v[2]
				byVer[label] = append(byVer[label], n)
			}
		}
	}
	var vers []string
	for v := range byVer {
		vers = append(vers, v)
	}
	sort.Strings(vers)
	for _, v := range vers {
		doms := byVer[v]
		sort.Strings(doms)
		shown := doms
		if len(shown) > 10 {
			shown = shown[:10]
		}
		more := ""
		if len(doms) > len(shown) {
			more = " and " + strconv.Itoa(len(doms)-len(shown)) + " more"
		}
		out = append(out, Item{Check: "php_eol", Severity: "medium", Title: strconv.Itoa(len(doms)) + " domain(s) on PHP " + v + " (no security fixes)",
			Detail: strings.Join(shown, ", ") + more + ". Move them to PHP 8.2 or newer (MultiPHP Manager)."})
	}
	return out
}

// ---- Stuck PHP processes ----

// stuckPHP lists PHP workers that have been busy on the CPU for a long
// time: a request in an endless loop, a script mining, or a hung import.
// Idle LiteSpeed parent processes run for days but use no CPU.
func (a *Auditor) stuckPHP() []Item {
	proc := a.ProcDir
	if proc == "" {
		proc = "/proc"
	}
	uptime := readUptime(proc)
	if uptime <= 0 {
		return nil
	}
	hz := 100.0
	dirs, _ := filepath.Glob(filepath.Join(proc, "[0-9]*"))
	var out []Item
	for _, d := range dirs {
		raw, err := os.ReadFile(filepath.Join(d, "stat"))
		if err != nil {
			continue
		}
		s := string(raw)
		open, cls := strings.IndexByte(s, '('), strings.LastIndexByte(s, ')')
		if open < 0 || cls < open {
			continue
		}
		comm := s[open+1 : cls]
		if !strings.HasPrefix(comm, "lsphp") && !strings.HasPrefix(comm, "php-fpm") && !strings.HasPrefix(comm, "php-cgi") && comm != "php" {
			continue
		}
		f := strings.Fields(s[cls+1:])
		if len(f) < 20 {
			continue
		}
		utime, _ := strconv.ParseFloat(f[11], 64)
		stime, _ := strconv.ParseFloat(f[12], 64)
		start, _ := strconv.ParseFloat(f[19], 64)
		age := uptime - start/hz
		cpu := (utime + stime) / hz
		if age < 1800 || cpu < 900 || cpu/age < 0.5 {
			continue
		}
		cmd, _ := os.ReadFile(filepath.Join(d, "cmdline"))
		c := strings.TrimSpace(strings.ReplaceAll(string(cmd), "\x00", " "))
		if len(c) > 160 {
			c = c[:160] + "…"
		}
		out = append(out, Item{Check: "stuck_php", Severity: "medium", Title: "PHP process busy for " + duration(age),
			Detail: "pid " + filepath.Base(d) + ", " + duration(cpu) + " of CPU (" + strconv.Itoa(int(cpu/age*100)) + "%): " + c +
				". A request stuck in a loop or a script that should not run; check what it runs before stopping it.",
			Owner: ownerOf(d)})
	}
	return out
}

func readUptime(proc string) float64 {
	b, err := os.ReadFile(filepath.Join(proc, "uptime"))
	if err != nil {
		return 0
	}
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return 0
	}
	v, _ := strconv.ParseFloat(f[0], 64)
	return v
}

func ownerOf(procDir string) string {
	b, err := os.ReadFile(filepath.Join(procDir, "status"))
	if err != nil {
		return ""
	}
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	for sc.Scan() {
		if f := strings.Fields(sc.Text()); len(f) > 1 && f[0] == "Uid:" {
			return userName(f[1])
		}
	}
	return ""
}

var userName = func(uid string) string {
	b, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return uid
	}
	for _, l := range strings.Split(string(b), "\n") {
		if f := strings.Split(l, ":"); len(f) > 2 && f[2] == uid {
			return f[0]
		}
	}
	return uid
}

func duration(sec float64) string {
	switch {
	case sec >= 86400:
		return strconv.Itoa(int(sec/86400)) + "d " + strconv.Itoa(int(sec)%86400/3600) + "h"
	case sec >= 3600:
		return strconv.Itoa(int(sec/3600)) + "h " + strconv.Itoa(int(sec)%3600/60) + "m"
	}
	return strconv.Itoa(int(sec/60)) + "m"
}

// ---- Cron jobs ----

var (
	reCronFetch   = regexp.MustCompile(`\b(wget|curl)\b`)
	reWgetTimeout = regexp.MustCompile(`(?:^|\s)(?:-T\s*\d|--timeout[= ]|--read-timeout[= ])`)
	reCurlTimeout = regexp.MustCompile(`(?:^|\s)(?:-m\s*\d|--max-time[= ])`)
	reHomeDir     = regexp.MustCompile(`/home\d*/`)
	reEveryMinute = regexp.MustCompile(`^\*(?:/1)?\s+\*\s+\*\s+\*\s+\*\s`)
)

func (a *Auditor) cronJobs() []Item {
	dir := a.CronDir
	if dir == "" {
		dir = "/var/spool/cron"
	}
	files, _ := os.ReadDir(dir)
	var out []Item
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		user := f.Name()
		b, err := os.ReadFile(filepath.Join(dir, user))
		if err != nil {
			continue
		}
		seen := map[string]string{}
		lines := map[string]bool{}
		for _, l := range strings.Split(string(b), "\n") {
			t := strings.TrimSpace(l)
			if t == "" || strings.HasPrefix(t, "#") || strings.Contains(t, "=") && !strings.Contains(t, " ") {
				continue
			}
			fields := strings.Fields(t)
			if len(fields) < 6 || strings.Contains(t, "xpguard") {
				continue
			}
			cmd := strings.Join(fields[5:], " ")
			if strings.HasPrefix(fields[0], "@") {
				cmd = strings.Join(fields[1:], " ")
			}
			// A fetch without a time limit piles up when the site is slow:
			// every run starts another one.
			if m := reCronFetch.FindStringSubmatch(cmd); m != nil {
				noLimit := m[1] == "wget" && !reWgetTimeout.MatchString(cmd) || m[1] == "curl" && !reCurlTimeout.MatchString(cmd)
				if noLimit && !strings.Contains(cmd, "timeout ") {
					sev := "low"
					if reEveryMinute.MatchString(t) {
						sev = "medium"
					}
					out = append(out, Item{Check: "cron", Severity: sev, Title: m[1] + " cron job without a time limit", Owner: user, Path: filepath.Join(dir, user),
						Detail: t + "\nWhen the site is slow, runs pile up and fill the account's process limit. Add " +
							map[string]string{"wget": "-T 60 -t 1", "curl": "-m 60"}[m[1]] + "."})
				}
			}
			// The same job once for /home and once for /home2: an account
			// moved between disks keeps running its old copy too.
			key := reHomeDir.ReplaceAllString(cmd, "/home/")
			if prev, ok := seen[key]; ok && prev != cmd {
				out = append(out, Item{Check: "cron", Severity: "medium", Title: "Cron job runs for two home folders", Owner: user, Path: filepath.Join(dir, user),
					Detail: prev + "\n" + cmd + "\nOne of them points to an old copy of the site. Remove it."})
			} else if lines[t] {
				out = append(out, Item{Check: "cron", Severity: "low", Title: "Cron job listed twice", Owner: user, Path: filepath.Join(dir, user),
					Detail: t + "\nIt runs twice each time. Remove one line."})
			}
			lines[t] = true
			seen[key] = cmd
		}
	}
	return out
}

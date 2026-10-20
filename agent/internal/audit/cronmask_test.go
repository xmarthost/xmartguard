package audit

import (
	"path/filepath"
	"strings"
	"testing"
)

// Cron lines in the report do not carry the passwords, tokens and keys
// they hold (A5 F18). The values here are inert placeholders.
func TestCronDetailsMasked(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "cron/bob"), strings.Join([]string{
		"* * * * * curl -u bob:FAKEPASS1 https://example.com/cron.php",
		"* * * * * wget -q https://bob:FAKEPASS2@example.com/c.php",
		"*/5 * * * * wget -q https://example.com/cron?key=FAKEKEY3&run=1",
		"*/5 * * * * wget -q https://example.com/cron?key=FAKEKEY3&run=1",
		`0 1 * * * curl -H "Authorization: Bearer FAKETOKEN4" https://example.com/x`,
		"0 2 * * * mysqldump -ubob -pFAKEPASS5 db > /home/bob/db.sql && curl https://example.com/done --api-key=FAKEKEY6",
		"0 3 * * * DB_PASSWORD=FAKEPASS7 wget https://example.com/y",
	}, "\n")+"\n")
	a := &Auditor{CronDir: filepath.Join(dir, "cron")}
	items := a.cronJobs()
	if len(items) < 6 {
		t.Fatalf("items: %+v", items)
	}
	for _, it := range items {
		if strings.Contains(it.Detail, "FAKE") {
			t.Errorf("secret in the report: %s", it.Detail)
		}
	}
	if got := maskCron("0 1 * * * wget -q -O /dev/null https://example.com/wp-cron.php"); got != "0 1 * * * wget -q -O /dev/null https://example.com/wp-cron.php" {
		t.Fatalf("a line without secrets changed: %s", got)
	}
}

package cms

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xmarthost/xmartguard/agent/internal/store"
)

const sampleWPV = `{"error":0,"message":null,"data":{"name":"Demo","plugin":"demo","vulnerability":[
 {"uuid":"a","name":"Demo < 5.8.4 - Reflected XSS","operator":{"min_version":null,"min_operator":null,"max_version":"5.8.4","max_operator":"lt","unfixed":"0","closed":"0"},
  "source":[{"id":"CVE-2024-0001","name":"x","link":"https://example.org/cve","description":"","date":"2024-01-02"}],
  "impact":{"cvss":{"version":"3.1","vector":"","score":"6.1","severity":"m"}}},
 {"uuid":"b","name":"Demo <= 4.0 - SQL Injection","operator":{"min_version":"3.0","min_operator":"ge","max_version":"4.0","max_operator":"le","unfixed":"0","closed":"0"},
  "source":[{"id":"CVE-2023-0002","link":"","date":"2023-05-01"}],"impact":{"cvss":{"score":9.8}}}
]}}`

func TestVulnDB(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XG_STATE_DIR", filepath.Join(dir, "state"))
	db, err := store.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.URL.Path != "/plugin/demo/" {
			http.NotFound(w, r)
			return
		}
		io.WriteString(w, sampleWPV)
	}))
	defer srv.Close()
	v := &VulnDB{DB: db, Client: srv.Client(), Base: srv.URL}
	got, err := v.Affecting(context.Background(), "plugin", "demo", "3.5")
	if err != nil || len(got) != 2 {
		t.Fatalf("3.5: %+v %v", got, err)
	}
	if got[1].CVSS != 9.8 || got[0].FixedIn != "5.8.4" || got[0].ID != "CVE-2024-0001" || got[0].Date == 0 {
		t.Fatalf("parse: %+v", got)
	}
	got, _ = v.Affecting(context.Background(), "plugin", "demo", "5.0")
	if len(got) != 1 {
		t.Fatalf("5.0: %+v", got)
	}
	got, _ = v.Affecting(context.Background(), "plugin", "demo", "5.8.4")
	if len(got) != 0 {
		t.Fatalf("fixed version still vulnerable: %+v", got)
	}
	if hits != 1 {
		t.Fatalf("cache not used: %d requests", hits)
	}
	if maxCVSS([]Vuln{{CVSS: 3}, {CVSS: 7.5}}) != 7.5 {
		t.Fatal("maxCVSS")
	}
}

func TestEnsureRealCron(t *testing.T) {
	if _, err := exec.LookPath("crontab"); err != nil || os.Geteuid() != 0 {
		t.Skip("needs root and crontab")
	}
	if os.Getenv("XG_DESTRUCTIVE_TESTS") != "1" {
		t.Skip("edits the crontab of user nobody; set XG_DESTRUCTIVE_TESTS=1")
	}
	site := t.TempDir()
	os.WriteFile(filepath.Join(site, "wp-config.php"), []byte("<?php\ndefine('DB_NAME','x');\n"), 0o640)
	defer exec.Command("crontab", "-u", "nobody", "-r").Run()
	changed, err := EnsureRealCron(site, "nobody", 12)
	if err != nil || !changed {
		t.Fatalf("first: %v %v", changed, err)
	}
	cfg, _ := os.ReadFile(filepath.Join(site, "wp-config.php"))
	if !strings.Contains(string(cfg), "DISABLE_WP_CRON") || !strings.HasPrefix(string(cfg), "<?php\ndefine( 'DISABLE_WP_CRON'") {
		t.Fatalf("wp-config: %s", cfg)
	}
	tab, _ := exec.Command("crontab", "-u", "nobody", "-l").Output()
	if !strings.Contains(string(tab), "0 */12 * * * cd "+site) {
		t.Fatalf("crontab: %s", tab)
	}
	if changed, _ := EnsureRealCron(site, "nobody", 12); changed {
		t.Fatal("second run changed things again")
	}
}

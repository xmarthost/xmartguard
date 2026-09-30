package core

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/xmarthost/xmartguard/agent/internal/store"
)

func TestReportable(t *testing.T) {
	for path, want := range map[string]string{
		"/home/shop/public_html/wp-2019.php":                          "wp-2019.php|wp-2019.php",
		"/home/shop/public_html/blog/wp-content/plugins/fix/gzup.php": "gzup.php|wp-content/plugins/fix/gzup.php",
		"/home/shop/public_html/wp-includes/fonts/about2.php":         "",
		"/home/shop/public_html/index.php":                            "",
		"/home/shop/public_html/wp-content/uploads/x.jpg":             "",
	} {
		name, tail, ok := reportable(path)
		got := ""
		if ok {
			got = name + "|" + tail
		}
		if got != want {
			t.Errorf("%s: %q", path, got)
		}
	}
}

func TestFleetIntelAgent(t *testing.T) {
	a := newTestAgent(t, `{"waf":{"enabled":false}}`)
	now := store.Now()
	ins := func(path, status string) {
		a.DB.Exec(`INSERT INTO findings (source, path, category, signature, status, created_at, updated_at) VALUES ('manual', ?, 'virus', 'php.webshell.alfa', ?, ?, ?)`, path, status, now, now)
	}
	ins("/home/a/public_html/alfa-rex.php7", "quarantined")
	ins("/home/a/public_html/index.php", "quarantined")
	ins("/home/b/public_html/wp-content/plugins/x/cleanlib.php", "restored")
	r, maxID, maxClean := a.collectNameReports()
	if len(r) != 2 || maxID != 2 || maxClean != now {
		t.Fatalf("reports %+v %d %d", r, maxID, maxClean)
	}
	for _, x := range r {
		if x.Name == "cleanlib.php" && !x.Clean || x.Name == "alfa-rex.php7" && x.Clean {
			t.Errorf("report %+v", x)
		}
	}
	// The portal pushes its intelligence; invalid entries are dropped.
	p, _ := json.Marshal(map[string]any{"etag": "e1", "names": []string{"alfa-rex.php7", "index.php"},
		"patches": []map[string]any{{"id": 7703001, "title": "WP Automatic SQL injection", "path": `/csv\.php$`}, {"id": 1, "title": "bad", "path": "/x"}}})
	res, err := a.Handlers()["waf.intel"](context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if m := res.(map[string]any); m["names"] != 1 || m["patches"] != 1 {
		t.Fatalf("stored %v", m)
	}
	found := false
	for _, r := range a.WAF.RuleCatalog() {
		found = found || r.ID == 7703001
	}
	if !found {
		t.Fatal("portal patch missing from the rule list")
	}
}

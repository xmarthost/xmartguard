package core

import (
	"context"
	"fmt"
	"testing"

	"github.com/xmarthost/xmartguard/agent/internal/store"
)

// One noisy rule or signature does not fill the sample: every group is
// counted and keeps a few examples from different sites and files.
func TestLearningSample(t *testing.T) {
	a := newTestAgent(t, `{"waf":{"enabled":false}}`)
	now := store.Now()
	for i := 0; i < 500; i++ {
		a.DB.Exec(`INSERT INTO waf_events (at, ip, method, host, uri, rule_id, msg, category, action, user, detail) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
			now-10, fmt.Sprintf("198.51.100.%d", i%200), "GET", fmt.Sprintf("site%d.example", i%7), "/xmlrpc.php", 7700307, "XML-RPC accepts only POST", "wordpress", "Access denied with code 403", "", "")
	}
	a.DB.Exec(`INSERT INTO waf_events (at, ip, method, host, uri, rule_id, msg, category, action, user, detail) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		now-10, "203.0.113.5", "GET", "shop.example", "/wp-admin/edit.php", 7700605, "Web shell name learned", "webshell", "Access denied with code 403", "", "")
	a.DB.Exec(`INSERT INTO waf_events (at, ip, method, host, uri, rule_id, msg, category, action, user, detail) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		now-100000, "203.0.113.6", "GET", "old.example", "/", 7700201, "old", "files", "Access denied with code 403", "", "")
	s, err := a.learningSample(context.Background(), "waf", 12, 5, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.WAFGroups) != 2 || s.WAFGroups[0].Count != 500 || s.WAFGroups[0].Hosts != 7 || s.WAFGroups[1].RuleID != 7700605 {
		t.Fatalf("groups %+v", s.WAFGroups)
	}
	if len(s.WAFEvents) != 6 {
		t.Fatalf("events %d", len(s.WAFEvents))
	}
	if s.Server["version"] == "" || s.Server["hostname"] == nil {
		t.Fatal("server info")
	}
	for i := 0; i < 50; i++ {
		a.DB.Exec(`INSERT INTO findings (source, path, owner, category, signature, sha256, size, status, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)`,
			"scheduled", fmt.Sprintf("/home/u%d/public_html/x.php", i), fmt.Sprintf("u%d", i%3), "virus", "XG.AI.Learned", "aa", 10, "quarantined", now, now)
	}
	a.DB.Exec(`INSERT INTO findings (source, path, owner, category, signature, sha256, size, status, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)`,
		"scheduled", "/home/b/public_html/main.js", "b", "suspicious", "JS.Obfuscated.EvalPacked", "bb", 10, "quarantined", now, now)
	d, err := a.learningSample(context.Background(), "detections", 12, 5, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.SigGroups) != 2 || d.SigGroups[0].Count != 50 || d.SigGroups[0].Files != 1 {
		t.Fatalf("sig groups %+v", d.SigGroups)
	}
	// Same content: one example per account.
	if len(d.Detections) != 4 {
		t.Fatalf("detections %d", len(d.Detections))
	}
}

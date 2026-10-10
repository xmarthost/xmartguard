package firewall

import "testing"

// Scanners the WAF refused on scanner-only rules are shared with the IPDB;
// weak signals, CDN addresses and whitelisted addresses are not.
func TestIPDBProbeReports(t *testing.T) {
	m := newManager(t, ProviderNFTables)
	add := func(ip string, rule int, action string) {
		m.DB.Exec(`INSERT INTO waf_events (at, ip, rule_id, msg, action) VALUES (100, ?, ?, 'xPGuard - Access to sensitive file blocked', ?)`, ip, rule, action)
	}
	for i := 0; i < 5; i++ {
		add("203.0.113.66", 7700201, "Access denied with code 403") // .env scanner, capped at 3
	}
	add("203.0.113.67", 7700601, "Access denied with code 403")  // web shell probe
	add("203.0.113.68", 949110, "Access denied with code 403")   // OWASP CRS: could be a visitor
	add("203.0.113.69", 7700201, "Warning")                      // not refused
	add("172.70.10.10", 7700201, "Access denied with code 403")  // Cloudflare
	add("198.51.100.20", 7701003, "Access denied with code 403") // virtual patch, whitelisted below
	m.Add(KindAllow, "198.51.100.0/24", "office", 0)

	got, cursor, err := m.IPDBProbeReports(0, 100)
	if err != nil {
		t.Fatal(err)
	}
	count := map[string]int{}
	for _, r := range got {
		count[r.IP]++
		if r.Source != "waf-probe" || r.Reason == "" {
			t.Fatalf("report %+v", r)
		}
	}
	if count["203.0.113.66"] != 3 || count["203.0.113.67"] != 1 || len(count) != 2 {
		t.Fatalf("reported %v", count)
	}
	var last int64
	m.DB.QueryRow(`SELECT max(id) FROM waf_events`).Scan(&last)
	if cursor != last-1 && cursor != last {
		t.Fatalf("cursor %d of %d", cursor, last)
	}
	// Nothing new: nothing reported, cursor kept.
	if again, c, _ := m.IPDBProbeReports(cursor, 100); len(again) != 0 || c < cursor {
		t.Fatalf("again %v %d", again, c)
	}
}

package waf

import (
	"net/url"
	"sort"
	"strings"
)

// VendorPackage is one rule package of a linked feed (Malware.Expert's
// "rules" and "extra" modules).
type VendorPackage struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	Desc  string `json:"desc"`
}

// VendorRule is a vendor rule that triggered on this server.
type VendorRule struct {
	ID      int    `json:"id"`
	Msg     string `json:"msg"`
	Hits    int    `json:"hits"`
	Hits24h int    `json:"hits_24h"`
	Last    int64  `json:"last"`
	Enabled bool   `json:"enabled"`
}

// VendorRules describes the rule set that replaces xPGuard's rules here.
type VendorRules struct {
	Name     string          `json:"name"`
	Packages []VendorPackage `json:"packages"`
	Rules    []VendorRule    `json:"rules"`
}

// Malware.Expert's modules as its download URL names them.
var mePackages = map[string][2]string{
	"generic":   {"Generic rules", "SQL injection, XSS, remote code and file inclusion, CMS exploits (WordPress, Joomla, Drupal, …)"},
	"webshell":  {"Web shells", "Requests to known web shells and backdoors"},
	"scanner":   {"Scanners", "Vulnerability scanners and attack tools"},
	"crawler":   {"Bad crawlers", "Abusive crawlers and scrapers"},
	"rbl":       {"Malware hosts (RBL)", "POST requests from addresses on rbl.malware.expert"},
	"proxy":     {"Proxies", "Requests from open and anonymous proxies"},
	"recaptcha": {"Login CAPTCHA", "Blacklisted visitors on WordPress / Joomla logins are sent to recaptcha.cloud"},
}

// ownOrCRS reports rule ids that are not the vendor's: xPGuard's range and
// the OWASP CRS range (hits from before the vendor was linked).
func ownOrCRS(id int) bool {
	return (id >= 7700000 && id <= 7709999) || (id >= 900000 && id <= 999999)
}

// VendorRules lists the replacing rule set's packages and the rules of it
// that have triggered on this server (from the web server log: the rules
// themselves are loaded by the web server straight from the vendor and are
// not stored here).
func (m *Manager) VendorRules() VendorRules {
	out := VendorRules{Name: m.OwnRulesReplacedBy(), Packages: []VendorPackage{}, Rules: []VendorRule{}}
	m.mu.Lock()
	remote := append([]RemoteRules(nil), m.ruleSets.Remote...)
	m.mu.Unlock()
	for _, r := range remote {
		if !r.Enabled || !strings.Contains(strings.ToLower(r.Name+" "+r.URL), "malware.expert") {
			continue
		}
		u, err := url.Parse(r.URL)
		if err != nil {
			continue
		}
		mods := strings.Split(u.Query().Get("rules"), ",")
		mods = append(mods, strings.Split(u.Query().Get("extra"), ",")...)
		for _, id := range mods {
			id = strings.TrimSpace(strings.ToLower(id))
			if id == "" {
				continue
			}
			p := VendorPackage{ID: id, Title: id, Desc: ""}
			if d, ok := mePackages[id]; ok {
				p.Title, p.Desc = d[0], d[1]
			}
			out.Packages = append(out.Packages, p)
		}
		break
	}
	disabled := map[int]bool{}
	for _, id := range m.Settings.Get().WAF.DisabledRules {
		disabled[id] = true
	}
	day := int64(0)
	if m.DB == nil {
		return out
	}
	_ = m.DB.QueryRow(`SELECT strftime('%s','now') - 86400`).Scan(&day)
	rows, err := m.DB.Query(`SELECT rule_id, count(*), sum(CASE WHEN at >= ? THEN 1 ELSE 0 END), max(at),
		coalesce((SELECT msg FROM waf_events w2 WHERE w2.rule_id = w.rule_id AND w2.msg != '' ORDER BY id DESC LIMIT 1), '')
		FROM waf_events w WHERE rule_id > 0 GROUP BY rule_id`, day)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var r VendorRule
		if rows.Scan(&r.ID, &r.Hits, &r.Hits24h, &r.Last, &r.Msg) != nil || ownOrCRS(r.ID) {
			continue
		}
		r.Enabled = !disabled[r.ID]
		out.Rules = append(out.Rules, r)
	}
	// Switched-off rules stay listed even without recent hits.
	seen := map[int]bool{}
	for _, r := range out.Rules {
		seen[r.ID] = true
	}
	for id := range disabled {
		if !seen[id] && !ownOrCRS(id) {
			out.Rules = append(out.Rules, VendorRule{ID: id, Enabled: false})
		}
	}
	sort.Slice(out.Rules, func(i, j int) bool {
		if out.Rules[i].Hits != out.Rules[j].Hits {
			return out.Rules[i].Hits > out.Rules[j].Hits
		}
		return out.Rules[i].ID < out.Rules[j].ID
	})
	return out
}

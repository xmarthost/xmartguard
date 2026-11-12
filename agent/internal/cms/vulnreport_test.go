package cms

import (
	"testing"

	"github.com/xmarthost/xmartguard/agent/internal/store"
)

// The owner's question (2026-11-12): did the automatic updates patch the
// vulnerable plugins? The report counts what is open now by cause and
// what the remembered attempts led to.
func TestVulnReport(t *testing.T) {
	m, _ := autoUpdateManager(t, `{"cms":{"auto_update":true,"auto_update_cvss":6,"auto_update_days":1}}`)
	v := func(cvss float64, fixed string) []Vuln {
		return []Vuln{{CVSS: cvss, FixedIn: fixed, Date: store.Now() - 30*86400}}
	}
	m.save(Site{Type: WordPress, Path: "/home/a/public_html", User: "a", Version: "7.1.4", Latest: "7.1.4", MUPlugins: []string{},
		Plugins: []Component{
			{Slug: "cf7", Version: "6.2.1", Latest: "6.2.5", Vulns: v(9.8, "6.2.4")}, // due, not applied
			{Slug: "kit", Version: "3.4.8", Latest: "3.5.1", Vulns: v(5.3, "3.5.1")}, // under the setting
			{Slug: "pro", Version: "3.0.39", Vulns: v(7.5, "3.0.97")},                // premium
			{Slug: "nofix", Version: "1.0", Latest: "1.0", Vulns: v(9.8, "")},        // no fix
			{Slug: "fine", Version: "2.0", Latest: "2.0"},
		}, Themes: []Component{}})
	m.save(Site{Type: WordPress, Path: "/home/b/public_html", User: "b", Version: "7.1.4", Latest: "7.1.4", MUPlugins: []string{},
		Plugins: []Component{{Slug: "cf7", Version: "6.2.5", Latest: "6.2.5"}}, Themes: []Component{}})
	// Attempts: b's cf7 went from 6.2.1 (updated), a's cf7 stayed (failed),
	// a site that is gone (removed).
	store.SetKV(m.DB, "cms_update_try|/home/b/public_html|plugin|cf7|6.2.1", "1")
	store.SetKV(m.DB, "cms_update_try|/home/a/public_html|plugin|cf7|6.2.1", "1")
	store.SetKV(m.DB, "cms_update_try|/home/gone/public_html|plugin|x|1.0", "1")
	r, err := m.VulnReport()
	if err != nil {
		t.Fatal(err)
	}
	if r.Sites != 2 || r.Vulnerable != 4 || r.SitesAffected != 1 || r.DueNotPatch != 1 || r.BelowPolicy != 1 || r.NoUpdate != 1 || r.NoFix != 1 {
		t.Errorf("open: %+v", r)
	}
	if r.Critical != 2 || r.High != 1 || r.Medium != 1 {
		t.Errorf("bands: %+v", r)
	}
	if r.Tried != 3 || r.Updated != 1 || r.Failed != 1 || r.Removed != 1 || len(r.TopFailed) != 1 || r.TopFailed[0].Slug != "cf7" {
		t.Errorf("attempts: %+v", r)
	}
}

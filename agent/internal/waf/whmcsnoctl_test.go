package waf

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"
)

// WHMCS General Settings on LiteSpeed (my.galaxyhoster.com, admin folder
// /proka/, 2026-10-21): LiteSpeed ignores ctl rule removal, and the
// threshold the WHMCS exclusion set was reset by the CRS setup loaded after
// it, so a save scoring above the session threshold was refused. With every
// ctl stripped, as LiteSpeed runs the rules, the save must pass, and the
// same request from another site or without the session must not.
func TestWHMCSAdminSaveWithoutCtlWithCRS(t *testing.T) {
	src := os.Getenv("XG_CRS_DIR")
	if src == "" {
		t.Skip("set XG_CRS_DIR to an OWASP CRS 4 checkout")
	}
	m := crsManager(t, src, `{"waf":{"enabled":true,"level":"normal","generic":true}}`, "off", nil)
	if st := m.Status(); st.Error != "" {
		t.Fatalf("WAF error: %s", st.Error)
	}
	p := filepath.Join(m.RulesDir, "rules.conf")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	stripped := regexp.MustCompile(`,ctl:ruleRemoveBy(?:Id|Tag)=[^,"]+`).ReplaceAll(b, nil)
	if err := os.WriteFile(p, stripped, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command("apache2ctl", "graceful").Run(); err != nil {
		t.Fatal(err)
	}
	waitApache()
	form := "application/x-www-form-urlencoded"
	// General Settings: company address in HTML, tracking and chat codes.
	save := "token=0a1b2c3d&tab=1&companyname=Galaxy+Host&invoicepayto=" + urlEncode(`<b>Galaxy Host</b><br>Karachi<br><a href="https://example.pk">example.pk</a>`) +
		"&trackingcode=" + urlEncode(`<script async src="https://www.googletagmanager.com/gtag/js?id=G-ABC123"></script><script>window.dataLayer=window.dataLayer||[];function gtag(){dataLayer.push(arguments);}gtag('js',new Date());</script>`) +
		"&chatcode=" + urlEncode(`<script type="text/javascript">var Tawk_API=Tawk_API||{};(function(){var s1=document.createElement("script");s1.src='https://embed.tawk.to/abc/default';document.body.appendChild(s1);})();</script>`)
	sess := "Cookie: WHMCSy551iLvnhYt7=0123456789abcdef"
	uri := "/proka/configgeneral.php?action=save"
	cases := []struct {
		name string
		hdr  []string
		want int
	}{
		{"admin save from its own page", []string{sess, "Referer: https://my.example.com/proka/configgeneral.php"}, 200},
		{"admin save without a Referer (same-origin)", []string{sess, "Sec-Fetch-Site: same-origin"}, 200},
		{"save posted from another site", []string{sess, "Sec-Fetch-Site: cross-site", "Referer: https://evil.example/x"}, 403},
		{"save without the WHMCS session", []string{"Referer: https://my.example.com/proka/configgeneral.php"}, 403},
	}
	for _, c := range cases {
		if got := sendBody(t, "my.example.com", "POST", uri, form, save, c.hdr...); (got == 403) != (c.want == 403) || got == 0 {
			t.Errorf("%s: got %d, want %d", c.name, got, c.want)
		}
	}
}

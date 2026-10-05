package waf

import (
	"strings"
	"testing"
)

// Search engine crawlers (trusted services) are never sent to the CAPTCHA
// page: a crawler redirected to another domain hurts the site in search
// results and fills the CAPTCHA domain with crawled links.
func TestSoftBlockSkipsTrustedServices(t *testing.T) {
	m := &Manager{RulesDir: t.TempDir(),
		Central: func() *Central {
			return &Central{URL: "https://captcha.example.org/v", ServerID: "15d69a72-653a-47b6-90f6-fde737bce061"}
		},
		TrustedIPs: func() []string { return []string{"66.249.64.0/19"} },
	}
	sb, ok := m.softBlock(CRSConfig{Enabled: true, Version: "4.29.0"}, 5)
	if !ok {
		t.Fatal("soft block off")
	}
	tf := m.RulesDir + "/" + FileTrustedIPs
	if !strings.Contains(sb.setup, "@ipMatchFromFile "+tf) || !strings.Contains(sb.setup, "id:7700038,") {
		t.Fatalf("no trusted-services rule:\n%s", sb.setup)
	}
	// Before the rule that marks clean visitors for the CAPTCHA.
	if strings.Index(sb.setup, "id:7700038,") > strings.Index(sb.setup, "id:7700034,") {
		t.Fatal("trusted rule after the soft-block flag")
	}
	if sb.files[tf] != "66.249.64.0/19\n" {
		t.Fatalf("trusted list file %q", sb.files[tf])
	}
	// No trusted list: no rule.
	m.TrustedIPs = nil
	sb, _ = m.softBlock(CRSConfig{Enabled: true, Version: "4.29.0"}, 5)
	if strings.Contains(sb.setup, "7700038") {
		t.Fatal("trusted rule without a list")
	}
}

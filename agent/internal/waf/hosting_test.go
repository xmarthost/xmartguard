package waf

import (
	"strings"
	"testing"

	"github.com/xmarthost/xmartguard/agent/internal/settings"
)

// server1 (2026-10-28): stolen WordPress passwords were used from rented
// servers, each login the first POST. A login page opened from a hosting
// network is sent to the CAPTCHA first; xmlrpc.php (apps, services),
// trusted services, the exempt addresses and the rest of the site are not.
func TestHostingLoginRule(t *testing.T) {
	c := &Central{URL: "https://captcha.xpguard.org/v", ServerID: "15d69a72-653a-47b6-90f6-fde737bce061",
		SiteLoginURLs: []string{"/wp-login.php"}, Hosting: true,
		HostingNets: []string{"203.0.113.0/24", "2001:db8::/32"}, HostingExempt: []string{"203.0.113.7"}}
	files := CentralFiles(c, nil)
	if files[FileCaptchaHosting] != "203.0.113.0/24\n2001:db8::/32\n" || files[FileCaptchaHostingExempt] != "203.0.113.7\n" {
		t.Fatalf("files: %q %q", files[FileCaptchaHosting], files[FileCaptchaHostingExempt])
	}
	conf := Render(settings.WAF{LoginURLs: []string{"/wp-login.php", "/xmlrpc.php"}}, Options{Dir: "/etc/xg", Central: c, Trusted: true})
	mark := strings.Index(conf, "id:7700069")
	gate := strings.Index(conf, "suspicious visitor sent to the CAPTCHA")
	if mark < 0 || gate < 0 || mark > gate {
		t.Fatalf("hosting mark %d, gate %d:\n%s", mark, gate, conf)
	}
	rule := conf[strings.LastIndex(conf[:mark], "\n")+1:]
	rule = rule[:strings.Index(rule, "setvar:tx.xg_suspect=1")]
	for _, want := range []string{"/etc/xg/" + FileCaptchaHosting, `"!@ipMatchFromFile /etc/xg/` + FileCaptchaHostingExempt, `"!@ipMatchFromFile /etc/xg/` + FileTrustedIPs, `(?:/wp-login\.php)(?:/|$)`} {
		if !strings.Contains(rule, want) {
			t.Errorf("rule lacks %q:\n%s", want, rule)
		}
	}
	if strings.Contains(rule, "xmlrpc") {
		t.Errorf("xmlrpc.php in the hosting rule:\n%s", rule)
	}
	// Off, or the CAPTCHA for everyone already: no rule.
	c.Hosting = false
	if strings.Contains(Render(settings.WAF{LoginURLs: []string{"/wp-login.php"}}, Options{Dir: "/etc/xg", Central: c}), "id:7700069") {
		t.Error("hosting rule while off")
	}
	c.Hosting, c.All = true, true
	if strings.Contains(Render(settings.WAF{LoginURLs: []string{"/wp-login.php"}}, Options{Dir: "/etc/xg", Central: c}), "id:7700069") {
		t.Error("hosting rule with the CAPTCHA for everyone")
	}
	// An empty list still writes a valid file (the placeholder).
	if f := CentralFiles(&Central{Hosting: true}, nil)[FileCaptchaHosting]; strings.TrimSpace(f) == "" {
		t.Error("empty hosting file")
	}
}

package waf

import (
	"strings"
	"testing"

	"github.com/xmarthost/xmartguard/agent/internal/settings"
)

func TestFleetNameOK(t *testing.T) {
	for name, want := range map[string]bool{
		"wp-2019.php": true, "alfa-rex.php7": true, "xmrlpc.php": true, "gzdecodes.php": true,
		"index.php": false, "config.php": false, "about.php": false, "Upload.php": false, "ab.php": false,
		"x.js": false, "../evil.php": false, "a\"b.php": false, "sh ell.php": false, "cache.php": false,
	} {
		if got := FleetNameOK(name); got != want {
			t.Errorf("%s: %v", name, got)
		}
	}
}

func TestPortalPatchValidation(t *testing.T) {
	good := PortalPatch{ID: 7703001, Title: "WP Automatic SQL injection", CVE: "CVE-2024-27956", Path: `/wp-content/plugins/wp-automatic/inc/csv\.php$`, LoggedOut: true}
	if err := good.Valid(); err != nil {
		t.Fatal(err)
	}
	bad := []PortalPatch{
		{ID: 7700201, Title: "Steals our id", Path: `/x$`},
		{ID: 7703002, Title: "Quote \" breaks out", Path: `/x$`},
		{ID: 7703003, Title: "Break out", Path: `/x" "id:1,exec:/bin/sh`},
		{ID: 7703004, Title: "No condition"},
		{ID: 7703005, Title: "Bad arg", Args: []PatchMatch{{Name: "a b", Op: "present"}}},
		{ID: 7703006, Title: "Bad regex", Path: `(`},
		{ID: 7703007, Title: "Bad op", Args: []PatchMatch{{Name: "a", Op: "exec", Value: "x"}}},
		{ID: 7703008, Title: "Newline", URI: "a\nSecRule"},
		{ID: 7703009, Title: "Trailing backslash", Path: `/x\`},
	}
	for _, p := range bad {
		if p.Valid() == nil {
			t.Errorf("accepted %+v", p)
		}
	}
	in := (&Intel{ETag: "e1", Names: []string{"WP-2019.php", "index.php", "wp-2019.php"}, Patches: append(bad, good)}).Clean()
	if len(in.Names) != 1 || in.Names[0] != "wp-2019.php" || len(in.Patches) != 1 {
		t.Fatalf("clean %+v", in)
	}
	c := settings.Defaults().WAF
	out := Render(c, Options{Dir: "/r", Intel: in})
	for _, want := range []string{"id:7700605,", `(?:wp-2019\.php)$`, "id:7703001,", "CVE-2024-27956", `csv\.php$`, "wordpress_logged_in_"} {
		if !strings.Contains(out, want) {
			t.Errorf("rules miss %q", want)
		}
	}
	c.DisabledRules = []int{7703001}
	if strings.Contains(Render(c, Options{Dir: "/r", Intel: in}), "id:7703001,") {
		t.Error("switched-off portal patch rendered")
	}
	if p, err := ToggleRule(c, 7703001, true); err != nil || len(p["disabled_rules"].([]int)) != 0 {
		t.Errorf("toggle portal patch: %v %v", p, err)
	}
}

// portalPatches mirrors the portal's patch list (server/src/waf/intel.ts).
var portalPatches = []PortalPatch{
	{ID: 7703001, Title: "WP Automatic SQL injection", CVE: "CVE-2024-27956", Path: `/wp-content/plugins/wp-automatic/inc/csv\.php$`, LoggedOut: true},
	{ID: 7703002, Title: "Bricks Builder remote code execution", CVE: "CVE-2024-25600", URI: `(?:/wp-json/+bricks/v1/render_element|rest_route=/?bricks/v1/render_element)`, LoggedOut: true},
	{ID: 7703003, Title: "Kaswara Modern VC Addons file upload", CVE: "CVE-2021-24284", Args: []PatchMatch{{Name: "action", Op: "equals", Value: "uploadFontIcon"}}, LoggedOut: true},
	{ID: 7703004, Title: "WooCommerce Payments authentication bypass", CVE: "CVE-2023-28121", Header: &PatchMatch{Name: "X-WCPAY-PLATFORM-CHECKOUT-USER", Op: "present"}},
	{ID: 7703005, Title: "Social Warfare remote code execution", CVE: "CVE-2019-9978", Args: []PatchMatch{{Name: "swp_debug", Op: "equals", Value: "load_options"}}},
	{ID: 7703006, Title: "WPCargo remote code execution", CVE: "CVE-2021-25003", Path: `/wp-content/plugins/wpcargo/includes/barcode\.php$`, Args: []PatchMatch{{Name: "text", Op: "contains", Value: "<?"}}},
}

func TestPortalPatchesOnApache(t *testing.T) {
	m, send := apacheWith(t, `{"waf":{"upload_scan":false}}`)
	in := &Intel{ETag: "t", Names: []string{"gzdecodes.php"}, Patches: portalPatches}
	m.Intel = func() *Intel { return in }
	if err := m.Apply(); err != nil {
		t.Fatal(err)
	}
	waitApache()
	logged := "Cookie: wordpress_logged_in_abc=admin%7C1"
	for _, c := range []struct {
		method, uri string
		hdr         []string
		want        bool
	}{
		{"GET", "/wp-content/plugins/wp-automatic/inc/csv.php?q=1", nil, true},
		{"GET", "/wp-content/plugins/wp-automatic/inc/csv.php", []string{logged}, false},
		{"POST", "/wp-json/bricks/v1/render_element", nil, true},
		{"POST", "/?rest_route=/bricks/v1/render_element", nil, true},
		{"POST", "/wp-json/bricks/v1/render_element", []string{logged}, false},
		{"POST", "/wp-admin/admin-ajax.php?action=uploadFontIcon", nil, true},
		{"POST", "/wp-admin/admin-ajax.php?action=heartbeat", nil, false},
		{"GET", "/wp-json/wc/v3/orders", []string{"X-WCPAY-PLATFORM-CHECKOUT-USER: 1"}, true},
		{"GET", "/wp-json/wc/v3/orders", nil, false},
		{"GET", "/wp-admin/admin-post.php?swp_debug=load_options&swp_url=http://x", nil, true},
		{"GET", "/wp-content/plugins/wpcargo/includes/barcode.php?text=x1234%3C%3Fphp", nil, true},
		{"GET", "/wp-content/plugins/wpcargo/includes/barcode.php?text=SHIP123", nil, false},
		{"GET", "/wp-content/plugins/x/gzdecodes.php", nil, true},
	} {
		if code := send(c.method, c.uri, c.hdr...); (code == 403) != c.want {
			t.Errorf("%s %s %v: %d", c.method, c.uri, c.hdr, code)
		}
	}
}

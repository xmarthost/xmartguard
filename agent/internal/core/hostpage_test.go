package core

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/xmarthost/xmartguard/agent/internal/captcha"
)

// Hostname mode: the page is set up in the hostname's document root and
// used only while its self-test passes; otherwise suspects go to the
// portal address (never to a broken page). Another place removes it.
func TestHostnameModeFallsBack(t *testing.T) {
	a := newTestAgent(t, `{"waf":{"enabled":true}}`)
	a.Cfg.ServerID = "15d69a72-653a-47b6-90f6-fde737bce061"
	root := t.TempDir()
	saved := captcha.HostDocRoot
	captcha.HostDocRoot = root
	defer func() { captcha.HostDocRoot = saved }()
	if err := a.applyCentralConfig(context.Background(), centralConfig{Version: 5, Enabled: true, URL: "https://captcha.test/v", Minutes: 30, Mode: "hostname"}); err != nil {
		t.Fatal(err)
	}
	if a.Settings.Get().Captcha.CentralMode != "hostname" {
		t.Fatalf("mode %q", a.Settings.Get().Captcha.CentralMode)
	}
	a.syncHostPage(context.Background())
	page := filepath.Join(root, "xpguard-check", "index.html")
	if captcha.ServerHostname() != "" {
		if _, err := os.Stat(page); err != nil {
			t.Fatal("page not installed")
		}
	}
	// Nothing answers on this test machine's 443: not in use, and why.
	if a.hostPageURL() != "" {
		t.Fatal("hostname page used although its self-test failed")
	}
	if why, _ := a.central.hostErr.Load().(string); why == "" {
		t.Fatal("no reason recorded")
	}
	if w := a.centralWAF(); w == nil || w.HostPage != "" || w.URL != "https://captcha.test/v" {
		t.Fatalf("central %+v", w)
	}
	// In use (as after a passing self-test): the WAF and the firewall's
	// redirect go to it.
	a.central.hostPage.Store("https://server1.example.net/xpguard-check/")
	if w := a.centralWAF(); w == nil || w.HostPage != "https://server1.example.net/xpguard-check/" {
		t.Fatalf("central %+v", w)
	}
	// Visitors the firewall sends to this server reach the page here: only
	// with a valid certificate for the hostname on the CAPTCHA port (Firefox
	// showed "Not Secure" for the self-signed one), else the portal address.
	if a.Captcha.HostPage() != "" {
		t.Fatal("firewall redirect to the hostname without a valid certificate on the CAPTCHA port")
	}
	a.central.hostFW.Store("https://server1.example.net/xpguard-check/")
	if a.Captcha.HostPage() != "https://server1.example.net/xpguard-check/" {
		t.Fatal("firewall redirect does not use the hostname page")
	}
	// The portal address chosen again: not used, and the page is removed.
	a.applyCentralConfig(context.Background(), centralConfig{Version: 6, Enabled: true, URL: "https://captcha.test/v", Minutes: 30})
	if a.hostPageURL() != "" {
		t.Fatal("hostname page used in portal mode")
	}
	if !a.syncHostPage(context.Background()) {
		t.Fatal("leaving hostname mode not reported")
	}
	if _, err := os.Stat(page); !os.IsNotExist(err) {
		t.Fatal("page left in the document root")
	}
}

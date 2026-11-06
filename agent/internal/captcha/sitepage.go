package captcha

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// The portal's check on each website's own address without a port
// (settings Captcha.CentralMode "site"): https://<website>/xpguard-verify/
// on port 443 with the website's own certificate. Before, site mode sent
// visitors to https://<website>:7743/, a port many networks, VPNs and
// Cloudflare do not reach (the owner asked for the port to go,
// 2026-11-06). One page for all websites: a global Alias of the web
// server (as cPanel's own /cgi-sys/ and /img-sys/) to a folder of this
// agent holding a static page that frames the portal's check, like the
// hostname page; the portal lets the address in through the pass list
// and the page sends the visitor back to the page they wanted.

// SitePagePath is the page's address on every website.
const SitePagePath = "/xpguard-verify/"

// SitePageDir holds the page (outside every account; readable by the web
// server). Tests change it.
var SitePageDir = "/usr/local/share/xpguard/verify"

// sitePageMarker tells the page apart (the self-test looks for it).
const sitePageMarker = "xpguard-site-check v1"

// SitePageHTML is the page: the hostname page's frame, told it is on the
// website's own address (fs=1: the portal allows that website, once its
// server confirms the website is its own, to frame the check).
func SitePageHTML(portalURL string) string {
	return framePageHTML(portalURL, sitePageMarker, "fs", true)
}

// SiteAliasConf is the web server configuration that serves the page on
// every website (Apache 2.4; LiteSpeed reads the same includes).
func SiteAliasConf() string {
	dir := filepath.Clean(SitePageDir)
	return "# Managed by the xPGuard agent: the CAPTCHA page on every website's own address.\n" +
		fmt.Sprintf("Alias %s %s/\n", SitePagePath, dir) +
		fmt.Sprintf("<Directory \"%s\">\n", dir) +
		"    Options None\n    AllowOverride None\n    DirectoryIndex index.html\n    Require all granted\n" +
		"    <FilesMatch \"\\.(?i:php\\d?|phtml|phar|cgi|pl|py|sh)$\">\n        Require all denied\n    </FilesMatch>\n" +
		"</Directory>\n"
}

// SiteAliasOff is what the configuration file holds while the page is not
// in use (kept, so the web server never loads a stale alias).
const SiteAliasOff = "# Managed by the xPGuard agent: the CAPTCHA page on websites is off.\n"

// InstallSitePage writes the page.
func InstallSitePage(portalURL string) error {
	body := SitePageHTML(portalURL)
	if body == "" {
		return fmt.Errorf("invalid CAPTCHA page address %q", portalURL)
	}
	if err := os.MkdirAll(SitePageDir, 0o755); err != nil {
		return err
	}
	_ = os.Chmod(SitePageDir, 0o755)
	for d := filepath.Dir(SitePageDir); d != "/" && strings.HasPrefix(d, "/usr/local/share"); d = filepath.Dir(d) {
		_ = os.Chmod(d, 0o755)
	}
	path := filepath.Join(SitePageDir, "index.html")
	if cur, err := os.ReadFile(path); err == nil && string(cur) == body {
		return nil
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(body), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// RemoveSitePage removes the page (only what InstallSitePage wrote).
func RemoveSitePage() {
	path := filepath.Join(SitePageDir, "index.html")
	if cur, err := os.ReadFile(path); err == nil && strings.Contains(string(cur), sitePageMarker) {
		_ = os.Remove(path)
		_ = os.Remove(SitePageDir)
	}
}

// CheckSitePage confirms the web server serves the page (on the server's
// hostname, a website like any other for the alias, with a certificate a
// browser accepts).
func CheckSitePage(ctx context.Context, hostname, portalURL string, serverIPs []string) error {
	return checkFramePage(ctx, hostname, SitePagePath, sitePageMarker, portalURL, serverIPs)
}

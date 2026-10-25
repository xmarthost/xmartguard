package captcha

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/settings"
)

// The portal's check on this server's own hostname (settings
// Captcha.CentralMode "hostname"): https://<hostname>/xpguard-check/ on
// port 443 with the hostname's certificate (cPanel issues one). No CAPTCHA
// port that networks, VPNs and Cloudflare do not reach, and none of a
// website's caching or proxy in the way. The page is a static file in the
// hostname's document root that shows the portal's check in a full-window
// frame; the portal then lets the address in through the pass list, like
// the portal address, and the page sends the visitor back to the website.

// HostPagePath is the page's address on the hostname (not a hidden folder:
// the WAF refuses those).
const HostPagePath = "/xpguard-check/"

// HostDocRoot is the hostname's document root (cPanel: the default
// virtual host, also for LiteSpeed). Tests change it.
var HostDocRoot = "/var/www/html"

// hostPageMarker tells the page apart (the self-test looks for it).
const hostPageMarker = "xpguard-hostname-check v1"

var reHostname = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)

// HostnameWanted reports whether the check is to open on the hostname.
func HostnameWanted(st settings.Settings) bool {
	c := st.Captcha
	return c.Central && c.CentralURL != "" && c.CentralMode == "hostname" && st.WAF.Enabled
}

// ServerHostname is this server's hostname when it can carry the page.
func ServerHostname() string {
	h, _ := os.Hostname()
	h = strings.TrimSuffix(strings.ToLower(h), ".")
	if !reHostname.MatchString(h) {
		return ""
	}
	return h
}

// HostPageURL is where suspects are sent on hostname.
func HostPageURL(hostname string) string { return "https://" + hostname + HostPagePath }

// HostPageHTML is the page: it frames the portal's check with the link's
// parameters (s, ip, h, k ... and the page "u" last) and, told by that
// check (its origin only) that the visitor passed, goes back to the
// website. The way back is built here from the link (https, the site's
// name, a path on it), never taken from the message.
func HostPageHTML(portalURL string) string {
	u, err := url.Parse(portalURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return ""
	}
	origin := "https://" + u.Host
	js := func(v string) string {
		return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "<", `<`, ">", `>`, "\n", "").Replace(v)
	}
	return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><meta name="referrer" content="no-referrer"><title>Security check</title>
<!-- ` + hostPageMarker + ` -->
<style>html,body{margin:0;height:100%;background:#f8fafc;font-family:system-ui,sans-serif;color:#334155}iframe{position:fixed;inset:0;width:100%;height:100%;border:0;display:block}p{text-align:center;margin-top:40vh}</style>
</head><body><noscript><p>Please turn on JavaScript to continue.</p></noscript>
<script>(function(){
var PAGE="` + js(portalURL) + `",ORIGIN="` + js(origin) + `";
var q=location.search.slice(1),i=q.indexOf("&u=");
function bad(){var p=document.createElement("p");p.textContent="This check link is not valid.";document.body.appendChild(p)}
if(i<0){bad();return}
var head=q.slice(0,i),back=q.slice(i+3),site="";
head.split("&").forEach(function(kv){var j=kv.indexOf("=");if(j>0&&kv.slice(0,j)==="h"){try{site=decodeURIComponent(kv.slice(j+1)).toLowerCase()}catch(e){}}});
site=site.replace(/:[0-9]+$/,"").replace(/\.$/,"");
if(!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(site)||back.charAt(0)!=="/"||back.charAt(1)==="/"||back.charAt(1)==="\\"){bad();return}
var f=document.createElement("iframe");f.title="Security check";f.allow="";
f.src=PAGE+"?"+head+"&fh=1&u="+back;
document.body.appendChild(f);
addEventListener("message",function(e){if(e.origin===ORIGIN&&e.source===f.contentWindow&&e.data&&e.data.xg==="passed")location.replace("https://"+site+back)});
})();</script></body></html>
`
}

// InstallHostPage writes the page into the hostname's document root.
func InstallHostPage(portalURL string) error {
	body := HostPageHTML(portalURL)
	if body == "" {
		return fmt.Errorf("invalid CAPTCHA page address %q", portalURL)
	}
	if st, err := os.Stat(HostDocRoot); err != nil || !st.IsDir() {
		return fmt.Errorf("the hostname's document root %s is missing", HostDocRoot)
	}
	dir := filepath.Join(HostDocRoot, strings.Trim(HostPagePath, "/"))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	_ = os.Chmod(dir, 0o755)
	path := filepath.Join(dir, "index.html")
	if cur, err := os.ReadFile(path); err == nil && string(cur) == body {
		return nil
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(body), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// RemoveHostPage removes the page (another place chosen, CAPTCHA off). It
// only removes what InstallHostPage wrote.
func RemoveHostPage() {
	dir := filepath.Join(HostDocRoot, strings.Trim(HostPagePath, "/"))
	path := filepath.Join(dir, "index.html")
	if cur, err := os.ReadFile(path); err == nil && strings.Contains(string(cur), hostPageMarker) {
		_ = os.Remove(path)
		_ = os.Remove(dir) // only when empty
	}
}

// hostCheckAddr is where the self-test connects (the web server on this
// machine) and hostCheckRoots the certificates it trusts (nil: the
// system's); tests change them.
var (
	hostCheckAddr  = "127.0.0.1:443"
	hostCheckRoots *x509.CertPool
)

// CheckHostPage confirms what a visitor's browser needs: the hostname
// resolves to this server, the web server serves the page on 443 with a
// certificate valid for the hostname, and the page is this one.
func CheckHostPage(ctx context.Context, hostname, portalURL string, serverIPs []string) error {
	if !reHostname.MatchString(hostname) {
		return fmt.Errorf("the server hostname %q cannot carry the page", hostname)
	}
	if serverIPs != nil {
		addrs, err := net.DefaultResolver.LookupHost(ctx, hostname)
		if err != nil {
			return fmt.Errorf("%s does not resolve: %v", hostname, err)
		}
		mine := map[string]bool{}
		for _, ip := range serverIPs {
			if p := net.ParseIP(ip); p != nil {
				mine[p.String()] = true
			}
		}
		ok := false
		for _, a := range addrs {
			if p := net.ParseIP(a); p != nil && mine[p.String()] {
				ok = true
			}
		}
		if !ok {
			return fmt.Errorf("%s resolves to %s, not to this server", hostname, strings.Join(addrs, ", "))
		}
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, hostCheckAddr)
		},
		TLSClientConfig: &tls.Config{ServerName: hostname, RootCAs: hostCheckRoots},
		Proxy:           nil,
	}
	defer tr.CloseIdleConnections()
	c := &http.Client{Transport: tr, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, HostPageURL(hostname)+"?s=self-test&ip=127.0.0.1&h="+hostname+"&u=/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (xPGuard hostname self-test)")
	req.Header.Set("Accept", "text/html")
	res, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("https://%s%s: %v", hostname, HostPagePath, err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 64<<10))
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("https://%s%s answers %s", hostname, HostPagePath, res.Status)
	}
	if !strings.Contains(string(body), hostPageMarker) || !strings.Contains(string(body), portalURL) {
		return errors.New("the hostname serves another page at " + HostPagePath)
	}
	return nil
}

// CheckOwnTLS confirms that this server's CAPTCHA HTTPS port presents a
// certificate valid for hostname: a visitor the firewall sends here (IPDB,
// ban) reaches the hostname page there, not at the web server. Without it
// those visitors go to the portal address instead.
func CheckOwnTLS(ctx context.Context, hostname string, port int) error {
	if port <= 0 || port > 65535 {
		return errors.New("no CAPTCHA HTTPS port")
	}
	addr := ownTLSAddr
	if addr == "" {
		addr = net.JoinHostPort("127.0.0.1", fmt.Sprint(port))
	}
	d := &tls.Dialer{Config: &tls.Config{ServerName: hostname, RootCAs: hostCheckRoots}}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	c, err := d.DialContext(cctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("the CAPTCHA port has no valid certificate for %s: %v", hostname, err)
	}
	return c.Close()
}

// ownTLSAddr replaces the CAPTCHA port's address in tests.
var ownTLSAddr = ""

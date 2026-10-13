package firewall

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/xmarthost/xmartguard/agent/internal/captcha"
)

// An IPDB-listed address: robots.txt comes from the website (through the
// redirected connection's original address), a script gets a plain 403 and
// a browser the CAPTCHA page.
func TestMachineFilesFromSiteOnKernel(t *testing.T) {
	if os.Getenv("XG_DESTRUCTIVE_TESTS") != "1" {
		t.Skip("changes nat rules of this machine; set XG_DESTRUCTIVE_TESTS=1")
	}
	providers(t, func(t *testing.T, provider string) {
		m := newManager(t, provider)
		in := netns(t)
		// The website on port 80 of the server's address.
		site, err := net.Listen("tcp", "10.99.0.1:80")
		if err != nil {
			t.Skip("port 80 busy")
		}
		defer site.Close()
		go http.Serve(site, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "site:"+r.Host+r.URL.Path)
		}))
		// The real CAPTCHA server.
		cs := &captcha.Server{Settings: m.Settings, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
		srv := captcha.HTTPServer(7780, cs)
		ln, err := net.Listen("tcp", ":7780")
		if err != nil {
			t.Skip("port 7780 busy")
		}
		go srv.Serve(ln)
		defer srv.Close()

		m.IPDB = &IPDB{}
		m.IPDB.Replace("v1", []string{"10.99.0.2"})
		if _, err := m.Settings.Patch([]byte(`{"ipdb":{"enabled":true,"captcha":true}}`)); err != nil {
			t.Fatal(err)
		}
		if err := m.Apply(); err != nil {
			t.Fatal(err)
		}
		curl := func(path, accept string) string {
			out, _ := in("curl", "-s", "-m", "5", "-H", "Accept: "+accept, "-H", "Host: shop.example", "http://10.99.0.1"+path)
			return string(out)
		}
		if got := curl("/robots.txt", "*/*"); got != "site:shop.example/robots.txt" {
			t.Fatalf("robots.txt: %q\n%s", got, kernelDump(m))
		}
		if got := curl("/sitemap_index.xml", "*/*"); got != "site:shop.example/sitemap_index.xml" {
			t.Fatalf("sitemap: %q", got)
		}
		if got := curl("/sync-worker-v2.php", "*/*"); !strings.Contains(got, "403 Forbidden") {
			t.Fatalf("script: %q", got)
		}
		if got := curl("/", "text/html,*/*"); !strings.Contains(got, "Security check") {
			t.Fatalf("browser: %q", got)
		}
	})
}

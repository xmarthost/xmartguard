package captcha

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Site mode without port 7743 (2026-11-06): the check is served on every
// website's own address (https://<website>/xpguard-verify/) from one
// folder of the agent through a global Alias; no port the visitor's
// network may refuse.
func TestSitePage(t *testing.T) {
	p := SitePageHTML("https://captcha.test/v")
	for _, want := range []string{sitePageMarker, `PAGE="https://captcha.test/v",ORIGIN="https://captcha.test"`, `"&fs=1&u="`,
		`e.origin===ORIGIN&&e.source===f.contentWindow`} {
		if !strings.Contains(p, want) {
			t.Errorf("page misses %q", want)
		}
	}
	if strings.Contains(p, "&fh=1") || strings.Contains(p, hostPageMarker) {
		t.Error("site page reads as the hostname page")
	}
	if SitePageHTML("http://captcha.test/v") != "" {
		t.Error("page for a portal address that is not https")
	}

	dir := filepath.Join(t.TempDir(), "share", "verify")
	saved := SitePageDir
	SitePageDir = dir
	defer func() { SitePageDir = saved }()

	conf := SiteAliasConf()
	for _, want := range []string{"Alias /xpguard-verify/ " + dir + "/\n", `<Directory "` + dir + `">`,
		"Options None", "AllowOverride None", "Require all granted", "Require all denied"} {
		if !strings.Contains(conf, want) {
			t.Errorf("alias misses %q:\n%s", want, conf)
		}
	}
	if strings.Contains(SiteAliasOff, "Alias") {
		t.Error("the off text still serves the page")
	}

	if err := InstallSitePage("https://captcha.test/v"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "index.html")
	if b, _ := os.ReadFile(path); string(b) != p {
		t.Fatal("page not written")
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o644 {
		t.Fatalf("mode %v", st.Mode())
	}
	if InstallSitePage("javascript:alert(1)") == nil {
		t.Fatal("installed a page for a bad portal address")
	}
	RemoveSitePage()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("page left behind")
	}
	os.MkdirAll(dir, 0o755)
	os.WriteFile(path, []byte("someone's page"), 0o644)
	RemoveSitePage()
	if _, err := os.Stat(path); err != nil {
		t.Fatal("a page that is not ours was removed")
	}
}

// The self-test asks the web server for the page on the server's hostname
// (the alias serves every name alike) and only a page for this portal
// passes; the hostname page at its own path does not count.
func TestCheckSitePage(t *testing.T) {
	site := SitePageHTML("https://captcha.test/v")
	mux := http.NewServeMux()
	mux.HandleFunc(SitePagePath, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(site)) })
	ts := httptest.NewTLSServer(mux)
	defer ts.Close()
	savedAddr, savedRoots := hostCheckAddr, hostCheckRoots
	defer func() { hostCheckAddr, hostCheckRoots = savedAddr, savedRoots }()
	hostCheckAddr = strings.TrimPrefix(ts.URL, "https://")
	hostCheckRoots = x509.NewCertPool()
	hostCheckRoots.AddCert(ts.Certificate())
	ctx := context.Background()
	if err := CheckSitePage(ctx, "example.com", "https://captcha.test/v", nil); err != nil {
		t.Fatal(err)
	}
	if err := CheckSitePage(ctx, "example.com", "https://other.test/v", nil); err == nil {
		t.Fatal("a page for another portal passed")
	}
	site = HostPageHTML("https://captcha.test/v")
	if err := CheckSitePage(ctx, "example.com", "https://captcha.test/v", nil); err == nil {
		t.Fatal("the hostname page passed as the site page")
	}
	ts.Config.Handler = http.NotFoundHandler()
	if err := CheckSitePage(ctx, "example.com", "https://captcha.test/v", nil); err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("missing page: %v", err)
	}
}

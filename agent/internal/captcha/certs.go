package captcha

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// CertStore serves the website's own certificate for the requested name, so
// a redirected HTTPS visitor sees the CAPTCHA without a browser warning.
// cPanel keeps one PEM (key + chain) per vhost; Let's Encrypt layouts are
// read too. Unknown names get a self-signed certificate.
type CertStore struct {
	// Dirs are searched in order; empty means the standard locations.
	Dirs []string

	mu       sync.Mutex
	cache    map[string]*tls.Certificate
	loaded   map[string]time.Time
	fallback *tls.Certificate
	// index maps every name a stored certificate covers to its folder: cPanel
	// names the folder after the vhost (e.g. addon.example.com for the addon
	// domain example.net), not after each domain it serves.
	index   map[string]string
	indexAt time.Time
}

func (c *CertStore) dirs() []string {
	if len(c.Dirs) > 0 {
		return c.Dirs
	}
	return []string{"/var/cpanel/ssl/apache_tls", "/etc/letsencrypt/live"}
}

// Get implements tls.Config.GetCertificate.
func (c *CertStore) Get(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := strings.ToLower(strings.TrimSuffix(hello.ServerName, "."))
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cache == nil {
		c.cache, c.loaded = map[string]*tls.Certificate{}, map[string]time.Time{}
	}
	if name != "" && !strings.ContainsAny(name, "/\\") && !strings.Contains(name, "..") {
		if cert, ok := c.cache[name]; ok && time.Since(c.loaded[name]) < time.Hour {
			if cert != nil {
				return cert, nil
			}
		} else {
			cert := c.load(name)
			if cert == nil {
				// www.example.com is usually covered by example.com's certificate.
				cert = c.load(strings.TrimPrefix(name, "www."))
			}
			if len(c.cache) > 5000 {
				c.cache, c.loaded = map[string]*tls.Certificate{}, map[string]time.Time{}
			}
			c.cache[name], c.loaded[name] = cert, time.Now()
			if cert != nil {
				return cert, nil
			}
		}
	}
	return c.selfSigned()
}

func (c *CertStore) load(name string) *tls.Certificate {
	if cert := c.loadDir(name); cert != nil {
		return cert
	}
	if time.Since(c.indexAt) > 10*time.Minute {
		c.buildIndex()
	}
	if dir, ok := c.index[name]; ok {
		return c.loadPath(dir)
	}
	// *.example.com covers a.example.com.
	if i := strings.IndexByte(name, '.'); i > 0 {
		if dir, ok := c.index["*"+name[i:]]; ok {
			return c.loadPath(dir)
		}
	}
	return nil
}

// buildIndex reads the names in every stored certificate.
func (c *CertStore) buildIndex() {
	c.index, c.indexAt = map[string]string{}, time.Now()
	for _, d := range c.dirs() {
		entries, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if len(c.index) > 50000 {
				return
			}
			dir := filepath.Join(d, e.Name())
			raw, err := os.ReadFile(filepath.Join(dir, "combined"))
			if err != nil {
				raw, err = os.ReadFile(filepath.Join(dir, "fullchain.pem"))
			}
			if err != nil {
				continue
			}
			leaf := firstCert(raw)
			if leaf == nil || time.Now().After(leaf.NotAfter) {
				continue
			}
			for _, n := range leaf.DNSNames {
				n = strings.ToLower(n)
				if _, dup := c.index[n]; !dup {
					c.index[n] = dir
				}
			}
		}
	}
}

func firstCert(raw []byte) *x509.Certificate {
	for {
		var b *pem.Block
		b, raw = pem.Decode(raw)
		if b == nil {
			return nil
		}
		if b.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(b.Bytes)
			if err != nil {
				return nil
			}
			return cert
		}
	}
}

func (c *CertStore) loadPath(dir string) *tls.Certificate {
	if raw, err := os.ReadFile(filepath.Join(dir, "combined")); err == nil {
		if cert, err := tls.X509KeyPair(raw, raw); err == nil {
			return &cert
		}
	}
	if cert, err := tls.LoadX509KeyPair(filepath.Join(dir, "fullchain.pem"), filepath.Join(dir, "privkey.pem")); err == nil {
		return &cert
	}
	return nil
}

func (c *CertStore) loadDir(name string) *tls.Certificate {
	for _, d := range c.dirs() {
		// cPanel: <dir>/<name>/combined holds key and chain in one file.
		if raw, err := os.ReadFile(filepath.Join(d, name, "combined")); err == nil {
			if cert, err := tls.X509KeyPair(raw, raw); err == nil {
				return &cert
			}
		}
		// Let's Encrypt (certbot) layout.
		if cert, err := tls.LoadX509KeyPair(filepath.Join(d, name, "fullchain.pem"), filepath.Join(d, name, "privkey.pem")); err == nil {
			return &cert
		}
	}
	return nil
}

func (c *CertStore) selfSigned() (*tls.Certificate, error) {
	if c.fallback != nil {
		return c.fallback, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "xPGuard security check"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(5, 0, 0),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	c.fallback = &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	return c.fallback, nil
}

package captcha

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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
		SerialNumber: serial, Subject: pkix.Name{CommonName: "XMart Guard security check"},
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

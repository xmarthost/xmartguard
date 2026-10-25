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
	index    map[string]string
	indexAt  time.Time
	building bool // an index rebuild is running
}

func (c *CertStore) dirs() []string {
	if len(c.Dirs) > 0 {
		return c.Dirs
	}
	return []string{"/var/cpanel/ssl/apache_tls", "/etc/letsencrypt/live"}
}

// Get implements tls.Config.GetCertificate. The lock is held only to read
// and write the cache: the files are read outside it, so one slow lookup
// (or the index rebuild) does not hold up every other handshake.
func (c *CertStore) Get(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := strings.ToLower(strings.TrimSuffix(hello.ServerName, "."))
	if name != "" && !strings.ContainsAny(name, "/\\") && !strings.Contains(name, "..") {
		c.mu.Lock()
		if c.cache == nil {
			c.cache, c.loaded = map[string]*tls.Certificate{}, map[string]time.Time{}
		}
		cert, ok := c.cache[name]
		fresh := ok && time.Since(c.loaded[name]) < time.Hour
		c.mu.Unlock()
		if fresh {
			if cert != nil {
				return cert, nil
			}
		} else {
			cert = c.load(name)
			if cert == nil {
				// www.example.com is usually covered by example.com's certificate.
				cert = c.load(strings.TrimPrefix(name, "www."))
			}
			if cert == nil {
				// The server's hostname: cPanel keeps its certificate with the
				// service certificates, not with the websites' (a banned
				// visitor sent to the hostname CAPTCHA page reaches this
				// server, not the web server).
				cert = serviceCert(name)
			}
			c.mu.Lock()
			if len(c.cache) > 5000 {
				c.cache, c.loaded = map[string]*tls.Certificate{}, map[string]time.Time{}
			}
			c.cache[name], c.loaded[name] = cert, time.Now()
			c.mu.Unlock()
			if cert != nil {
				return cert, nil
			}
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.selfSigned()
}

func (c *CertStore) load(name string) *tls.Certificate {
	if cert := c.loadDir(name); cert != nil {
		return cert
	}
	index := c.currentIndex()
	if dir, ok := index[name]; ok {
		return c.loadPath(dir)
	}
	// *.example.com covers a.example.com.
	if i := strings.IndexByte(name, '.'); i > 0 {
		if dir, ok := index["*"+name[i:]]; ok {
			return c.loadPath(dir)
		}
	}
	return nil
}

// currentIndex returns the name index. The first one is built right away;
// later ones (every 10 minutes) are rebuilt in the background while
// handshakes keep using the previous index.
func (c *CertStore) currentIndex() map[string]string {
	c.mu.Lock()
	index := c.index
	// No index yet: every caller builds it (not "not found" for an hour).
	stale := time.Since(c.indexAt) > 10*time.Minute && (!c.building || index == nil)
	if stale {
		c.building = true
	}
	c.mu.Unlock()
	if !stale {
		return index
	}
	rebuild := func() map[string]string {
		next := c.buildIndex()
		c.mu.Lock()
		c.index, c.indexAt, c.building = next, time.Now(), false
		c.mu.Unlock()
		return next
	}
	if index == nil {
		return rebuild()
	}
	go rebuild()
	return index
}

// buildIndex reads the names in every stored certificate.
func (c *CertStore) buildIndex() map[string]string {
	index := map[string]string{}
	for _, d := range c.dirs() {
		entries, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if len(index) > 50000 {
				return index
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
				if _, dup := index[n]; !dup {
					index[n] = dir
				}
			}
		}
	}
	return index
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

// ServiceCerts are files that may hold the server hostname's certificate
// with its key (cPanel's service certificates: cpsrvd, Exim, Dovecot,
// Pure-FTPd), tried in order. A file with the certificate only is paired
// with the key file next to it (.key). Tests change them.
var ServiceCerts = []string{
	"/var/cpanel/ssl/cpanel/cpanel.pem",
	"/var/cpanel/ssl/cpanel/mycpanel.pem",
	"/var/cpanel/ssl/exim/exim.pem",
	"/var/cpanel/ssl/dovecot/dovecot.pem",
	"/var/cpanel/ssl/ftp/pure-ftpd.pem",
}

// serviceCert is the first service certificate valid now for name.
func serviceCert(name string) *tls.Certificate {
	if !reHostname.MatchString(name) {
		return nil
	}
	for _, f := range ServiceCerts {
		raw, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		cert, err := tls.X509KeyPair(raw, raw)
		if err != nil {
			key, kerr := os.ReadFile(strings.TrimSuffix(f, filepath.Ext(f)) + ".key")
			if kerr != nil {
				continue
			}
			if cert, err = tls.X509KeyPair(raw, key); err != nil {
				continue
			}
		}
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil || time.Now().After(leaf.NotAfter) || time.Now().Before(leaf.NotBefore) || leaf.VerifyHostname(name) != nil {
			continue
		}
		// The issuers when the file holds only the certificate (cPanel keeps
		// them in a .cabundle next to it).
		if len(cert.Certificate) == 1 {
			if bundle, err := os.ReadFile(strings.TrimSuffix(f, filepath.Ext(f)) + ".cabundle"); err == nil {
				for {
					var b *pem.Block
					if b, bundle = pem.Decode(bundle); b == nil {
						break
					}
					if b.Type == "CERTIFICATE" {
						cert.Certificate = append(cert.Certificate, b.Bytes)
					}
				}
			}
		}
		return &cert
	}
	return nil
}

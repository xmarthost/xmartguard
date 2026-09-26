// Package wpcore knows the official WordPress core files, so the scanner
// never flags them, and restores infected core files from the official
// release of the site's version.
//
// The agent ships with the MD5 of every PHP/JS/HTML/text/image file of every
// WordPress release since 5.8 (baseline.md5.gz, built from the official
// release history); the portal keeps the list current with every new
// release, beta and release candidate (see Sync).
package wpcore

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/md5"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/store"
)

//go:embed baseline.md5.gz
var baseline []byte

// BaselineVersion is the newest release included in baseline.md5.gz.
const BaselineVersion = "7.1.2"

// Set is a sorted list of MD5 digests.
type Set struct {
	mu   sync.RWMutex
	sums [][16]byte
	etag string
}

var (
	defOnce sync.Once
	def     *Set
)

// Default returns the known-good set: the baseline plus the portal's list.
func Default() *Set {
	defOnce.Do(func() {
		def = &Set{}
		def.sums = decode(baseline)
		if raw, err := os.ReadFile(SyncedPath()); err == nil {
			def.merge(decode(raw))
			def.etag = strings.TrimSpace(readString(SyncedPath() + ".etag"))
		}
	})
	return def
}

// SyncedPath is where the portal's list is kept.
func SyncedPath() string { return filepath.Join(store.StateDir(), "wp-core.md5.gz") }

func readString(p string) string {
	b, _ := os.ReadFile(p)
	return string(b)
}

// decode reads gzip-compressed concatenated 16-byte digests (or raw).
func decode(data []byte) [][16]byte {
	if zr, err := gzip.NewReader(bytes.NewReader(data)); err == nil {
		if raw, err := io.ReadAll(io.LimitReader(zr, 64<<20)); err == nil {
			data = raw
		}
	}
	out := make([][16]byte, 0, len(data)/16)
	for i := 0; i+16 <= len(data); i += 16 {
		var d [16]byte
		copy(d[:], data[i:i+16])
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i][:], out[j][:]) < 0 })
	return out
}

func (s *Set) merge(more [][16]byte) {
	all := append(s.sums, more...)
	sort.Slice(all, func(i, j int) bool { return bytes.Compare(all[i][:], all[j][:]) < 0 })
	out := all[:0]
	for i, d := range all {
		if i == 0 || d != all[i-1] {
			out = append(out, d)
		}
	}
	s.sums = out
}

// Known reports whether content with this MD5 is an official core file.
func (s *Set) Known(sum [16]byte) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	i := sort.Search(len(s.sums), func(i int) bool { return bytes.Compare(s.sums[i][:], sum[:]) >= 0 })
	return i < len(s.sums) && s.sums[i] == sum
}

// Count is the number of known files.
func (s *Set) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.sums)
}

// ETag identifies the portal list in use ("" = baseline only).
func (s *Set) ETag() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.etag
}

// Update stores and merges a list received from the portal.
func (s *Set) Update(data []byte, etag string) error {
	sums := decode(data)
	if len(sums) < 1000 {
		return fmt.Errorf("wpcore: list too small (%d)", len(sums))
	}
	if err := os.MkdirAll(filepath.Dir(SyncedPath()), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(SyncedPath(), data, 0o600); err != nil {
		return err
	}
	_ = os.WriteFile(SyncedPath()+".etag", []byte(etag), 0o600)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sums = decode(baseline)
	s.merge(sums)
	s.etag = etag
	return nil
}

// ------------------------------------------------------------------ sites

var reVersion = regexp.MustCompile(`\$wp_version\s*=\s*'([^']+)'`)

// FindRoot returns the WordPress install containing path and the file's
// path relative to it ("", "" when path is not inside WordPress).
func FindRoot(path string) (root, rel string) {
	dir := filepath.Dir(path)
	for i := 0; i < 12 && dir != "/" && dir != "."; i++ {
		if st, err := os.Stat(filepath.Join(dir, "wp-includes", "version.php")); err == nil && st.Mode().IsRegular() {
			if st, err := os.Stat(filepath.Join(dir, "wp-admin")); err == nil && st.IsDir() {
				r, err := filepath.Rel(dir, path)
				if err != nil || strings.HasPrefix(r, "..") {
					return "", ""
				}
				return dir, filepath.ToSlash(r)
			}
		}
		dir = filepath.Dir(dir)
	}
	return "", ""
}

// Version reads the WordPress version of an install.
func Version(root string) string {
	f, err := os.Open(filepath.Join(root, "wp-includes", "version.php"))
	if err != nil {
		return ""
	}
	defer f.Close()
	head, _ := io.ReadAll(io.LimitReader(f, 32<<10))
	if m := reVersion.FindSubmatch(head); m != nil {
		return string(m[1])
	}
	return ""
}

// ------------------------------------------------------------------ repair

// Source provides official checksums and files (the portal, then
// wordpress.org directly).
type Source interface {
	Checksums(ctx context.Context, version string) (map[string]string, error)
	File(ctx context.Context, version, rel string) ([]byte, error)
}

// ErrNotCore means the file is not part of the site's WordPress release.
var ErrNotCore = errors.New("not a WordPress core file")

// Official returns the official content of a core file for the version of
// the install it belongs to, verified against the official checksum.
func Official(ctx context.Context, src Source, path string) (content []byte, version, rel string, err error) {
	root, rel := FindRoot(path)
	if root == "" {
		return nil, "", "", ErrNotCore
	}
	version = Version(root)
	if version == "" {
		return nil, "", rel, errors.New("the WordPress version could not be read")
	}
	sums, err := src.Checksums(ctx, version)
	if err != nil {
		return nil, version, rel, err
	}
	want, ok := sums[rel]
	if !ok {
		return nil, version, rel, ErrNotCore
	}
	body, err := src.File(ctx, version, rel)
	if err != nil {
		return nil, version, rel, err
	}
	sum := md5.Sum(body)
	if hex.EncodeToString(sum[:]) != strings.ToLower(want) {
		return nil, version, rel, fmt.Errorf("downloaded %s does not match the official checksum", rel)
	}
	return body, version, rel, nil
}

// Direct fetches from wordpress.org (and its GitHub mirror as a fallback).
type Direct struct {
	Client   *http.Client
	API      string // https://api.wordpress.org
	SVN      string // https://core.svn.wordpress.org/tags
	Mirror   string // https://raw.githubusercontent.com/WordPress/WordPress
	CacheDir string
}

// NewDirect returns a Direct source with the public endpoints.
func NewDirect() *Direct {
	return &Direct{
		Client:   &http.Client{Timeout: 60 * time.Second},
		API:      "https://api.wordpress.org",
		SVN:      "https://core.svn.wordpress.org/tags",
		Mirror:   "https://raw.githubusercontent.com/WordPress/WordPress",
		CacheDir: filepath.Join(store.StateDir(), "cms"),
	}
}

func (d *Direct) get(ctx context.Context, u string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "XMartGuard")
	res, err := d.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("%s: HTTP %d", u, res.StatusCode)
	}
	return io.ReadAll(io.LimitReader(res.Body, limit))
}

// Checksums implements Source (cached on disk).
func (d *Direct) Checksums(ctx context.Context, version string) (map[string]string, error) {
	cache := filepath.Join(d.CacheDir, "wp-checksums-"+version+"-en_US.json")
	if b, err := os.ReadFile(cache); err == nil {
		if m := parseChecksums(b); len(m) > 0 {
			return m, nil
		}
	}
	b, err := d.get(ctx, d.API+"/core/checksums/1.0/?version="+version+"&locale=en_US", 8<<20)
	if err != nil {
		return nil, err
	}
	m := parseChecksums(b)
	if len(m) == 0 {
		return nil, fmt.Errorf("no official checksums for WordPress %s", version)
	}
	_ = os.MkdirAll(d.CacheDir, 0o700)
	_ = os.WriteFile(cache, b, 0o600)
	return m, nil
}

// File implements Source.
func (d *Direct) File(ctx context.Context, version, rel string) ([]byte, error) {
	if !safeRel(rel) {
		return nil, errors.New("invalid path")
	}
	b, err := d.get(ctx, d.SVN+"/"+version+"/"+rel, 32<<20)
	if err == nil {
		return b, nil
	}
	if b2, err2 := d.get(ctx, d.Mirror+"/"+version+"/"+rel, 32<<20); err2 == nil {
		return b2, nil
	}
	return nil, err
}

func safeRel(rel string) bool {
	return rel != "" && !strings.HasPrefix(rel, "/") && !strings.Contains(rel, "..") && !strings.ContainsAny(rel, "\\\x00?#")
}

// Chain tries sources in order.
type Chain []Source

// Checksums implements Source.
func (c Chain) Checksums(ctx context.Context, version string) (map[string]string, error) {
	var last error = errors.New("no source")
	for _, s := range c {
		if m, err := s.Checksums(ctx, version); err == nil && len(m) > 0 {
			return m, nil
		} else if err != nil {
			last = err
		}
	}
	return nil, last
}

// File implements Source.
func (c Chain) File(ctx context.Context, version, rel string) ([]byte, error) {
	var last error = errors.New("no source")
	for _, s := range c {
		if b, err := s.File(ctx, version, rel); err == nil {
			return b, nil
		} else {
			last = err
		}
	}
	return nil, last
}

// parseChecksums reads {"checksums": {"path": "md5"}} (or a bare map).
func parseChecksums(b []byte) map[string]string {
	var r struct {
		Checksums map[string]string `json:"checksums"`
	}
	if json.Unmarshal(b, &r) == nil && len(r.Checksums) > 0 {
		return r.Checksums
	}
	var m map[string]string
	_ = json.Unmarshal(b, &m)
	return m
}

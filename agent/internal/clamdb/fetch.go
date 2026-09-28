package clamdb

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// MaxDownload caps one subscription database.
var MaxDownload int64 = 300 << 20

// dbExt guesses a database's type from its URL or its first bytes.
func dbExt(u string, head []byte) string {
	if p, err := url.Parse(u); err == nil {
		if e := strings.ToLower(filepath.Ext(p.Path)); dbExts[e] || e == ".cvd" || e == ".cld" {
			return e
		}
	}
	if bytes.HasPrefix(head, []byte("ClamAV-VDB")) {
		return ".cvd"
	}
	sc := bufio.NewScanner(bytes.NewReader(head))
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l == "" || l[0] == '#' {
			continue
		}
		if strings.Count(l, ";") >= 3 {
			return ".ldb"
		}
		f := strings.Split(l, ":")
		if len(f) >= 3 {
			switch len(f[0]) {
			case 32:
				return ".hdb"
			case 40, 64:
				return ".hsb"
			}
		}
		return ".ndb"
	}
	return ".ndb"
}

// Fetch downloads the subscription databases into dir (one file per URL,
// named after a hash of the URL so a license key never appears in a file
// name) and removes files of URLs no longer configured. It returns errors
// per URL; a failed download keeps the previous copy.
func Fetch(ctx context.Context, client *http.Client, urls []string, dir string) map[string]string {
	errs := map[string]string{}
	_ = os.MkdirAll(dir, 0o700)
	keep := map[string]bool{}
	for _, u := range urls {
		sum := sha256.Sum256([]byte(u))
		base := "sub-" + hex.EncodeToString(sum[:6])
		// An existing copy keeps its name (and type).
		old, _ := filepath.Glob(filepath.Join(dir, base+".*"))
		for _, o := range old {
			keep[filepath.Base(o)] = true
		}
		if err := fetchOne(ctx, client, u, dir, base, old, keep); err != nil {
			errs[redact(u)] = err.Error()
		}
	}
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if !keep[e.Name()] {
			_ = os.Remove(filepath.Join(dir, e.Name()))
		}
	}
	return errs
}

func fetchOne(ctx context.Context, client *http.Client, u, dir, base string, old []string, keep map[string]bool) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "xPGuard-Agent (signature update)")
	if len(old) == 1 {
		if st, err := os.Stat(old[0]); err == nil {
			req.Header.Set("If-Modified-Since", st.ModTime().UTC().Format(http.TimeFormat))
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	tmp, err := os.CreateTemp(dir, ".dl-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	n, err := io.Copy(tmp, io.LimitReader(resp.Body, MaxDownload+1))
	tmp.Close()
	if err != nil {
		return err
	}
	if n > MaxDownload {
		return fmt.Errorf("larger than %d MB", MaxDownload>>20)
	}
	f, err := os.Open(tmp.Name())
	if err != nil {
		return err
	}
	head := make([]byte, 4096)
	k, _ := io.ReadFull(f, head)
	f.Close()
	name := base + dbExt(u, head[:k])
	for _, o := range old {
		if filepath.Base(o) != name {
			_ = os.Remove(o)
			delete(keep, filepath.Base(o))
		}
	}
	if err := os.Rename(tmp.Name(), filepath.Join(dir, name)); err != nil {
		return err
	}
	keep[name] = true
	if lm, err := http.ParseTime(resp.Header.Get("Last-Modified")); err == nil {
		_ = os.Chtimes(filepath.Join(dir, name), time.Now(), lm)
	}
	return nil
}

// redact hides query strings and user info (license keys) in messages.
func redact(u string) string {
	p, err := url.Parse(u)
	if err != nil {
		return "(invalid URL)"
	}
	p.User = nil
	if p.RawQuery != "" {
		p.RawQuery = "…"
	}
	return p.String()
}

// Fingerprint identifies the current set of database files (paths, sizes,
// modification times) so the engine is only rebuilt when something changed.
func Fingerprint(srcs []Source) string {
	var parts []string
	for _, s := range srcs {
		if st, err := os.Stat(s.Path); err == nil {
			parts = append(parts, fmt.Sprintf("%s:%d:%d", s.Path, st.Size(), st.ModTime().Unix()))
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, "|")
}

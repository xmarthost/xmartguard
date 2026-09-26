package cms

import (
	"context"
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Versions looks up the latest public releases, cached for a day in the
// agent database so hundreds of sites sharing plugins cost one request each.
type Versions struct {
	DB     *sql.DB
	Client *http.Client
	// Base URLs (overridable in tests).
	WPAPI     string
	JoomlaAPI string

	mu sync.Mutex
}

func NewVersions(db *sql.DB) *Versions {
	return &Versions{DB: db, Client: &http.Client{Timeout: 20 * time.Second},
		WPAPI: "https://api.wordpress.org", JoomlaAPI: "https://downloads.joomla.org/api/v1/latest/cms"}
}

const cacheTTL = 24 * time.Hour

func (v *Versions) cached(kind, slug string) (string, bool) {
	var ver string
	var at int64
	err := v.DB.QueryRow(`SELECT version, checked_at FROM cms_latest WHERE kind = ? AND slug = ?`, kind, slug).Scan(&ver, &at)
	if err != nil || time.Since(time.Unix(at, 0)) > cacheTTL {
		return "", false
	}
	return ver, true
}

func (v *Versions) store(kind, slug, ver string) {
	_, _ = v.DB.Exec(`INSERT INTO cms_latest (kind, slug, version, checked_at) VALUES (?,?,?,?)
		ON CONFLICT(kind, slug) DO UPDATE SET version = excluded.version, checked_at = excluded.checked_at`, kind, slug, ver, time.Now().Unix())
}

func (v *Versions) getJSON(ctx context.Context, u string, out any) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	req.Header.Set("User-Agent", "XMartGuard-Agent")
	res, err := v.Client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return fmt.Errorf("%s: HTTP %d", u, res.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(res.Body, 32<<20)).Decode(out)
}

// Latest returns the newest version of a core/plugin/theme ("" if unknown,
// e.g. a premium plugin that is not on wordpress.org).
func (v *Versions) Latest(ctx context.Context, kind, slug string) string {
	v.mu.Lock()
	defer v.mu.Unlock()
	if ver, ok := v.cached(kind, slug); ok {
		return ver
	}
	var ver string
	switch kind {
	case "wp-core":
		var r struct {
			Offers []struct {
				Current string `json:"current"`
			} `json:"offers"`
		}
		if v.getJSON(ctx, v.WPAPI+"/core/version-check/1.7/", &r) == nil && len(r.Offers) > 0 {
			ver = r.Offers[0].Current
		}
	case "wp-plugin", "wp-theme":
		api := "plugins/info/1.2/?action=plugin_information"
		if kind == "wp-theme" {
			api = "themes/info/1.2/?action=theme_information"
		}
		var r struct {
			Version string `json:"version"`
		}
		if v.getJSON(ctx, v.WPAPI+"/"+api+"&request[slug]="+url.QueryEscape(slug), &r) == nil {
			ver = r.Version
		}
	case "joomla":
		var r struct {
			Branches []struct {
				Version string `json:"version"`
			} `json:"branches"`
		}
		if v.getJSON(ctx, v.JoomlaAPI, &r) == nil {
			for _, b := range r.Branches {
				if CompareVersions(b.Version, ver) > 0 {
					ver = b.Version
				}
			}
		}
	}
	if ctx.Err() == nil {
		v.store(kind, slug, ver)
	}
	return ver
}

// ---- WordPress core integrity

// CoreReport lists core files that differ from the official release.
type CoreReport struct {
	Checked  int      `json:"checked"`
	Modified []string `json:"modified"`
	Unknown  []string `json:"unknown"` // PHP files in wp-admin/wp-includes that are not part of WordPress
	Error    string   `json:"error,omitempty"`
}

var reLocale = regexp.MustCompile(`\$wp_local_package\s*=\s*'([^']+)'`)

// Checksums fetches official md5 checksums for a WordPress version,
// cached on disk.
func (v *Versions) Checksums(ctx context.Context, cacheDir, version, locale string) (map[string]string, error) {
	file := filepath.Join(cacheDir, "wp-checksums-"+version+"-"+locale+".json")
	if b, err := os.ReadFile(file); err == nil {
		var m map[string]string
		if json.Unmarshal(b, &m) == nil && len(m) > 0 {
			return m, nil
		}
	}
	var r struct {
		Checksums json.RawMessage `json:"checksums"`
	}
	u := fmt.Sprintf("%s/core/checksums/1.0/?version=%s&locale=%s", v.WPAPI, url.QueryEscape(version), url.QueryEscape(locale))
	if err := v.getJSON(ctx, u, &r); err != nil {
		return nil, err
	}
	var m map[string]string
	if err := json.Unmarshal(r.Checksums, &m); err != nil || len(m) == 0 {
		return nil, fmt.Errorf("no official checksums for WordPress %s (%s)", version, locale)
	}
	if b, err := json.Marshal(m); err == nil {
		_ = os.MkdirAll(cacheDir, 0o700)
		_ = os.WriteFile(file, b, 0o600)
	}
	return m, nil
}

func md5File(p string) string {
	f, err := os.Open(p)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// VerifyCore compares a WordPress install against the official checksums.
func VerifyCore(root string, sums map[string]string) CoreReport {
	rep := CoreReport{Modified: []string{}, Unknown: []string{}}
	for rel, want := range sums {
		if strings.HasPrefix(rel, "wp-content/") {
			continue // themes/plugins shipped with core are updated separately
		}
		got := md5File(filepath.Join(root, rel))
		if got == "" {
			continue // missing core files are not a malware sign
		}
		rep.Checked++
		if got != want && len(rep.Modified) < 200 {
			rep.Modified = append(rep.Modified, rel)
		}
	}
	for _, dir := range []string{"wp-admin", "wp-includes"} {
		_ = filepath.WalkDir(filepath.Join(root, dir), func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || len(rep.Unknown) >= 200 {
				return nil
			}
			rel, _ := filepath.Rel(root, p)
			if _, ok := sums[filepath.ToSlash(rel)]; !ok && strings.HasSuffix(strings.ToLower(d.Name()), ".php") {
				rep.Unknown = append(rep.Unknown, filepath.ToSlash(rel))
			}
			return nil
		})
	}
	sort.Strings(rep.Modified)
	sort.Strings(rep.Unknown)
	return rep
}

// Locale reads the install's locale from version.php (default en_US).
func Locale(root string) string {
	if l := firstMatch(reLocale, readHead(filepath.Join(root, "wp-includes", "version.php"), 16<<10)); l != "" {
		return l
	}
	return "en_US"
}

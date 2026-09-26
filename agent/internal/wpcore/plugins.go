package wpcore

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Plugins recognises unmodified files of plugins published on
// WordPress.org, using the official per-version checksums
// (downloads.wordpress.org/plugin-checksums/<slug>/<version>.json).
// Premium plugins have no public checksums and are scanned normally.
type Plugins struct {
	Source   PluginSource
	CacheDir string

	mu      sync.Mutex
	sums    map[string]*pluginSums // "slug@version"
	version map[string]verEntry    // plugin dir -> version
}

// PluginSource fetches the checksums JSON of one plugin version.
// ErrNoChecksums means the plugin is not on WordPress.org.
type PluginSource interface {
	PluginChecksums(ctx context.Context, slug, version string) ([]byte, error)
}

// ErrNoChecksums is returned for plugins without public checksums.
var ErrNoChecksums = errors.New("no public checksums")

type pluginSums struct {
	files map[string]map[string]bool // rel -> md5 set
	until time.Time                  // retry time for a failed lookup
}

type verEntry struct {
	version string
	mtime   time.Time
}

var (
	reSlug          = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,99}$`)
	rePluginVersion = regexp.MustCompile(`(?mi)^[ \t/*#@]*Version:\s*([0-9][0-9A-Za-z.\-+]*)`)
	rePluginName    = regexp.MustCompile(`(?mi)^[ \t/*#@]*Plugin Name:`)
)

// pluginOf splits .../wp-content/plugins/<slug>/<rel>.
func pluginOf(path string) (dir, slug, rel string) {
	const marker = "/wp-content/plugins/"
	i := strings.LastIndex(path, marker)
	if i < 0 {
		return "", "", ""
	}
	rest := path[i+len(marker):]
	slug, rel, ok := strings.Cut(rest, "/")
	if !ok || !reSlug.MatchString(slug) || rel == "" {
		return "", "", ""
	}
	return path[:i+len(marker)] + slug, slug, rel
}

// pluginVersion reads the Version header of the plugin's main file.
func (p *Plugins) pluginVersion(dir string) string {
	st, err := os.Stat(dir)
	if err != nil {
		return ""
	}
	p.mu.Lock()
	if e, ok := p.version[dir]; ok && e.mtime.Equal(st.ModTime()) {
		p.mu.Unlock()
		return e.version
	}
	p.mu.Unlock()
	ver := ""
	files, _ := filepath.Glob(filepath.Join(dir, "*.php"))
	for _, f := range files {
		head := readHead(f, 8<<10)
		if rePluginName.Match(head) {
			if m := rePluginVersion.FindSubmatch(head); m != nil {
				ver = string(m[1])
				break
			}
		}
	}
	p.mu.Lock()
	if p.version == nil {
		p.version = map[string]verEntry{}
	}
	p.version[dir] = verEntry{ver, st.ModTime()}
	p.mu.Unlock()
	return ver
}

func readHead(path string, n int) []byte {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	buf := make([]byte, n)
	k, _ := bufio.NewReader(f).Read(buf)
	return buf[:k]
}

// parsePluginChecksums reads {"files": {"rel": {"md5": "…" | ["…", …]}}}.
func parsePluginChecksums(b []byte) (map[string]map[string]bool, error) {
	var doc struct {
		Files map[string]struct {
			MD5 json.RawMessage `json:"md5"`
		} `json:"files"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	out := map[string]map[string]bool{}
	for rel, f := range doc.Files {
		set := map[string]bool{}
		var one string
		var many []string
		if json.Unmarshal(f.MD5, &one) == nil && one != "" {
			set[strings.ToLower(one)] = true
		} else if json.Unmarshal(f.MD5, &many) == nil {
			for _, m := range many {
				set[strings.ToLower(m)] = true
			}
		}
		if len(set) > 0 {
			out[rel] = set
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no files in the checksums")
	}
	return out, nil
}

func (p *Plugins) checksums(slug, version string) map[string]map[string]bool {
	key := slug + "@" + version
	p.mu.Lock()
	if p.sums == nil {
		p.sums = map[string]*pluginSums{}
	}
	e, ok := p.sums[key]
	p.mu.Unlock()
	if ok && (e.files != nil || time.Now().Before(e.until)) {
		return e.files
	}
	cache := ""
	if p.CacheDir != "" {
		cache = filepath.Join(p.CacheDir, slug+"@"+version+".json")
		if b, err := os.ReadFile(cache); err == nil {
			if files, err := parsePluginChecksums(b); err == nil {
				p.store(key, files, time.Time{})
				return files
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var files map[string]map[string]bool
	b, err := p.Source.PluginChecksums(ctx, slug, version)
	if err == nil {
		files, err = parsePluginChecksums(b)
	}
	if err != nil {
		// Premium plugin or network trouble: do not ask again for a while.
		retry := time.Hour
		if errors.Is(err, ErrNoChecksums) {
			retry = 24 * time.Hour
		}
		p.store(key, nil, time.Now().Add(retry))
		return nil
	}
	if cache != "" {
		_ = os.MkdirAll(p.CacheDir, 0o700)
		_ = os.WriteFile(cache, b, 0o600)
	}
	p.store(key, files, time.Time{})
	return files
}

func (p *Plugins) store(key string, files map[string]map[string]bool, until time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.sums) > 5000 {
		p.sums = map[string]*pluginSums{}
	}
	p.sums[key] = &pluginSums{files: files, until: until}
}

// Known reports whether path is an unmodified file of a WordPress.org plugin.
func (p *Plugins) Known(path string, sum [16]byte) bool {
	if p == nil || p.Source == nil {
		return false
	}
	dir, slug, rel := pluginOf(path)
	if dir == "" {
		return false
	}
	ver := p.pluginVersion(dir)
	if ver == "" {
		return false
	}
	files := p.checksums(slug, ver)
	return files[rel][hex.EncodeToString(sum[:])]
}

// DirectPlugins fetches from downloads.wordpress.org.
type DirectPlugins struct{ D *Direct }

// PluginChecksums implements PluginSource.
func (d DirectPlugins) PluginChecksums(ctx context.Context, slug, version string) ([]byte, error) {
	b, err := d.D.get(ctx, fmt.Sprintf("https://downloads.wordpress.org/plugin-checksums/%s/%s.json", slug, version), 16<<20)
	if err != nil && strings.Contains(err.Error(), "HTTP 404") {
		return nil, ErrNoChecksums
	}
	return b, err
}

// PluginChain tries sources in order (the portal, then WordPress.org).
type PluginChain []PluginSource

// PluginChecksums implements PluginSource.
func (c PluginChain) PluginChecksums(ctx context.Context, slug, version string) ([]byte, error) {
	var last error = ErrNoChecksums
	for _, s := range c {
		b, err := s.PluginChecksums(ctx, slug, version)
		if err == nil {
			return b, nil
		}
		last = err
		if errors.Is(err, ErrNoChecksums) {
			return nil, err
		}
	}
	return nil, last
}

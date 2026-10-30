package cms

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Plugin integrity. A backdoor is most often a few lines added to a real
// plugin's file, or a PHP file dropped into its folder, where a site owner
// never looks. wordpress.org publishes the checksums of every release of
// its plugins: a PHP file that differs, or one the release does not have,
// is reported for a person to check (WP.Plugin.ModifiedFiles). Nothing is
// changed; the file scanner judges the files themselves.

const (
	IntegrityCategory = "integrity"
	integritySig      = "WP.Plugin.ModifiedFiles"
	// Plugins checked per site and files per plugin (a scan stays light).
	integrityPlugins = 80
	integrityFiles   = 6000
)

// DownloadsAPI is where wordpress.org keeps plugin checksums (tests
// replace it).
var DownloadsAPI = "https://downloads.wordpress.org"

// PluginChecksums returns the SHA-256 sums of a plugin release by path
// (cached on disk; every release keeps its sums).
func (v *Versions) PluginChecksums(ctx context.Context, cacheDir, slug, version string) (map[string][]string, error) {
	if !reSlug.MatchString(slug) || !reSlug.MatchString(version) {
		return nil, fmt.Errorf("invalid plugin %q %q", slug, version)
	}
	file := filepath.Join(cacheDir, "plugin-"+slug+"-"+version+".json")
	if b, err := os.ReadFile(file); err == nil {
		var m map[string][]string
		if json.Unmarshal(b, &m) == nil && len(m) > 0 {
			return m, nil
		}
	}
	var r struct {
		Files map[string]struct {
			SHA256 json.RawMessage `json:"sha256"`
		} `json:"files"`
	}
	u := fmt.Sprintf("%s/plugin-checksums/%s/%s.json", DownloadsAPI, url.PathEscape(slug), url.PathEscape(version))
	if err := v.getJSON(ctx, u, &r); err != nil {
		return nil, err
	}
	m := map[string][]string{}
	for p, f := range r.Files {
		var one string
		var many []string
		if json.Unmarshal(f.SHA256, &one) == nil && one != "" {
			m[p] = []string{one}
		} else if json.Unmarshal(f.SHA256, &many) == nil && len(many) > 0 {
			m[p] = many // a file changed in the release without a version bump
		}
	}
	if len(m) == 0 {
		return nil, fmt.Errorf("no checksums for %s %s", slug, version)
	}
	if b, err := json.Marshal(m); err == nil {
		_ = os.MkdirAll(cacheDir, 0o700)
		_ = os.WriteFile(file, b, 0o600)
	}
	return m, nil
}

func sha256File(p string) string {
	f, _, err := openUserFile(p, os.O_RDONLY, -1) // no symlink, no FIFO
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// VerifyPlugin lists a plugin folder's PHP files that differ from the
// release and the ones the release does not have.
func VerifyPlugin(dir string, sums map[string][]string) (modified, added []string) {
	n := 0
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || n >= integrityFiles {
			return nil
		}
		if d.IsDir() {
			// Folders plugins fill at run time (caches, logs, uploads).
			if p != dir && (d.Name() == "cache" || d.Name() == "logs" || d.Name() == "node_modules") {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || !strings.HasSuffix(strings.ToLower(d.Name()), ".php") {
			return nil
		}
		n++
		rel, _ := filepath.Rel(dir, p)
		rel = filepath.ToSlash(rel)
		want, ok := sums[rel]
		if !ok {
			added = append(added, rel)
			return nil
		}
		got := sha256File(p)
		if got == "" {
			return nil
		}
		for _, w := range want {
			if strings.EqualFold(w, got) {
				return nil
			}
		}
		modified = append(modified, rel)
		return nil
	})
	sort.Strings(modified)
	sort.Strings(added)
	return modified, added
}

// checkIntegrity compares a site's wordpress.org plugins with their
// releases and records what differs.
func (m *Manager) checkIntegrity(ctx context.Context, s Site, cacheDir string) {
	if s.Type != WordPress || m.Versions == nil {
		return
	}
	var found []DBFinding
	checked := 0
	for _, p := range s.Plugins {
		if ctx.Err() != nil || checked >= integrityPlugins {
			break
		}
		// Only wordpress.org plugins at a version it has.
		if p.Latest == "" || p.Version == "" {
			continue
		}
		sums, err := m.Versions.PluginChecksums(ctx, cacheDir, p.Slug, p.Version)
		if err != nil {
			// wordpress.org did not answer: what was found before stays
			// (a release without sums, 404, has nothing to compare).
			if !strings.Contains(err.Error(), "HTTP 404") {
				found = append(found, m.keptWatchRows(s.Path, IntegrityCategory, "slug="+p.Slug)...)
			}
			continue
		}
		checked++
		mod, add := VerifyPlugin(filepath.Join(s.Path, "wp-content", "plugins", p.Slug), sums)
		if len(mod)+len(add) == 0 {
			continue
		}
		found = append(found, DBFinding{Table: "wp-content/plugins", Row: "slug=" + p.Slug, Signature: integritySig, Column: "files",
			Category: IntegrityCategory, Snippet: integritySnippet(p, mod, add)})
	}
	if ctx.Err() == nil {
		m.recordWatch(s, IntegrityCategory, found)
	}
}

// keptWatchRows are a site's detected rows of a watch for one row_ref, to be
// recorded again unchanged.
func (m *Manager) keptWatchRows(site, category, row string) []DBFinding {
	var out []DBFinding
	rows, err := m.DB.Query(`SELECT tbl, signature, column_name, snippet FROM db_findings WHERE site_path = ? AND category = ? AND row_ref = ? AND status = 'detected'`, site, category, row)
	if err != nil {
		return nil
	}
	defer rows.Close()
	for rows.Next() {
		f := DBFinding{Row: row, Category: category}
		if rows.Scan(&f.Table, &f.Signature, &f.Column, &f.Snippet) == nil {
			out = append(out, f)
		}
	}
	return out
}

func integritySnippet(p Component, mod, add []string) string {
	list := func(l []string) string {
		if len(l) > 8 {
			return strings.Join(l[:8], ", ") + fmt.Sprintf(" and %d more", len(l)-8)
		}
		return strings.Join(l, ", ")
	}
	var parts []string
	if len(mod) > 0 {
		parts = append(parts, fmt.Sprintf("%d PHP file(s) differ from the wordpress.org release: %s", len(mod), list(mod)))
	}
	if len(add) > 0 {
		parts = append(parts, fmt.Sprintf("%d PHP file(s) are not in it: %s", len(add), list(add)))
	}
	return fmt.Sprintf("plugin %s %s: %s. Reinstall the plugin from wordpress.org if nobody changed it.", p.Slug, p.Version, strings.Join(parts, "; "))
}

// Package cms finds WordPress, Joomla and OpenCart installations in hosting
// accounts, inventories their versions, plugins and themes, compares them
// with the latest releases, verifies WordPress core files and scans
// WordPress databases for injected malware.
package cms

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Kinds of CMS.
const (
	WordPress = "wordpress"
	Joomla    = "joomla"
	OpenCart  = "opencart"
)

// Install is one discovered CMS installation.
type Install struct {
	Type   string `json:"type"`
	Path   string `json:"path"`
	User   string `json:"user"`
	Domain string `json:"domain"`
}

// Account is a hosting account to search.
type Account struct {
	Name, Home string
}

// skip directories never holding a site (and huge ones).
var skipDirs = map[string]bool{
	"mail": true, "etc": true, "tmp": true, "logs": true, ".cpanel": true, ".trash": true, ".cache": true,
	"node_modules": true, "vendor": true, ".git": true, "wp-content": true, "wp-includes": true, "wp-admin": true,
	"cache": true, ".softaculous": true, "ssl": true, "access-logs": true, "virtfs": true, ".cagefs": true,
}

// Discover walks each account (to a limited depth) looking for CMS roots.
func Discover(accounts []Account, domains map[string]string) []Install {
	var out []Install
	for _, a := range accounts {
		base := strings.Count(filepath.Clean(a.Home), "/")
		_ = filepath.WalkDir(a.Home, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if !d.IsDir() {
				return nil
			}
			if p != a.Home && skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			if strings.Count(p, "/")-base > 5 {
				return filepath.SkipDir
			}
			if t := detect(p); t != "" {
				out = append(out, Install{Type: t, Path: p, User: a.Name, Domain: domainFor(p, domains)})
			}
			return nil
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

func isFile(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Mode().IsRegular()
}

func detect(dir string) string {
	switch {
	case isFile(filepath.Join(dir, "wp-config.php")) && isFile(filepath.Join(dir, "wp-includes", "version.php")):
		return WordPress
	case isFile(filepath.Join(dir, "configuration.php")) && (isFile(filepath.Join(dir, "libraries", "src", "Version.php")) || isFile(filepath.Join(dir, "libraries", "cms", "version", "version.php"))):
		return Joomla
	case isFile(filepath.Join(dir, "config.php")) && isFile(filepath.Join(dir, "admin", "config.php")) && isFile(filepath.Join(dir, "system", "startup.php")):
		return OpenCart
	}
	return ""
}

// domainFor maps a site directory to the domain whose document root holds it.
func domainFor(path string, docroots map[string]string) string {
	best, bestLen := "", -1
	for root, dom := range docroots {
		if (path == root || strings.HasPrefix(path, root+"/")) && len(root) > bestLen {
			best, bestLen = dom, len(root)
			if path != root { // a subfolder install: show domain/sub
				best = dom + strings.TrimPrefix(path, root)
			}
		}
	}
	return best
}

var reUserdataKV = regexp.MustCompile(`^(documentroot|servername):\s*(\S+)`)

// CPanelDocroots reads /var/cpanel/userdata/*/* (documentroot -> domain).
func CPanelDocroots(dir string) map[string]string {
	out := map[string]string{}
	users, _ := os.ReadDir(dir)
	for _, u := range users {
		if !u.IsDir() {
			continue
		}
		files, _ := os.ReadDir(filepath.Join(dir, u.Name()))
		for _, f := range files {
			n := f.Name()
			if f.IsDir() || strings.Contains(n, ".") == false || strings.HasSuffix(n, ".cache") || strings.HasSuffix(n, ".json") ||
				strings.HasSuffix(n, "_SSL") || n == "main" || strings.HasPrefix(n, "cache") {
				continue
			}
			fh, err := os.Open(filepath.Join(dir, u.Name(), n))
			if err != nil {
				continue
			}
			var root, name string
			sc := bufio.NewScanner(fh)
			for sc.Scan() {
				if m := reUserdataKV.FindStringSubmatch(strings.TrimSpace(sc.Text())); m != nil {
					if m[1] == "documentroot" {
						root = m[2]
					} else {
						name = m[2]
					}
				}
			}
			fh.Close()
			if root != "" && name != "" {
				if _, dup := out[root]; !dup {
					out[filepath.Clean(root)] = name
				}
			}
		}
	}
	return out
}

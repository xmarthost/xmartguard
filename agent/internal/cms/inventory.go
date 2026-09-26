package cms

import (
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Component is a plugin or theme.
type Component struct {
	Slug     string `json:"slug"`
	Name     string `json:"name"`
	Version  string `json:"version"`
	Latest   string `json:"latest"`
	Outdated bool   `json:"outdated"`
	Active   bool   `json:"active,omitempty"`
	// Known vulnerabilities of the installed version.
	Vulns []Vuln `json:"vulns,omitempty"`
}

func readHead(path string, n int64) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	b, _ := io.ReadAll(io.LimitReader(f, n))
	return string(b)
}

var (
	reWPVersion = regexp.MustCompile(`\$wp_version\s*=\s*'([^']+)'`)
	reHeader    = func(name string) *regexp.Regexp {
		return regexp.MustCompile(`(?mi)^[ \t/*#@]*` + name + `:\s*(.+?)\s*$`)
	}
	rePluginName = reHeader("Plugin Name")
	reThemeName  = reHeader("Theme Name")
	reVersionHdr = reHeader("Version")
	reJMajor     = regexp.MustCompile(`MAJOR_VERSION\s*=\s*(\d+)`)
	reJMinor     = regexp.MustCompile(`MINOR_VERSION\s*=\s*(\d+)`)
	reJPatch     = regexp.MustCompile(`PATCH_VERSION\s*=\s*(\d+)`)
	reJRelease   = regexp.MustCompile(`\$RELEASE\s*=\s*'([^']+)'`)
	reJDev       = regexp.MustCompile(`\$DEV_LEVEL\s*=\s*'([^']+)'`)
	reOCVersion  = regexp.MustCompile(`define\(\s*'VERSION'\s*,\s*'([^']+)'`)
)

func firstMatch(re *regexp.Regexp, s string) string {
	if m := re.FindStringSubmatch(s); m != nil {
		return strings.TrimSpace(m[1])
	}
	return ""
}

// Version reads the installed CMS version.
func Version(in Install) string {
	switch in.Type {
	case WordPress:
		return firstMatch(reWPVersion, readHead(filepath.Join(in.Path, "wp-includes", "version.php"), 16<<10))
	case Joomla:
		if s := readHead(filepath.Join(in.Path, "libraries", "src", "Version.php"), 32<<10); s != "" {
			ma, mi, pa := firstMatch(reJMajor, s), firstMatch(reJMinor, s), firstMatch(reJPatch, s)
			if ma != "" {
				return ma + "." + mi + "." + pa
			}
		}
		s := readHead(filepath.Join(in.Path, "libraries", "cms", "version", "version.php"), 32<<10)
		if r := firstMatch(reJRelease, s); r != "" {
			return r + "." + firstMatch(reJDev, s)
		}
	case OpenCart:
		for _, f := range []string{"index.php", filepath.Join("admin", "index.php")} {
			if v := firstMatch(reOCVersion, readHead(filepath.Join(in.Path, f), 16<<10)); v != "" {
				return v
			}
		}
	}
	return ""
}

// Plugins lists WordPress plugins (folder plugins and single-file plugins).
func Plugins(wpRoot string) []Component {
	dir := filepath.Join(wpRoot, "wp-content", "plugins")
	entries, _ := os.ReadDir(dir)
	var out []Component
	for _, e := range entries {
		p := filepath.Join(dir, e.Name())
		if e.IsDir() {
			files, _ := os.ReadDir(p)
			for _, f := range files {
				if f.IsDir() || !strings.HasSuffix(f.Name(), ".php") {
					continue
				}
				head := readHead(filepath.Join(p, f.Name()), 8<<10)
				if name := firstMatch(rePluginName, head); name != "" {
					out = append(out, Component{Slug: e.Name(), Name: name, Version: firstMatch(reVersionHdr, head)})
					break
				}
			}
		} else if strings.HasSuffix(e.Name(), ".php") {
			head := readHead(p, 8<<10)
			if name := firstMatch(rePluginName, head); name != "" {
				out = append(out, Component{Slug: strings.TrimSuffix(e.Name(), ".php"), Name: name, Version: firstMatch(reVersionHdr, head)})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Slug < out[j].Slug })
	return out
}

// Themes lists WordPress themes.
func Themes(wpRoot string) []Component {
	dir := filepath.Join(wpRoot, "wp-content", "themes")
	entries, _ := os.ReadDir(dir)
	var out []Component
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		head := readHead(filepath.Join(dir, e.Name(), "style.css"), 8<<10)
		if name := firstMatch(reThemeName, head); name != "" {
			out = append(out, Component{Slug: e.Name(), Name: name, Version: firstMatch(reVersionHdr, head)})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Slug < out[j].Slug })
	return out
}

// MUPlugins lists must-use plugins, a common hiding place for malware.
func MUPlugins(wpRoot string) []string {
	entries, _ := os.ReadDir(filepath.Join(wpRoot, "wp-content", "mu-plugins"))
	var out []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".php") {
			out = append(out, e.Name())
		}
	}
	return out
}

// CompareVersions returns -1, 0, 1 comparing dotted numeric versions.
func CompareVersions(a, b string) int {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y int
		if i < len(pa) {
			x = leadingInt(pa[i])
		}
		if i < len(pb) {
			y = leadingInt(pb[i])
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

func leadingInt(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	return n
}

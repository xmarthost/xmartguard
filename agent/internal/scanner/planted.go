package scanner

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

// A PHP file planted in WordPress core's asset folders. WordPress keeps no
// PHP file in wp-admin/css, wp-admin/images, wp-includes/css or
// wp-includes/images, and no plugin writes there. A dropper copies one
// name into every core folder so that deleting one copy leaves the others
// (business200, 2026-10-26: worksec.php in 42 core folders of one site, no
// finding, because each copy's content passed the content rules).

// coreAssetDirs hold no PHP file in any WordPress release
// (wp-includes/fonts does since 6.5).
var coreAssetDirs = []string{"wp-admin/css", "wp-admin/images", "wp-includes/css", "wp-includes/images"}

// coreDirs are the core folders a dropper fills (counted for the spray).
var coreDirs = []string{"wp-admin", "wp-admin/css", "wp-admin/images", "wp-admin/includes", "wp-admin/js", "wp-admin/maint",
	"wp-admin/network", "wp-admin/user", "wp-includes", "wp-includes/css", "wp-includes/images", "wp-includes/js",
	"wp-includes/fonts", "wp-includes/ID3", "wp-includes/IXR", "wp-includes/Text", "wp-includes/SimplePie",
	"wp-includes/Requests", "wp-includes/PHPMailer", "wp-includes/pomo", "wp-includes/widgets", "wp-includes/blocks",
	"wp-includes/rest-api", "wp-includes/customize", "wp-includes/certificates", "wp-includes/sitemaps",
	"wp-includes/sodium_compat", "wp-includes/theme-compat", "wp-includes/html-api", "wp-includes/block-supports",
	"wp-includes/assets", "wp-includes/l10n", "wp-includes/style-engine", "wp-includes/interactivity-api",
	"wp-includes/php-compat", "wp-includes/block-patterns", "wp-includes/block-bindings"}

// sprayCopies: the same name in this many other core folders, one copy in
// an asset folder, is a dropper (core's own names are never in them).
const sprayCopies = 3

// sprayed remembers the droppers found (site root and file name, with the
// time): the copies are quarantined one by one, and the last ones would no
// longer see enough others.
var sprayed sync.Map

const sprayedFor = 24 * time.Hour

// plantedInCore judges a PHP file that is not an official WordPress file
// by where it is: directly in a core asset folder of a WordPress site it
// is suspicious (the AI scanner looks at it); with copies of its name in
// other core folders it is malware, every copy in every core folder.
func plantedInCore(path string) *Detection {
	var root, rel string
	for _, top := range []string{"/wp-admin/", "/wp-includes/"} {
		if i := strings.LastIndex(path, top); i > 0 {
			root, rel = path[:i], path[i+1:]
			break
		}
	}
	if root == "" {
		return nil
	}
	dir, base := filepath.Dir(rel), filepath.Base(rel)
	asset := slices.Contains(coreAssetDirs, dir)
	if !asset && !slices.Contains(coreDirs, dir) {
		return nil
	}
	key := root + "\x00" + base
	spray := &Detection{CatVirus, "PHP.Planted.WordPressCoreSpray"}
	if t, ok := sprayed.Load(key); ok && time.Since(t.(time.Time)) < sprayedFor {
		return spray
	}
	// Only a name that is in an asset folder counts (four lookups for any
	// other file in core: a site on a WordPress release newer than the
	// known-file list has a thousand of them).
	stat := func(d string) bool {
		st, err := os.Lstat(filepath.Join(root, d, base))
		return err == nil && st.Mode().IsRegular()
	}
	if !asset && !slices.ContainsFunc(coreAssetDirs, stat) {
		return nil
	}
	// A WordPress site (not a folder that happens to be called so).
	if st, err := os.Stat(filepath.Join(root, "wp-includes", "version.php")); err != nil || !st.Mode().IsRegular() {
		return nil
	}
	copies := 0
	for _, d := range coreDirs {
		if d != dir && stat(d) {
			copies++
		}
	}
	if copies >= sprayCopies {
		sprayed.Store(key, time.Now())
		return spray
	}
	if asset {
		return &Detection{CatSuspicious, "PHP.Planted.WordPressCoreAssets"}
	}
	return nil
}

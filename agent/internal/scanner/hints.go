package scanner

import (
	"context"
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/store"
)

// New detection rules reach files written before them (owner, 2026-11-14):
// realtime protection only sees new writes and the daily and weekly sweeps
// only files changed since (attackers set dates back), while a full scan of
// a 1,500-account server is kept for the weekend. So a release with new
// rules starts, right away and at the lowest priority, a sweep of only the
// files those rules (and every evidence set so far) are about: chosen by
// name and place from the directory listing, without reading the others.
// The full scan follows on the next weekend night (see Scheduler).

// DetectionVersion changes with a release whose rules find files earlier
// ones did not (wave 2 of 2026-11-14).
const DetectionVersion = "2026-11-14"

// hintNames: file names of the malware in the evidence sets (2026-10-28 to
// 2026-11-14: cPGuard quarantine, ClickFix, expresswrap, bitepestcontrol,
// mangomela wp-merc, the 2026-11-11 server-wide compromise, halaltech,
// legalcokemdma and wave 2) and the files their rules judge.
var hintNames = map[string]bool{
	// backdoors, droppers and shells
	"data.php": true, "hmhfm.php": true, "01.php": true, "02.php": true, "03.php": true, "04.php": true, "a.php": true, "bots.php": true,
	"l.php": true, "kl.php": true, "g.php": true, "h.php": true, "x.php": true, "css.php": true, "itu.php": true, "zip.php": true,
	"geck.php": true, "plugin-editor.php": true, "sd.php": true, "rum.php": true, "jend.php": true, "bytkl.php": true, "dosya.php": true,
	"hiroshi.php": true, "apalah.php": true, "moddofuns.php": true, "web-dropper.php": true, "visit.php": true, "editusers.php": true,
	"card_admincreator.php": true, "dark_websocket_filemanager.php": true, "tinyfilemanager.php": true, "1.php": true, "gen2.php": true,
	"wp-crrm.php": true, "zenitsu.php": true, "onehatbypass.php": true, "bflow.php": true, "oya.php": true, "alff.php": true, "tnt.php": true,
	"admin.php": true, "plugin.php": true, "wp-actions.php": true, "woocommerce-load.php": true, "woocommerce_inputs.php": true,
	"fhelpers.php": true, "bootstrap.inc.php": true, "setup.php": true, "platform_check.php": true, "service-admin-bootstrap.php": true,
	"cf-captcha-windows.php": true, "cf-security-shield.php": true, "captcha.php": true, "blocker-detector.php": true, "wp-read.php": true,
	"ht.php": true, "maintenance.php": true, "rtl.assets.php": true, "index (9).php": true,
	// files the place rules judge
	".htaccess": true, "wp-load.php": true, "wp-blog-header.php": true, "wp-settings.php": true, "index.php": true, "index.html": true, "index.htm": true,
}

// hintMinSize: names too common to scan every copy of (WordPress's
// "Silence is golden" index.php everywhere): only copies at least this big.
var hintMinSize = map[string]int64{"index.php": 2048, "index.html": 2048, "index.htm": 2048, "admin.php": 1, "plugin.php": 1}

var (
	// Random dropper names (iuwgopufpj46jFM.php, xrgmlaxnv2vjbyWMF.php,
	// ytq7fv184iabavs1F.php), upload names (up_tnpugjplrq-t49HHJFJ0L2Vby85.php),
	// hex names and the per-plugin "wt_fm_<digits>_*.php" dumper.
	reHintName = regexp.MustCompile(`^(?:[a-z0-9]{10,}[A-Z]{1,4}[A-Za-z]{0,3}|up_[a-z]+-[A-Za-z0-9]{12,}|[0-9a-f]{32,64}|wt_fm_\d{6,}_[\w-]+|firewall-[0-9a-f]{6})\.php$`)
	// Places malware was hidden in: any PHP there is looked at.
	hintDirs = map[string]bool{".tmb": true, ".cache": true, ".koality": true, ".local": true, ".well-known": true, "cgi-bin": true,
		"upgrade-temp-backup": true, "uploads": true, "mu-plugins": true, "backuply": true, "lscache": true, "virtualenv": true, "wpfm-private-backups": true}
)

// hintRoots are the folders the sweep walks (tests replace it).
var hintRoots = FullRoots

// HintCandidate reports whether the sweep looks at a file (from its listing;
// size is read only for the common names).
func HintCandidate(path string, d fs.DirEntry) bool {
	name := d.Name()
	low := strings.ToLower(name)
	if hintNames[low] {
		if min, ok := hintMinSize[low]; ok {
			info, err := d.Info()
			return err == nil && info.Size() >= min
		}
		return true
	}
	if reHintName.MatchString(name) {
		return true
	}
	if !isPHP(name) {
		return false
	}
	// Dated back: changed lately (ctime) but showing an old date (mtime).
	// touch() sets the date shown, not the change time: the injector of the
	// RAHASIA gate and the wave-2 tools set dates back by hundreds of days.
	if info, err := d.Info(); err == nil && backdated(info, time.Now()) {
		return true
	}
	dir := filepath.Dir(path)
	// A PHP file right in wp-content (geck.php, plugin-editor.php).
	if filepath.Base(dir) == "wp-content" {
		return true
	}
	for p := dir; p != "/" && p != "."; p = filepath.Dir(p) {
		if hintDirs[filepath.Base(p)] {
			return true
		}
		if strings.Count(p, "/") <= 2 {
			break
		}
	}
	return false
}

// backdated: the file's inode changed within 30 days, more than two days
// after the date it shows.
func backdated(info fs.FileInfo, now time.Time) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	ctime := time.Unix(int64(st.Ctim.Sec), int64(st.Ctim.Nsec))
	return now.Sub(ctime) < 30*24*time.Hour && ctime.Sub(info.ModTime()) > 48*time.Hour
}

// HintSweep checks the candidate files of every account at the lowest
// priority and records what the rules find, as a scan ("rules") in the
// list. It returns the files checked and found.
func (s *Scanner) HintSweep(ctx context.Context) (checked, found int64) {
	lowPriorityThread()
	res, err := s.DB.Exec(`INSERT INTO scans (kind, target, status, initiator, started_at) VALUES ('rules', ?, 'running', 'scheduler', ?)`,
		"files the new detection rules are about ("+DetectionVersion+")", store.Now())
	var id int64
	if err == nil {
		id, _ = res.LastInsertId()
	}
	qdir := QuarantineDir()
	cfg := s.Settings.Get().Scanner
	last := time.Now()
	for _, root := range hintRoots() {
		if ctx.Err() != nil {
			break
		}
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if path != root && (skipAnywhere[d.Name()] || (filepath.Dir(path) == root && skipInHome[d.Name()] && d.Name() != ".cache") || path == qdir || systemPath(path)) {
					return filepath.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() || !HintCandidate(path, d) {
				return nil
			}
			info, err := d.Info()
			if err != nil || info.Size() > int64(cfg.MaxFileSizeMB)<<20 {
				return nil
			}
			checked++
			det, _ := s.CheckFile(path, info, cfg)
			if det != nil {
				if _, err := s.Record(id, "manual", path, info, *det); err == nil {
					found++
				}
			}
			if time.Since(last) > 2*time.Second && id > 0 {
				last = time.Now()
				_, _ = s.DB.Exec(`UPDATE scans SET files = ?, infected = ?, current = ? WHERE id = ?`, checked, found, path, id)
			}
			// Gentle: a short pause per file keeps the disk free for sites.
			time.Sleep(2 * time.Millisecond)
			return nil
		})
	}
	if id > 0 {
		status := "completed"
		if ctx.Err() != nil {
			status = "stopped"
		}
		_, _ = s.DB.Exec(`UPDATE scans SET status = ?, files = ?, infected = ?, current = '', finished_at = ? WHERE id = ?`, status, checked, found, store.Now(), id)
	}
	return checked, found
}

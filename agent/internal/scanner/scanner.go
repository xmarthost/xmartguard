// Package scanner implements XMart Guard's malware scanner: manual, scheduled
// and realtime scans, detection with built-in signatures (plus ClamAV when the
// server has it), and a reversible quarantine.
package scanner

import (
	"bufio"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/settings"
	"github.com/xmarthost/xmartguard/agent/internal/store"
)

// Finding is one detection.
type Finding struct {
	ID        int64  `json:"id"`
	ScanID    int64  `json:"scan_id"`
	Source    string `json:"source"`
	Path      string `json:"path"`
	Owner     string `json:"owner"`
	Category  string `json:"category"`
	Signature string `json:"signature"`
	SHA256    string `json:"sha256"`
	Size      int64  `json:"size"`
	Status    string `json:"status"`
	CreatedAt int64  `json:"created_at"`
	UpdatedAt int64  `json:"updated_at"`
}

// Scan is one scan job.
type Scan struct {
	ID         int64  `json:"id"`
	Kind       string `json:"kind"`
	Target     string `json:"target"`
	Status     string `json:"status"`
	Files      int64  `json:"files"`
	Infected   int64  `json:"infected"`
	Initiator  string `json:"initiator"`
	StartedAt  int64  `json:"started_at"`
	FinishedAt int64  `json:"finished_at"`
	Error      string `json:"error"`
}

// Scanner owns scan jobs and the quarantine.
type Scanner struct {
	DB       *sql.DB
	Settings *settings.Store
	Log      *slog.Logger
	// OnFinding is called for every new detection (notifications).
	OnFinding func(Finding)

	mu      sync.Mutex
	cancels map[int64]context.CancelFunc
	sem     chan struct{}
	users   map[uint32]string
}

// New creates a scanner and marks scans interrupted by a restart as failed.
func New(db *sql.DB, st *settings.Store, log *slog.Logger) *Scanner {
	s := &Scanner{DB: db, Settings: st, Log: log, cancels: map[int64]context.CancelFunc{}, sem: make(chan struct{}, 1), users: map[uint32]string{}}
	_, _ = db.Exec(`UPDATE scans SET status = 'failed', error = 'interrupted by agent restart', finished_at = ? WHERE status IN ('queued','running')`, store.Now())
	return s
}

// QuarantineDir holds quarantined files.
func QuarantineDir() string { return filepath.Join(store.StateDir(), "quarantine") }

// forbidden are never scanned or acted on.
var forbidden = []string{"/proc", "/sys", "/dev", "/run", "/boot", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc"}

// skipAnywhere are skipped at any depth: bind mounts and caches.
var skipAnywhere = map[string]bool{"virtfs": true, ".cagefs": true, ".trash": true}

// skipInHome are skipped directly inside a home directory (mailboxes, panel data).
var skipInHome = map[string]bool{"mail": true, ".cpanel": true, "etc": true, "logs": true, "tmp": false, ".cache": true, ".spamassassin": true}

func underAny(p string, prefixes []string) bool {
	for _, f := range prefixes {
		if p == f || strings.HasPrefix(p, f+"/") {
			return true
		}
	}
	return false
}

// ValidateTarget checks a user-supplied scan path.
func ValidateTarget(p string) (string, error) {
	if !filepath.IsAbs(p) {
		return "", errors.New("path must be absolute")
	}
	p = filepath.Clean(p)
	if p == "/" {
		return "", errors.New("scanning / is not allowed; use a Full scan")
	}
	if underAny(p, forbidden) || underAny(p, []string{store.StateDir()}) {
		return "", fmt.Errorf("%s is a system path and cannot be scanned", p)
	}
	st, err := os.Stat(p)
	if err != nil {
		return "", fmt.Errorf("path not found: %s", p)
	}
	if !st.IsDir() && !st.Mode().IsRegular() {
		return "", errors.New("path must be a directory or a regular file")
	}
	return p, nil
}

// HostingUser is an account whose files are scanned.
type HostingUser struct {
	Name    string `json:"name"`
	Home    string `json:"home"`
	WebRoot string `json:"web_root"`
}

// Users lists hosting accounts: cPanel users when present, otherwise regular
// users (uid >= 1000) with a home directory.
func Users() []HostingUser {
	cp := map[string]bool{}
	if entries, err := os.ReadDir("/var/cpanel/users"); err == nil {
		for _, e := range entries {
			if !e.IsDir() && !strings.HasPrefix(e.Name(), ".") && e.Name() != "system" {
				cp[e.Name()] = true
			}
		}
	}
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []HostingUser
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.Split(sc.Text(), ":")
		if len(parts) < 7 {
			continue
		}
		uid, _ := strconv.Atoi(parts[2])
		name, home := parts[0], parts[5]
		if len(cp) > 0 {
			if !cp[name] {
				continue
			}
		} else if uid < 1000 || uid >= 60000 || !strings.HasPrefix(home, "/home") {
			continue
		}
		if st, err := os.Stat(home); err != nil || !st.IsDir() {
			continue
		}
		web := filepath.Join(home, "public_html")
		if _, err := os.Stat(web); err != nil {
			web = ""
		}
		out = append(out, HostingUser{Name: name, Home: home, WebRoot: web})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// FullRoots are the directories covered by a full scan.
func FullRoots() []string {
	var roots []string
	for _, u := range Users() {
		roots = append(roots, u.Home)
	}
	for _, p := range []string{"/var/www", "/tmp", "/var/tmp", "/dev/shm"} {
		if st, err := os.Stat(p); err == nil && st.IsDir() {
			roots = append(roots, p)
		}
	}
	return roots
}

// WebRoots are the document roots used by quick scans and realtime protection.
func WebRoots() []string {
	var roots []string
	for _, u := range Users() {
		if u.WebRoot != "" {
			roots = append(roots, u.WebRoot)
		}
	}
	if st, err := os.Stat("/var/www/html"); err == nil && st.IsDir() {
		roots = append(roots, "/var/www/html")
	}
	return roots
}

func (s *Scanner) owner(uid uint32) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n, ok := s.users[uid]; ok {
		return n
	}
	n := strconv.FormatUint(uint64(uid), 10)
	if u, err := user.LookupId(n); err == nil {
		n = u.Username
	}
	s.users[uid] = n
	return n
}

// Detection is the result of checking one file.
type Detection struct {
	Category  string
	Signature string
}

// CheckFile applies whitelist/blacklist rules and signatures to one file.
func (s *Scanner) CheckFile(path string, info fs.FileInfo, cfg settings.Scanner) (*Detection, error) {
	if !info.Mode().IsRegular() || info.Size() == 0 {
		return nil, nil
	}
	name := filepath.Base(path)
	for _, w := range cfg.WhitelistPaths {
		if w == name || w == path || (strings.HasPrefix(w, "/") && strings.HasPrefix(path, strings.TrimRight(w, "/")+"/")) {
			return nil, nil
		}
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		owner := s.owner(st.Uid)
		for _, u := range cfg.WhitelistUsers {
			if u == owner {
				return nil, nil
			}
		}
	}
	for _, b := range cfg.BlacklistNames {
		if b == name {
			return &Detection{CatVirus, "XG-BLACKLIST.FileName"}, nil
		}
	}
	ext := extOf(name)
	if ScriptExts[ext] {
		max := int64(cfg.MaxFileSizeMB) << 20
		if info.Size() > max {
			return nil, nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if ext == "" && IsELF(content) {
			return binaryCheck(path)
		}
		if r := Match(ext, content); r != nil {
			return &Detection{r.Category, r.Name}, nil
		}
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	head := make([]byte, 4)
	n, _ := io.ReadFull(f, head)
	f.Close()
	if IsELF(head[:n]) {
		return binaryCheck(path)
	}
	return nil, nil
}

// binaryCheck flags executables inside web-accessible directories.
func binaryCheck(path string) (*Detection, error) {
	for _, part := range strings.Split(path, "/") {
		if part == "public_html" || part == "www" || part == "html" || part == "tmp" || part == "shm" {
			return &Detection{CatBinary, "Binary.ELF.InWebOrTempDir"}, nil
		}
	}
	return nil, nil
}

func sha256File(path string) string {
	f, err := os.Open(path)
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

// Record stores a detection and applies the configured action.
func (s *Scanner) Record(scanID int64, source, path string, info fs.FileInfo, d Detection) (Finding, error) {
	now := store.Now()
	f := Finding{ScanID: scanID, Source: source, Path: path, Category: d.Category, Signature: d.Signature,
		SHA256: sha256File(path), Size: info.Size(), Status: "detected", CreatedAt: now, UpdatedAt: now}
	uid, gid := -1, -1
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		f.Owner = s.owner(st.Uid)
		uid, gid = int(st.Uid), int(st.Gid)
	}
	// Do not re-report an unchanged file that is already tracked.
	var existing int64
	if err := s.DB.QueryRow(`SELECT id FROM findings WHERE path = ? AND sha256 = ? AND status IN ('detected','quarantined','disabled','ignored') LIMIT 1`, path, f.SHA256).Scan(&existing); err == nil {
		return Finding{}, errExists
	}
	res, err := s.DB.Exec(`INSERT INTO findings (scan_id, source, path, owner, category, signature, sha256, size, status, created_at, updated_at, orig_mode, orig_uid, orig_gid)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, scanID, source, path, f.Owner, f.Category, f.Signature, f.SHA256, f.Size, f.Status, now, now, int(info.Mode().Perm()), uid, gid)
	if err != nil {
		return f, err
	}
	f.ID, _ = res.LastInsertId()
	cfg := s.Settings.Get().Scanner
	action := cfg.VirusAction
	switch d.Category {
	case CatSuspicious:
		action = cfg.SuspiciousAction
	case CatBinary:
		action = cfg.BinaryAction
	}
	switch action {
	case settings.ActionQuarantine:
		if err := s.Quarantine(f.ID); err != nil {
			s.Log.Warn("quarantine failed", "path", path, "err", err)
		} else {
			f.Status = "quarantined"
		}
	case settings.ActionDisable:
		if err := s.Disable(f.ID); err != nil {
			s.Log.Warn("disable failed", "path", path, "err", err)
		} else {
			f.Status = "disabled"
		}
	}
	s.Log.Info("detection", "path", path, "signature", d.Signature, "category", d.Category, "status", f.Status)
	if s.OnFinding != nil {
		s.OnFinding(f)
	}
	return f, nil
}

var errExists = errors.New("already recorded")

// Start queues a scan and returns its ID. kind: full | quick | path | daily | weekly.
func (s *Scanner) Start(kind, target, initiator string) (int64, error) {
	var roots []string
	var since time.Time
	switch kind {
	case "full":
		roots = FullRoots()
		target = "all accounts"
	case "daily", "weekly":
		roots = FullRoots()
		days := 1
		if kind == "weekly" {
			days = 7
		}
		since = time.Now().AddDate(0, 0, -days)
		target = fmt.Sprintf("files changed in the last %d day(s)", days)
	case "quick", "path":
		p, err := ValidateTarget(target)
		if err != nil {
			return 0, err
		}
		target, roots = p, []string{p}
	default:
		return 0, fmt.Errorf("unknown scan type %q", kind)
	}
	if len(roots) == 0 {
		return 0, errors.New("no hosting accounts found to scan")
	}
	res, err := s.DB.Exec(`INSERT INTO scans (kind, target, status, initiator, started_at) VALUES (?,?,?,?,?)`, kind, target, "queued", initiator, store.Now())
	if err != nil {
		return 0, err
	}
	id, _ := res.LastInsertId()
	ctx, cancel := context.WithCancel(context.Background())
	s.mu.Lock()
	s.cancels[id] = cancel
	s.mu.Unlock()
	go s.run(ctx, id, roots, since)
	return id, nil
}

// Stop cancels a queued or running scan.
func (s *Scanner) Stop(id int64) error {
	s.mu.Lock()
	cancel, ok := s.cancels[id]
	s.mu.Unlock()
	if !ok {
		return errors.New("scan is not running")
	}
	cancel()
	return nil
}

func (s *Scanner) run(ctx context.Context, id int64, roots []string, since time.Time) {
	defer func() {
		s.mu.Lock()
		delete(s.cancels, id)
		s.mu.Unlock()
	}()
	select {
	case s.sem <- struct{}{}:
	case <-ctx.Done():
		_, _ = s.DB.Exec(`UPDATE scans SET status='stopped', finished_at=? WHERE id=?`, store.Now(), id)
		return
	}
	defer func() { <-s.sem }()
	_, _ = s.DB.Exec(`UPDATE scans SET status='running', started_at=? WHERE id=?`, store.Now(), id)

	cfg := s.Settings.Get().Scanner
	clam := newClam(cfg.UseClamAV)
	var files, infected int64
	var batch []string
	flushClam := func() {
		for path, sig := range clam.scan(batch) {
			info, err := os.Lstat(path)
			if err != nil {
				continue
			}
			if _, err := s.Record(id, "manual", path, info, Detection{CatVirus, "ClamAV." + sig}); err == nil {
				infected++
			}
		}
		batch = batch[:0]
	}
	qdir := QuarantineDir()
	var walkErr error
	for _, root := range roots {
		walkErr = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err != nil {
				return nil // unreadable entry: skip
			}
			if d.IsDir() {
				if path != root && (skipAnywhere[d.Name()] || (filepath.Dir(path) == root && skipInHome[d.Name()]) || path == qdir || underAny(path, forbidden)) {
					return filepath.SkipDir
				}
				return nil
			}
			if d.Type()&fs.ModeSymlink != 0 || !d.Type().IsRegular() {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			if !since.IsZero() && info.ModTime().Before(since) {
				return nil
			}
			files++
			if files%250 == 0 {
				_, _ = s.DB.Exec(`UPDATE scans SET files=?, infected=? WHERE id=?`, files, infected, id)
			}
			det, err := s.CheckFile(path, info, cfg)
			if err != nil || det == nil {
				if clam.ok && ScriptExts[extOf(d.Name())] && info.Size() <= int64(cfg.MaxFileSizeMB)<<20 {
					batch = append(batch, path)
					if len(batch) >= 200 {
						flushClam()
					}
				}
				return nil
			}
			if _, err := s.Record(id, "manual", path, info, *det); err == nil {
				infected++
			}
			return nil
		})
		if walkErr != nil {
			break
		}
	}
	if ctx.Err() == nil {
		flushClam()
	}
	status, errText := "completed", ""
	if errors.Is(walkErr, context.Canceled) {
		status = "stopped"
	} else if walkErr != nil {
		status, errText = "failed", walkErr.Error()
	}
	_, _ = s.DB.Exec(`UPDATE scans SET status=?, files=?, infected=?, finished_at=?, error=? WHERE id=?`, status, files, infected, store.Now(), errText, id)
	s.Log.Info("scan finished", "id", id, "status", status, "files", files, "infected", infected)
}

// ScanFile checks a single file (realtime protection).
func (s *Scanner) ScanFile(path string) {
	cfg := s.Settings.Get().Scanner
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return
	}
	det, err := s.CheckFile(path, info, cfg)
	if err != nil || det == nil {
		return
	}
	_, _ = s.Record(0, "realtime", path, info, *det)
}

// ListScans returns recent scans, newest first.
func (s *Scanner) ListScans(limit int) ([]Scan, error) {
	rows, err := s.DB.Query(`SELECT id, kind, target, status, files, infected, initiator, started_at, finished_at, error FROM scans ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Scan{}
	for rows.Next() {
		var sc Scan
		if err := rows.Scan(&sc.ID, &sc.Kind, &sc.Target, &sc.Status, &sc.Files, &sc.Infected, &sc.Initiator, &sc.StartedAt, &sc.FinishedAt, &sc.Error); err != nil {
			return nil, err
		}
		out = append(out, sc)
	}
	return out, rows.Err()
}

// DeleteScan removes a finished scan record (its findings are kept).
func (s *Scanner) DeleteScan(id int64) error {
	res, err := s.DB.Exec(`DELETE FROM scans WHERE id = ? AND status NOT IN ('queued','running')`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("scan not found or still running")
	}
	return nil
}

// FindingFilter narrows ListFindings.
type FindingFilter struct {
	ScanID   int64  `json:"scan_id"`
	Category string `json:"category"`
	Status   string `json:"status"`
	Query    string `json:"q"`
	Limit    int    `json:"limit"`
	Offset   int    `json:"offset"`
}

// ListFindings returns detections, newest first, with the total count.
func (s *Scanner) ListFindings(f FindingFilter) ([]Finding, int, error) {
	where := []string{"1=1"}
	args := []any{}
	if f.ScanID > 0 {
		where, args = append(where, "scan_id = ?"), append(args, f.ScanID)
	}
	if f.Category != "" {
		where, args = append(where, "category = ?"), append(args, f.Category)
	}
	if f.Status != "" {
		where, args = append(where, "status = ?"), append(args, f.Status)
	}
	if f.Query != "" {
		where, args = append(where, "(path LIKE ? OR signature LIKE ? OR owner LIKE ?)"), append(args, "%"+f.Query+"%", "%"+f.Query+"%", "%"+f.Query+"%")
	}
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 50
	}
	cond := strings.Join(where, " AND ")
	var total int
	if err := s.DB.QueryRow(`SELECT count(*) FROM findings WHERE `+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.DB.Query(`SELECT id, scan_id, source, path, owner, category, signature, sha256, size, status, created_at, updated_at
		FROM findings WHERE `+cond+` ORDER BY id DESC LIMIT ? OFFSET ?`, append(args, f.Limit, f.Offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []Finding{}
	for rows.Next() {
		var x Finding
		if err := rows.Scan(&x.ID, &x.ScanID, &x.Source, &x.Path, &x.Owner, &x.Category, &x.Signature, &x.SHA256, &x.Size, &x.Status, &x.CreatedAt, &x.UpdatedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, x)
	}
	return out, total, rows.Err()
}

// Stats summarises scanner activity for dashboards.
type Stats struct {
	Threats30d    int   `json:"threats_30d"`
	ThreatsTotal  int   `json:"threats_total"`
	Quarantined   int   `json:"quarantined"`
	OpenFindings  int   `json:"open_findings"`
	LastScanAt    int64 `json:"last_scan_at"`
	RealtimeWatch int   `json:"realtime_watches"`
}

// Stats returns dashboard counters.
func (s *Scanner) Stats() Stats {
	var st Stats
	since := store.Now() - 30*86400
	_ = s.DB.QueryRow(`SELECT count(*) FROM findings WHERE created_at >= ?`, since).Scan(&st.Threats30d)
	_ = s.DB.QueryRow(`SELECT count(*) FROM findings`).Scan(&st.ThreatsTotal)
	_ = s.DB.QueryRow(`SELECT count(*) FROM findings WHERE status = 'quarantined'`).Scan(&st.Quarantined)
	_ = s.DB.QueryRow(`SELECT count(*) FROM findings WHERE status IN ('detected','disabled')`).Scan(&st.OpenFindings)
	_ = s.DB.QueryRow(`SELECT coalesce(max(finished_at),0) FROM scans WHERE status='completed'`).Scan(&st.LastScanAt)
	return st
}

// DailyCounts returns detections per day for the last n days (oldest first).
func (s *Scanner) DailyCounts(days int) []map[string]any {
	out := make([]map[string]any, 0, days)
	start := time.Now().Truncate(24*time.Hour).AddDate(0, 0, -(days - 1))
	counts := map[string]map[string]int{}
	rows, err := s.DB.Query(`SELECT created_at, category FROM findings WHERE created_at >= ?`, start.Unix())
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var ts int64
			var cat string
			if rows.Scan(&ts, &cat) == nil {
				day := time.Unix(ts, 0).UTC().Format("2006-01-02")
				if counts[day] == nil {
					counts[day] = map[string]int{}
				}
				counts[day][cat]++
			}
		}
	}
	for i := 0; i < days; i++ {
		day := start.AddDate(0, 0, i).UTC().Format("2006-01-02")
		c := counts[day]
		out = append(out, map[string]any{"day": day, "virus": c[CatVirus], "suspicious": c[CatSuspicious], "binary": c[CatBinary]})
	}
	return out
}

// ---------------------------------------------------------------- ClamAV

type clamAV struct {
	ok  bool
	bin string
}

// newClam enables ClamAV when clamdscan (preferred) or clamscan exists.
func newClam(enabled bool) *clamAV {
	if !enabled {
		return &clamAV{}
	}
	for _, p := range []string{"/usr/local/cpanel/3rdparty/bin/clamdscan", "/usr/bin/clamdscan", "/usr/local/bin/clamdscan"} {
		if _, err := os.Stat(p); err == nil {
			return &clamAV{ok: true, bin: p}
		}
	}
	return &clamAV{}
}

// ClamAvailable reports the ClamAV binary in use, if any.
func ClamAvailable() string { return newClam(true).bin }

// scan runs clamdscan over a batch and returns path -> signature.
func (c *clamAV) scan(paths []string) map[string]string {
	out := map[string]string{}
	if !c.ok || len(paths) == 0 {
		return out
	}
	list, err := os.CreateTemp(store.StateDir(), "clamlist-*")
	if err != nil {
		return out
	}
	defer os.Remove(list.Name())
	_, _ = list.WriteString(strings.Join(paths, "\n") + "\n")
	list.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, c.bin, "--no-summary", "--infected", "--fdpass", "--file-list="+list.Name())
	raw, err := cmd.Output()
	// Exit code 1 means "virus found"; 2 means an error (e.g. clamd not running).
	var ee *exec.ExitError
	if err != nil && (!errors.As(err, &ee) || ee.ExitCode() != 1) {
		c.ok = false
		return out
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasSuffix(line, " FOUND") {
			continue
		}
		i := strings.LastIndex(line, ": ")
		if i < 0 {
			continue
		}
		out[line[:i]] = strings.TrimSuffix(line[i+2:], " FOUND")
	}
	return out
}

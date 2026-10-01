package scanner

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// MaxWatches caps inotify watches so huge servers stay responsive; 0 sizes
// it from the server's memory (about 1 KB of kernel memory per watch, at
// most 2% of RAM, between 500,000 and 1,000,000) and from the kernel's
// max_user_watches when that could not be raised.
var MaxWatches = 0

// WatchReserve watches are kept free at start for folders made later (new
// upload folders, extracted archives); -1 keeps 5% of the limit.
var WatchReserve = -1

// SweepEvery is how often folders beyond the watch limit are checked for
// new files, so no folder is left unprotected on very large servers.
var SweepEvery = 5 * time.Minute

func maxWatches() int {
	if MaxWatches > 0 {
		return MaxWatches
	}
	n := 500000
	if raw, err := os.ReadFile("/proc/meminfo"); err == nil {
		for _, l := range strings.Split(string(raw), "\n") {
			if f := strings.Fields(l); len(f) >= 2 && f[0] == "MemTotal:" {
				kb, _ := strconv.Atoi(f[1])
				n = max(n, min(kb*2/100, 1000000)) // kB / 1 KB per watch
			}
		}
	}
	// Other programs (cPanel, LiteSpeed, backups) use watches too.
	if raw, err := os.ReadFile("/proc/sys/fs/inotify/max_user_watches"); err == nil {
		if k, _ := strconv.Atoi(strings.TrimSpace(string(raw))); k > 0 {
			n = min(n, max(k-50000, k/2))
		}
	}
	return n
}

// RealtimeWorkers scan changed files in parallel, so reading events never
// waits for a scan (a stalled reader loses events when the queue fills up).
var RealtimeWorkers = 4

const watchMask = unix.IN_CLOSE_WRITE | unix.IN_MOVED_TO | unix.IN_CREATE | unix.IN_DELETE_SELF | unix.IN_ONLYDIR

// Realtime watches every hosting account (the whole home directory, not
// only public_html: addon domains, uploads and extracted archives live
// anywhere in it) plus /tmp, /var/tmp and /dev/shm, and scans files as soon
// as they are written.
type Realtime struct {
	S *Scanner
	// Roots overrides the watched directories (tests).
	Roots func() []string

	mu      sync.Mutex
	fd      int
	dirs    map[int]string
	byPath  map[string]int
	pending map[string]time.Time
	watches int
	homes   map[string]bool
	limit   int
	setting atomic.Bool // the watches are still being set up
	// unwatched are folders beyond the watch limit (each with everything
	// below it); they are swept for new files every SweepEvery.
	unwatched map[string]bool
	lastSweep time.Time
	sweeping  atomic.Bool
	work      chan string
	scanned   atomic.Int64
	overflow  atomic.Int64
	events    atomic.Int64
	swept     atomic.Int64 // files looked at by sweeps
	sweepTook atomic.Int64 // nanoseconds the last sweep took
	active    atomic.Bool
	lastErr   atomic.Value // string
}

// Health reports whether inotify watching is running and, if not, why.
func (r *Realtime) Health() (active bool, err string) {
	e, _ := r.lastErr.Load().(string)
	return r.active.Load(), e
}

// Watches returns the number of active directory watches.
func (r *Realtime) Watches() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.watches
}

// SettingUp reports that the folders are still being watched (on servers
// with millions of folders this takes minutes; new files are scanned
// meanwhile in the folders watched so far).
func (r *Realtime) SettingUp() bool { return r.setting.Load() }

// Unwatched is the number of folders left to the periodic sweep because
// the watch limit was reached.
func (r *Realtime) Unwatched() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.unwatched)
}

// Scanned is the number of files the realtime scanner checked since start.
func (r *Realtime) Scanned() int64 { return r.scanned.Load() }

// RealtimeStats are counters for the agent's CPU profile.
type RealtimeStats struct {
	Watches   int     `json:"watches"`
	Unwatched int     `json:"unwatched_folders"`
	Events    int64   `json:"events"`
	Scanned   int64   `json:"files_scanned"`
	Swept     int64   `json:"files_swept"`
	SweepSecs float64 `json:"last_sweep_seconds"`
}

// Stats returns the counters (totals since start).
func (r *Realtime) Stats() RealtimeStats {
	return RealtimeStats{
		Watches: r.Watches(), Unwatched: r.Unwatched(),
		Events: r.events.Load(), Scanned: r.scanned.Load(), Swept: r.swept.Load(),
		SweepSecs: float64(r.sweepTook.Load()/1e7) / 100,
	}
}

// ensureLimits raises the inotify limits (runtime only) when too low.
func ensureLimits() {
	for p, want := range map[string]int{
		"/proc/sys/fs/inotify/max_user_watches":  MaxWatches + 100000,
		"/proc/sys/fs/inotify/max_queued_events": 1 << 20,
	} {
		raw, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		cur, _ := strconv.Atoi(strings.TrimSpace(string(raw)))
		if cur < want {
			_ = os.WriteFile(p, []byte(strconv.Itoa(want)), 0o644)
		}
	}
}

func (r *Realtime) roots() []string {
	if r.Roots != nil {
		return r.Roots()
	}
	return FullRoots()
}

// RootsRefresh is how often new hosting accounts are looked for.
var RootsRefresh = time.Minute

// addNewRoots watches hosting accounts created since the last look. Their
// files are scanned too: a new account is often filled at once (a
// WordPress install), before any watch on it exists.
func (r *Realtime) addNewRoots() {
	homes := map[string]bool{}
	if r.Roots == nil {
		for _, u := range Users() {
			homes[u.Home] = true
		}
	}
	r.mu.Lock()
	for h := range homes {
		r.homes[h] = true
	}
	r.mu.Unlock()
	for _, root := range r.roots() {
		r.mu.Lock()
		_, known := r.byPath[root]
		r.mu.Unlock()
		if !known {
			r.addTree(root, true)
		}
	}
}

// Run watches until ctx ends. New accounts are picked up within
// RootsRefresh; enable/disable follows the scanner settings.
func (r *Realtime) Run(ctx context.Context) {
	ensureLimits()
	for ctx.Err() == nil {
		if !r.S.Settings.Get().Scanner.Enabled || !r.S.Settings.Get().Scanner.Realtime {
			select {
			case <-ctx.Done():
				return
			case <-time.After(30 * time.Second):
				continue
			}
		}
		r.session(ctx)
	}
}

func (r *Realtime) session(ctx context.Context) {
	// Events are read from the first watch on: setting up every watch of a
	// very large server takes minutes and must not keep the scanner idle.
	if err := r.init(nil); err != nil {
		r.lastErr.Store(err.Error())
		r.S.Log.Warn("realtime scanning unavailable", "err", err)
		select {
		case <-ctx.Done():
		case <-time.After(10 * time.Minute):
		}
		return
	}
	r.lastErr.Store("")
	r.active.Store(true)
	sctx, stop := context.WithCancel(ctx)
	r.setting.Store(true)
	go func() {
		defer r.setting.Store(false)
		// Walking millions of folders after a restart: lowest priority.
		lowPriorityThread()
		start := time.Now()
		r.addLevelsCtx(sctx, r.roots())
		if sctx.Err() == nil {
			r.S.Log.Info("realtime scanning active", "watches", r.Watches(), "swept_folders", r.Unwatched(), "setup", time.Since(start).Round(time.Second).String())
		}
	}()
	r.loop(ctx)
	stop()
	r.active.Store(false)
}

// init opens an inotify instance and watches the given roots recursively.
func (r *Realtime) init(roots []string) error {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return err
	}
	homes := map[string]bool{}
	for _, u := range Users() {
		homes[u.Home] = true
	}
	r.mu.Lock()
	r.fd, r.dirs, r.byPath, r.pending, r.watches, r.homes = fd, map[int]string{}, map[string]int{}, map[string]time.Time{}, 0, homes
	r.limit, r.unwatched, r.lastSweep = maxWatches(), map[string]bool{}, time.Now()
	r.work = make(chan string, 20000)
	r.mu.Unlock()
	r.addLevels(roots)
	return nil
}

// addLevels watches the roots breadth first: every account's top folders
// (where File Manager uploads and new folders land) are watched before any
// deep folder, so the watch limit only ever leaves deep folders to the sweep.
func (r *Realtime) addLevels(roots []string) { r.addLevelsCtx(context.Background(), roots) }

func (r *Realtime) addLevelsCtx(ctx context.Context, roots []string) {
	level := append([]string(nil), roots...)
	reserve := WatchReserve
	if reserve < 0 {
		r.mu.Lock()
		reserve = r.limit / 20
		r.mu.Unlock()
	}
	for len(level) > 0 {
		var next []string
		for i, dir := range level {
			if ctx.Err() != nil {
				return
			}
			if !r.addWatchKeeping(dir, reserve) {
				r.leave(level[i:]...)
				r.leave(next...)
				return
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				continue
			}
			for _, e := range entries {
				if !e.IsDir() {
					continue
				}
				p := filepath.Join(dir, e.Name())
				if !r.skip(p, e.Name()) {
					next = append(next, p)
				}
			}
		}
		level = next
	}
}

// leave hands folders to the periodic sweep.
func (r *Realtime) leave(dirs ...string) {
	r.mu.Lock()
	for _, d := range dirs {
		r.unwatched[d] = true
	}
	r.mu.Unlock()
}

// sweep scans files changed since the last sweep in the folders beyond the
// watch limit, and watches them when watches became free.
func (r *Realtime) sweep() {
	if !r.sweeping.CompareAndSwap(false, true) {
		return
	}
	defer r.sweeping.Store(false)
	// Statting every file of the folders beyond the limit is background
	// work: lowest priority, and the next sweep waits 20 times as long as
	// this one took (at most 5% of one core on servers with millions of
	// files).
	lowPriorityThread()
	t0 := time.Now()
	defer func() { r.sweepTook.Store(int64(time.Since(t0))) }()
	r.mu.Lock()
	since := r.lastSweep
	r.lastSweep = time.Now()
	dirs := make([]string, 0, len(r.unwatched))
	for d := range r.unwatched {
		dirs = append(dirs, d)
	}
	r.mu.Unlock()
	for _, root := range dirs {
		if _, err := os.Stat(root); err != nil {
			r.mu.Lock()
			delete(r.unwatched, root)
			r.mu.Unlock()
			continue
		}
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if path != root && r.skip(path, d.Name()) {
					return filepath.SkipDir
				}
				return nil
			}
			if info, err := d.Info(); err == nil && info.Mode().IsRegular() && !info.ModTime().Before(since.Add(-time.Minute)) {
				r.queue(path)
			}
			return nil
		})
		r.mu.Lock()
		free := r.watches < r.limit-1000
		r.mu.Unlock()
		if free {
			r.mu.Lock()
			delete(r.unwatched, root)
			r.mu.Unlock()
			r.addTree(root, false)
		}
	}
}

// loop processes events until ctx ends or realtime is switched off.
func (r *Realtime) loop(ctx context.Context) {
	fd := r.fd
	wctx, stopWorkers := context.WithCancel(ctx)
	var wg sync.WaitGroup
	for i := 0; i < max(1, RealtimeWorkers); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Checking new files waits for the websites: lowest CPU and
			// disk priority.
			lowPriorityThread()
			for {
				select {
				case <-wctx.Done():
					return
				case p := <-r.work:
					r.S.ScanFile(p)
					r.scanned.Add(1)
				}
			}
		}()
	}
	defer func() {
		stopWorkers()
		wg.Wait()
		unix.Close(fd)
		r.mu.Lock()
		r.watches = 0
		r.mu.Unlock()
	}()
	refresh := time.NewTicker(RootsRefresh)
	defer refresh.Stop()
	sweep := time.NewTicker(SweepEvery)
	defer sweep.Stop()
	buf := make([]byte, 256*1024)
	lastFlush := time.Now()
	pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	for {
		if ctx.Err() != nil {
			return
		}
		select {
		case <-refresh.C:
			cfg := r.S.Settings.Get().Scanner
			if !cfg.Enabled || !cfg.Realtime {
				return
			}
			r.addNewRoots()
		case <-sweep.C:
			if r.Unwatched() > 0 && r.sweepDue() {
				go r.sweep()
			}
		default:
		}
		// Wait up to 200 ms for events, then read everything queued.
		if n, _ := unix.Poll(pfd, 200); n > 0 {
			for {
				n, err := unix.Read(fd, buf)
				if err != nil || n <= 0 {
					break
				}
				r.handle(buf[:n])
			}
		}
		if time.Since(lastFlush) >= 250*time.Millisecond {
			r.flushPending()
			lastFlush = time.Now()
		}
	}
}

// sweepDue spaces sweeps 20 times their duration apart, SweepEvery at least.
func (r *Realtime) sweepDue() bool {
	r.mu.Lock()
	last := r.lastSweep
	r.mu.Unlock()
	gap := max(SweepEvery, 20*time.Duration(r.sweepTook.Load()))
	return time.Since(last) >= gap-time.Second
}

func (r *Realtime) addWatch(dir string) bool { return r.addWatchKeeping(dir, 0) }

// addWatchKeeping watches dir unless fewer than reserve watches are left.
func (r *Realtime) addWatchKeeping(dir string, reserve int) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.watches >= r.limit-reserve {
		return false
	}
	if _, ok := r.byPath[dir]; ok {
		return true
	}
	wd, err := unix.InotifyAddWatch(r.fd, dir, watchMask)
	if err == unix.ENOSPC || err == unix.ENOMEM {
		// The kernel's limit is lower than ours: this is the limit now,
		// and the remaining folders go to the sweep.
		if r.limit > r.watches {
			r.limit = r.watches
			r.S.Log.Warn("inotify watch limit of the kernel reached; remaining folders are swept", "watches", r.watches)
		}
		return false
	}
	if err != nil {
		return true // unreadable dir: skip but keep walking
	}
	r.dirs[wd], r.byPath[dir] = dir, wd
	r.watches++
	return true
}

// skip reports directories never watched: bind mounts and caches anywhere,
// and mailboxes, logs and panel data directly inside a home directory.
// Caches that hold thousands of folders (page caches, node_modules, git
// objects) would use up the watch limit; scheduled scans still cover them.
func (r *Realtime) skip(path string, name string) bool {
	if skipAnywhere[name] || rtSkipAnywhere[name] || path == QuarantineDir() || systemPath(path) {
		return true
	}
	parent := filepath.Dir(path)
	if name == "cache" && filepath.Base(parent) == "wp-content" {
		return true
	}
	r.mu.Lock()
	home := r.homes[parent]
	r.mu.Unlock()
	return home && (skipInHome[name] || name == "access-logs" || name == ".trash" || name == "ssl" || name == ".htpasswds" || name == "lscache")
}

// rtSkipAnywhere are folders with many subfolders and no web content.
var rtSkipAnywhere = map[string]bool{"node_modules": true, ".git": true}

// addTree watches root and every directory below it. With queueFiles, the
// files already inside are scanned too: a directory that just appeared
// (an extracted archive, a moved folder) is usually filled before its
// watch exists, and those files would otherwise never be seen.
func (r *Realtime) addTree(root string, queueFiles bool) {
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !d.IsDir() {
			if queueFiles && d.Type().IsRegular() {
				r.queue(path)
			}
			return nil
		}
		if path != root && r.skip(path, d.Name()) {
			return filepath.SkipDir
		}
		if !r.addWatch(path) {
			// Over the limit: the sweep looks after this folder.
			r.leave(path)
			if queueFiles {
				_ = filepath.WalkDir(path, func(p string, e fs.DirEntry, err error) error {
					if err == nil && e.Type().IsRegular() {
						r.queue(p)
					}
					return nil
				})
			}
			return filepath.SkipDir
		}
		return nil
	})
}

func (r *Realtime) queue(path string) {
	r.mu.Lock()
	r.pending[path] = time.Now()
	r.mu.Unlock()
}

// inOverflow is set by the kernel when events were lost.
const inOverflow = unix.IN_Q_OVERFLOW

func (r *Realtime) handle(buf []byte) {
	for off := 0; off+unix.SizeofInotifyEvent <= len(buf); {
		ev := (*unix.InotifyEvent)(unsafe.Pointer(&buf[off]))
		r.events.Add(1)
		end := off + unix.SizeofInotifyEvent + int(ev.Len)
		if end > len(buf) {
			break
		}
		nameBytes := buf[off+unix.SizeofInotifyEvent : end]
		off = end
		if ev.Mask&inOverflow != 0 {
			r.overflow.Add(1)
			go r.catchUp(time.Now().Add(-10 * time.Minute))
			continue
		}
		name := strings.TrimRight(string(nameBytes), "\x00")
		r.mu.Lock()
		dir, ok := r.dirs[int(ev.Wd)]
		r.mu.Unlock()
		if !ok {
			continue
		}
		if ev.Mask&unix.IN_IGNORED != 0 || ev.Mask&unix.IN_DELETE_SELF != 0 {
			r.mu.Lock()
			if _, still := r.dirs[int(ev.Wd)]; still {
				delete(r.dirs, int(ev.Wd))
				delete(r.byPath, dir)
				r.watches--
			}
			r.mu.Unlock()
			continue
		}
		if name == "" {
			continue
		}
		full := filepath.Join(dir, name)
		if ev.Mask&unix.IN_ISDIR != 0 {
			if ev.Mask&(unix.IN_CREATE|unix.IN_MOVED_TO) != 0 && !r.skip(full, name) {
				r.addTree(full, true)
			}
			continue
		}
		if ev.Mask&(unix.IN_CLOSE_WRITE|unix.IN_MOVED_TO) != 0 {
			r.queue(full)
		}
	}
}

// catchUp scans files changed since t after the kernel dropped events.
func (r *Realtime) catchUp(since time.Time) {
	lowPriorityThread()
	r.S.Log.Warn("realtime event queue overflowed; rescanning recently changed files")
	for _, root := range r.roots() {
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if path != root && r.skip(path, d.Name()) {
					return filepath.SkipDir
				}
				return nil
			}
			if info, err := d.Info(); err == nil && info.Mode().IsRegular() && info.ModTime().After(since) {
				r.queue(path)
			}
			return nil
		})
	}
}

// flushPending hands files that were quiet for a moment to the workers.
func (r *Realtime) flushPending() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for p, t := range r.pending {
		if time.Since(t) < 300*time.Millisecond {
			continue
		}
		select {
		case r.work <- p:
			delete(r.pending, p)
		default:
			return // workers busy: try again on the next flush
		}
	}
}

// Scheduler runs the daily and weekly scans of recently changed files.
func (s *Scanner) Scheduler(ctx context.Context, lastRun func(kind string) int64, markRun func(kind string)) {
	t := time.NewTicker(15 * time.Minute)
	defer t.Stop()
	for {
		cfg := s.Settings.Get().Scanner
		now := time.Now().In(ScheduleZone(cfg.ScheduleTZ))
		// Run just after midnight (00:00-03:00 in the schedule's time zone,
		// whatever the server's clock is set to) at most once per period.
		if cfg.Enabled && now.Hour() < 3 {
			if cfg.WeeklyScan && now.Weekday() == time.Sunday && now.Unix()-lastRun("weekly") > 6*86400 {
				if _, err := s.Start("weekly", "", "scheduler"); err == nil {
					markRun("weekly")
				}
			} else if cfg.DailyScan && now.Unix()-lastRun("daily") > 20*3600 {
				if _, err := s.Start("daily", "", "scheduler"); err == nil {
					markRun("daily")
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

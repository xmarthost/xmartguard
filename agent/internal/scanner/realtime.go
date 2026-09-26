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

// MaxWatches caps inotify watches so huge servers stay responsive.
var MaxWatches = 500000

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

	mu       sync.Mutex
	fd       int
	dirs     map[int]string
	byPath   map[string]int
	pending  map[string]time.Time
	watches  int
	homes    map[string]bool
	work     chan string
	scanned  atomic.Int64
	overflow atomic.Int64
	active   atomic.Bool
	lastErr  atomic.Value // string
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

// Scanned is the number of files the realtime scanner checked since start.
func (r *Realtime) Scanned() int64 { return r.scanned.Load() }

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

// Run watches until ctx ends. Roots are refreshed every 10 minutes so new
// accounts are picked up; enable/disable follows the scanner settings.
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
	if err := r.init(r.roots()); err != nil {
		r.lastErr.Store(err.Error())
		r.S.Log.Warn("realtime scanning unavailable", "err", err)
		select {
		case <-ctx.Done():
		case <-time.After(10 * time.Minute):
		}
		return
	}
	r.S.Log.Info("realtime scanning active", "watches", r.Watches())
	r.lastErr.Store("")
	r.active.Store(true)
	r.loop(ctx)
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
	r.work = make(chan string, 20000)
	r.mu.Unlock()
	for _, root := range roots {
		r.addTree(root, false)
	}
	return nil
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
	refresh := time.NewTicker(10 * time.Minute)
	defer refresh.Stop()
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
			for _, root := range r.roots() {
				r.mu.Lock()
				_, known := r.byPath[root]
				r.mu.Unlock()
				if !known {
					r.addTree(root, false)
				}
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

func (r *Realtime) addWatch(dir string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.watches >= MaxWatches {
		return false
	}
	if _, ok := r.byPath[dir]; ok {
		return true
	}
	wd, err := unix.InotifyAddWatch(r.fd, dir, watchMask)
	if err != nil {
		return true // unreadable dir: skip but keep walking
	}
	r.dirs[wd], r.byPath[dir] = dir, wd
	r.watches++
	return true
}

// skip reports directories never watched: bind mounts and caches anywhere,
// and mailboxes, logs and panel data directly inside a home directory.
func (r *Realtime) skip(path string, name string) bool {
	if skipAnywhere[name] || path == QuarantineDir() || systemPath(path) {
		return true
	}
	r.mu.Lock()
	home := r.homes[filepath.Dir(path)]
	r.mu.Unlock()
	return home && (skipInHome[name] || name == "access-logs" || name == ".trash" || name == "ssl" || name == ".htpasswds")
}

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
			return filepath.SkipAll
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
		now := time.Now()
		cfg := s.Settings.Get().Scanner
		// Run in the quiet hours (02:00-05:00 local) at most once per period.
		if cfg.Enabled && now.Hour() >= 2 && now.Hour() < 5 {
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

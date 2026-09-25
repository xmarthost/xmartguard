package scanner

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// MaxWatches caps inotify watches so huge servers stay responsive.
var MaxWatches = 300000

const watchMask = unix.IN_CLOSE_WRITE | unix.IN_MOVED_TO | unix.IN_CREATE | unix.IN_DELETE_SELF | unix.IN_ONLYDIR

// Realtime watches web roots with inotify and scans files as they are written.
type Realtime struct {
	S *Scanner

	mu      sync.Mutex
	fd      int
	dirs    map[int]string
	byPath  map[string]int
	pending map[string]time.Time
	watches int
}

// Watches returns the number of active directory watches.
func (r *Realtime) Watches() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.watches
}

// ensureLimit raises fs.inotify.max_user_watches (runtime only) when too low.
func ensureLimit(want int) {
	const p = "/proc/sys/fs/inotify/max_user_watches"
	raw, err := os.ReadFile(p)
	if err != nil {
		return
	}
	cur, _ := strconv.Atoi(strings.TrimSpace(string(raw)))
	if cur < want {
		_ = os.WriteFile(p, []byte(strconv.Itoa(want)), 0o644)
	}
}

// Run watches until ctx ends. Roots are refreshed every 10 minutes so new
// accounts are picked up; enable/disable follows the scanner settings.
func (r *Realtime) Run(ctx context.Context) {
	ensureLimit(MaxWatches + 100000)
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
	if err := r.init(WebRoots()); err != nil {
		r.S.Log.Warn("realtime scanning unavailable", "err", err)
		select {
		case <-ctx.Done():
		case <-time.After(10 * time.Minute):
		}
		return
	}
	r.S.Log.Info("realtime scanning active", "watches", r.Watches())
	r.loop(ctx)
}

// init opens an inotify instance and watches the given roots recursively.
func (r *Realtime) init(roots []string) error {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.fd, r.dirs, r.byPath, r.pending, r.watches = fd, map[int]string{}, map[string]int{}, map[string]time.Time{}, 0
	r.mu.Unlock()
	for _, root := range roots {
		r.addTree(root)
	}
	return nil
}

// loop processes events until ctx ends or realtime is switched off.
func (r *Realtime) loop(ctx context.Context) {
	fd := r.fd
	defer func() {
		unix.Close(fd)
		r.mu.Lock()
		r.watches = 0
		r.mu.Unlock()
	}()
	refresh := time.NewTicker(10 * time.Minute)
	flush := time.NewTicker(time.Second)
	defer refresh.Stop()
	defer flush.Stop()
	buf := make([]byte, 64*1024)
	for {
		select {
		case <-ctx.Done():
			return
		case <-refresh.C:
			cfg := r.S.Settings.Get().Scanner
			if !cfg.Enabled || !cfg.Realtime {
				return
			}
			for _, root := range WebRoots() {
				r.mu.Lock()
				_, known := r.byPath[root]
				r.mu.Unlock()
				if !known {
					r.addTree(root)
				}
			}
		case <-flush.C:
			r.flushPending()
		default:
			n, err := unix.Read(fd, buf)
			if err != nil || n <= 0 {
				time.Sleep(200 * time.Millisecond)
				continue
			}
			r.handle(buf[:n])
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

func (r *Realtime) addTree(root string) {
	qdir := QuarantineDir()
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		if skipAnywhere[d.Name()] || path == qdir {
			return filepath.SkipDir
		}
		if !r.addWatch(path) {
			return filepath.SkipAll
		}
		return nil
	})
}

func (r *Realtime) handle(buf []byte) {
	for off := 0; off+unix.SizeofInotifyEvent <= len(buf); {
		ev := (*unix.InotifyEvent)(unsafe.Pointer(&buf[off]))
		nameBytes := buf[off+unix.SizeofInotifyEvent : off+unix.SizeofInotifyEvent+int(ev.Len)]
		off += unix.SizeofInotifyEvent + int(ev.Len)
		name := strings.TrimRight(string(nameBytes), "\x00")
		r.mu.Lock()
		dir, ok := r.dirs[int(ev.Wd)]
		r.mu.Unlock()
		if !ok {
			continue
		}
		if ev.Mask&unix.IN_IGNORED != 0 || ev.Mask&unix.IN_DELETE_SELF != 0 {
			r.mu.Lock()
			delete(r.dirs, int(ev.Wd))
			delete(r.byPath, dir)
			r.watches--
			r.mu.Unlock()
			continue
		}
		if name == "" {
			continue
		}
		full := filepath.Join(dir, name)
		if ev.Mask&unix.IN_ISDIR != 0 {
			if ev.Mask&(unix.IN_CREATE|unix.IN_MOVED_TO) != 0 {
				r.addTree(full)
			}
			continue
		}
		if ev.Mask&(unix.IN_CLOSE_WRITE|unix.IN_MOVED_TO) != 0 {
			r.mu.Lock()
			r.pending[full] = time.Now()
			r.mu.Unlock()
		}
	}
}

// flushPending scans files that have been quiet for at least one second.
func (r *Realtime) flushPending() {
	r.mu.Lock()
	var ready []string
	for p, t := range r.pending {
		if time.Since(t) >= time.Second {
			ready = append(ready, p)
			delete(r.pending, p)
		}
	}
	r.mu.Unlock()
	for _, p := range ready {
		r.S.ScanFile(p)
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

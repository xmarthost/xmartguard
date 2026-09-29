package scanner

import (
	"context"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

// Scans must not slow the websites down: they use few threads, run them at
// the lowest CPU and disk priority, and pause while the server is busy.

// scanWorkers is the number of scan threads for a speed setting.
func scanWorkers(speed string, cpus int) int {
	n := 1
	switch speed {
	case "low":
	case "fast":
		n = min(cpus/2, 8)
	default: // normal
		n = min(cpus/4, 4)
	}
	return max(n, 1)
}

// lowPriorityThread gives the calling goroutine its own OS thread with the
// lowest CPU priority (nice 19) and the idle disk class: it only gets the
// time the web server, PHP and MySQL leave unused. The thread is discarded
// when the goroutine ends (the goroutine never unlocks it).
func lowPriorityThread() {
	runtime.LockOSThread()
	tid := unix.Gettid()
	_ = unix.Setpriority(unix.PRIO_PROCESS, tid, 19)
	const ioprioClassIdle, ioprioClassShift, ioprioWhoProcess = 3, 13, 1
	_, _, _ = unix.Syscall(unix.SYS_IOPRIO_SET, ioprioWhoProcess, uintptr(tid), ioprioClassIdle<<ioprioClassShift)
}

// loadPerCPU is the 1-minute load average divided by the CPU count, read
// at most once a second (x1000, shared by all scan threads).
var (
	loadPerCPU atomic.Int64
	loadReadAt atomic.Int64
)

func currentLoad() float64 {
	now := time.Now().Unix()
	if last := loadReadAt.Load(); now != last && loadReadAt.CompareAndSwap(last, now) {
		if b, err := os.ReadFile("/proc/loadavg"); err == nil {
			if f := strings.Fields(string(b)); len(f) > 0 {
				if l, err := strconv.ParseFloat(f[0], 64); err == nil {
					loadPerCPU.Store(int64(l * 1000 / float64(runtime.NumCPU())))
				}
			}
		}
	}
	return float64(loadPerCPU.Load()) / 1000
}

// busyLimit is the load per CPU above which a scan pauses.
func busyLimit(speed string) float64 {
	switch speed {
	case "low":
		return 0.7
	case "fast":
		return 1.5
	}
	return 1.0
}

// waitForIdle pauses a scan thread while the server is busy (at most a
// minute at a time, so a server that is always loaded still gets scanned).
func waitForIdle(ctx context.Context, speed string) {
	limit := busyLimit(speed)
	deadline := time.Now().Add(time.Minute)
	for currentLoad() > limit && time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return
		case <-time.After(500 * time.Millisecond):
		}
	}
}

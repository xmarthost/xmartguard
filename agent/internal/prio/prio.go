// Package prio runs background work (CMS checks, scans) at the lowest
// priority, so it only uses what the websites, PHP and MySQL leave free.
package prio

import (
	"context"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// LowThread gives the calling goroutine its own OS thread with the lowest
// CPU priority (nice 19) and the idle disk class. The goroutine never
// unlocks it, so the thread is discarded when the goroutine ends.
func LowThread() {
	runtime.LockOSThread()
	tid := unix.Gettid()
	_ = unix.Setpriority(unix.PRIO_PROCESS, tid, 19)
	const ioprioClassIdle, ioprioClassShift, ioprioWhoProcess = 3, 13, 1
	_, _, _ = unix.Syscall(unix.SYS_IOPRIO_SET, ioprioWhoProcess, uintptr(tid), ioprioClassIdle<<ioprioClassShift)
}

// LoadPerCPU is the 1-minute load average divided by the CPU count.
func LoadPerCPU() float64 {
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0
	}
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return 0
	}
	l, _ := strconv.ParseFloat(f[0], 64)
	return l / float64(runtime.NumCPU())
}

// WaitIdle pauses while the server's load per CPU is above limit, at most
// max at a time (a server that is always busy still gets its checks).
func WaitIdle(ctx context.Context, limit float64, max time.Duration) {
	deadline := time.Now().Add(max)
	for LoadPerCPU() > limit && time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

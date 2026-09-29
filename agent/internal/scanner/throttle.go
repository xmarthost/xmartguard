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

// Scans must not slow the websites down. Their threads run at the lowest
// CPU and disk priority, and with the "auto" speed (the default) the number
// of threads follows the CPU time the rest of the server leaves free: fewer
// as soon as websites, PHP, MySQL or mail get busy, more when it is quiet.

// maxWorkers is the most scan threads a speed setting allows: half of the
// CPUs, so a large server scans with many threads (up to 32).
func maxWorkers(speed string, cpus int) int {
	if speed == "low" {
		return 1
	}
	return max(min(cpus/2, 32), 1) // auto, fast
}

// cpuShare is the share of all CPUs the scan may bring the server to in
// auto mode: the scan only uses what is left below it.
const cpuShare = 0.75

// lowMemory is the share of RAM available below which a scan uses one
// thread.
const lowMemory = 0.10

// nextWorkers decides the auto-mode thread count from the CPU cores the
// rest of the server used over the last interval and the RAM available:
// drop at once to what is free (at least one thread, so the scan
// finishes), grow one thread at a time.
func nextWorkers(cur, most, cpus int, othersCores, memAvail float64) int {
	free := int(cpuShare*float64(cpus) - othersCores)
	if memAvail < lowMemory {
		free = 1
	}
	switch {
	case free < cur:
		cur = free
	case free > cur:
		cur++
	}
	return min(max(cur, 1), most)
}

// governor holds how many of a scan's threads may work right now.
type governor struct {
	active atomic.Int32
}

// newGovernor starts the thread control for a scan. Low and fast use a
// fixed count; auto starts with one thread and adapts every 2 seconds.
func newGovernor(ctx context.Context, speed string, cpus int) (*governor, int) {
	g := &governor{}
	most := maxWorkers(speed, cpus)
	if speed != "auto" {
		g.active.Store(int32(most))
		return g, most
	}
	g.active.Store(1)
	go func() {
		prev, ok := readCPU()
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			cur, ok2 := readCPU()
			if ok && ok2 {
				others := cur.othersCores(prev, cpus)
				g.active.Store(int32(nextWorkers(int(g.active.Load()), most, cpus, others, memAvailable())))
			}
			prev, ok = cur, ok2
		}
	}()
	return g, most
}

// wait holds thread i while it is above the allowed count.
func (g *governor) wait(ctx context.Context, i int) {
	for int32(i) >= g.active.Load() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// memAvailable is the share of RAM available (MemAvailable / MemTotal; 1
// when unknown).
func memAvailable() float64 {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 1
	}
	var total, avail float64
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		v, _ := strconv.ParseFloat(f[1], 64)
		switch f[0] {
		case "MemTotal:":
			total = v
		case "MemAvailable:":
			avail = v
		}
	}
	if total <= 0 || avail <= 0 {
		return 1
	}
	return avail / total
}

// cpuSample is the whole machine's and this process's CPU time (jiffies).
type cpuSample struct{ total, idle, self uint64 }

// othersCores is how many cores everything but the agent kept busy
// between two samples.
func (c cpuSample) othersCores(prev cpuSample, cpus int) float64 {
	total := float64(c.total - prev.total)
	if total <= 0 || c.total < prev.total {
		return 0
	}
	busy := total - float64(c.idle-prev.idle) - float64(c.self-prev.self)
	return max(busy, 0) / total * float64(cpus)
}

func readCPU() (cpuSample, bool) {
	var s cpuSample
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return s, false
	}
	line, _, _ := strings.Cut(string(b), "\n")
	f := strings.Fields(line)
	if len(f) < 9 || f[0] != "cpu" {
		return s, false
	}
	for i := 1; i <= 8; i++ { // user nice system idle iowait irq softirq steal
		v, _ := strconv.ParseUint(f[i], 10, 64)
		s.total += v
		if i == 4 || i == 5 {
			s.idle += v
		}
	}
	// Fields 14 and 15 of /proc/self/stat (after the command in brackets).
	st, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return s, false
	}
	if i := strings.LastIndexByte(string(st), ')'); i >= 0 {
		rest := strings.Fields(string(st)[i+1:])
		if len(rest) > 12 {
			u, _ := strconv.ParseUint(rest[11], 10, 64)
			k, _ := strconv.ParseUint(rest[12], 10, 64)
			s.self = u + k
		}
	}
	return s, true
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

// busyLimit is the load per CPU above which every scan thread pauses (an
// overloaded server, e.g. waiting on a slow disk, which CPU time alone
// does not show).
func busyLimit(speed string) float64 {
	switch speed {
	case "low":
		return 0.7
	case "fast":
		return 1.5
	}
	return 1.0 // auto
}

// waitForIdle pauses a scan thread while the server is overloaded (at
// most a minute at a time, so a server that is always loaded still gets
// scanned).
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

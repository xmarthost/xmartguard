package sysinfo

import (
	"bufio"
	"os"
	"os/user"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Memory holds values in bytes.
type Memory struct {
	Total, Available, Used, SwapTotal, SwapUsed uint64
}

// ReadMemory parses /proc/meminfo.
func ReadMemory() (Memory, error) {
	f, err := os.Open(p("proc", "meminfo"))
	if err != nil {
		return Memory{}, err
	}
	defer f.Close()
	v := map[string]uint64{}
	s := bufio.NewScanner(f)
	for s.Scan() {
		k, rest, ok := strings.Cut(s.Text(), ":")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		n, _ := strconv.ParseUint(fields[0], 10, 64)
		v[k] = n * 1024
	}
	m := Memory{Total: v["MemTotal"], SwapTotal: v["SwapTotal"]}
	if a, ok := v["MemAvailable"]; ok {
		m.Available = a
	} else {
		m.Available = v["MemFree"] + v["Buffers"] + v["Cached"]
	}
	if m.Total > m.Available {
		m.Used = m.Total - m.Available
	}
	if m.SwapTotal > v["SwapFree"] {
		m.SwapUsed = m.SwapTotal - v["SwapFree"]
	}
	return m, nil
}

// LoadAvg parses /proc/loadavg.
func LoadAvg() (l1, l5, l15 float64) {
	raw, err := os.ReadFile(p("proc", "loadavg"))
	if err != nil {
		return
	}
	f := strings.Fields(string(raw))
	if len(f) >= 3 {
		l1, _ = strconv.ParseFloat(f[0], 64)
		l5, _ = strconv.ParseFloat(f[1], 64)
		l15, _ = strconv.ParseFloat(f[2], 64)
	}
	return
}

// Uptime returns seconds since boot.
func Uptime() uint64 {
	raw, err := os.ReadFile(p("proc", "uptime"))
	if err != nil {
		return 0
	}
	f := strings.Fields(string(raw))
	if len(f) == 0 {
		return 0
	}
	x, _ := strconv.ParseFloat(f[0], 64)
	return uint64(x)
}

// Disk returns total/used bytes for the filesystem containing path.
func Disk(path string) (total, used uint64) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return
	}
	bs := uint64(st.Bsize)
	total = st.Blocks * bs
	free := st.Bfree * bs
	if total > free {
		used = total - free
	}
	return
}

// cpuTimes reads the aggregate "cpu" line of /proc/stat.
func cpuTimes() (idle, total uint64, ok bool) {
	f, err := os.Open(p("proc", "stat"))
	if err != nil {
		return
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	if !s.Scan() {
		return
	}
	fields := strings.Fields(s.Text())
	if len(fields) < 5 || fields[0] != "cpu" {
		return
	}
	for i, x := range fields[1:] {
		n, _ := strconv.ParseUint(x, 10, 64)
		total += n
		if i == 3 || i == 4 { // idle + iowait
			idle += n
		}
	}
	return idle, total, true
}

// Established counts established TCP connections (IPv4 + IPv6).
func Established() int {
	n := 0
	for _, name := range []string{"tcp", "tcp6"} {
		f, err := os.Open(p("proc", "net", name))
		if err != nil {
			continue
		}
		s := bufio.NewScanner(f)
		s.Scan() // header
		for s.Scan() {
			fields := strings.Fields(s.Text())
			if len(fields) > 3 && fields[3] == "01" {
				n++
			}
		}
		f.Close()
	}
	return n
}

// Process is one entry of the top-process table.
type Process struct {
	PID        int     `json:"pid"`
	Name       string  `json:"name"`
	User       string  `json:"user"`
	CPUPercent float64 `json:"cpu_percent"`
	MemBytes   uint64  `json:"mem_bytes"`
	RunSeconds uint64  `json:"run_seconds"`
}

// Sample is one metrics snapshot sent to the portal.
type Sample struct {
	TS            int64     `json:"ts"`
	CPUPercent    float64   `json:"cpu_percent"`
	Load1         float64   `json:"load1"`
	Load5         float64   `json:"load5"`
	Load15        float64   `json:"load15"`
	MemTotal      uint64    `json:"mem_total"`
	MemUsed       uint64    `json:"mem_used"`
	SwapTotal     uint64    `json:"swap_total"`
	SwapUsed      uint64    `json:"swap_used"`
	DiskTotal     uint64    `json:"disk_total"`
	DiskUsed      uint64    `json:"disk_used"`
	Connections   int       `json:"connections"`
	UptimeSeconds uint64    `json:"uptime_seconds"`
	TopProcesses  []Process `json:"top_processes"`
}

type procTimes struct{ ticks uint64 }

// Collector keeps the previous counters needed to compute CPU percentages.
type Collector struct {
	mu        sync.Mutex
	prevIdle  uint64
	prevTotal uint64
	prevProc  map[int]procTimes
	prevAt    time.Time
	userCache map[string]string
}

// NewCollector primes the CPU counters.
func NewCollector() *Collector {
	c := &Collector{prevProc: map[int]procTimes{}, userCache: map[string]string{}}
	c.prevIdle, c.prevTotal, _ = cpuTimes()
	c.prevProc = c.readProcs(nil)
	c.prevAt = time.Now()
	return c
}

const clkTck = 100 // USER_HZ on all mainstream Linux builds

func (c *Collector) username(uid string) string {
	if n, ok := c.userCache[uid]; ok {
		return n
	}
	name := uid
	if u, err := user.LookupId(uid); err == nil {
		name = u.Username
	}
	c.userCache[uid] = name
	return name
}

// readProcs returns cumulative CPU ticks per pid. When out is non-nil it is
// also filled with per-process details.
func (c *Collector) readProcs(out *[]Process) map[int]procTimes {
	res := map[int]procTimes{}
	entries, err := os.ReadDir(p("proc"))
	if err != nil {
		return res
	}
	boot := Uptime()
	pageSize := uint64(os.Getpagesize())
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		raw, err := os.ReadFile(p("proc", e.Name(), "stat"))
		if err != nil {
			continue
		}
		s := string(raw)
		open, close := strings.IndexByte(s, '('), strings.LastIndexByte(s, ')')
		if open < 0 || close < open {
			continue
		}
		name := s[open+1 : close]
		f := strings.Fields(s[close+1:])
		// f[0]=state; utime=f[11], stime=f[12], starttime=f[19], rss=f[21]
		if len(f) < 22 {
			continue
		}
		ut, _ := strconv.ParseUint(f[11], 10, 64)
		st, _ := strconv.ParseUint(f[12], 10, 64)
		res[pid] = procTimes{ticks: ut + st}
		if out == nil {
			continue
		}
		start, _ := strconv.ParseUint(f[19], 10, 64)
		rss, _ := strconv.ParseUint(f[21], 10, 64)
		var run uint64
		if boot > start/clkTck {
			run = boot - start/clkTck
		}
		uid := ""
		if st, err := os.Stat(p("proc", e.Name())); err == nil {
			if sys, ok := st.Sys().(*syscall.Stat_t); ok {
				uid = strconv.FormatUint(uint64(sys.Uid), 10)
			}
		}
		*out = append(*out, Process{PID: pid, Name: name, User: c.username(uid), MemBytes: rss * pageSize, RunSeconds: run})
	}
	return res
}

// Collect produces a new sample, computing CPU usage since the previous call.
func (c *Collector) Collect(topN int) Sample {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	s := Sample{TS: now.Unix()}

	idle, total, ok := cpuTimes()
	if ok && total > c.prevTotal {
		dt := float64(total - c.prevTotal)
		di := float64(idle - c.prevIdle)
		s.CPUPercent = round1(100 * (dt - di) / dt)
	}
	c.prevIdle, c.prevTotal = idle, total

	s.Load1, s.Load5, s.Load15 = LoadAvg()
	if m, err := ReadMemory(); err == nil {
		s.MemTotal, s.MemUsed, s.SwapTotal, s.SwapUsed = m.Total, m.Used, m.SwapTotal, m.SwapUsed
	}
	s.DiskTotal, s.DiskUsed = Disk(p())
	s.Connections = Established()
	s.UptimeSeconds = Uptime()

	var procs []Process
	cur := c.readProcs(&procs)
	elapsed := now.Sub(c.prevAt).Seconds()
	if elapsed > 0 {
		for i := range procs {
			prev, ok := c.prevProc[procs[i].PID]
			now := cur[procs[i].PID]
			if ok && now.ticks >= prev.ticks {
				procs[i].CPUPercent = round1(100 * float64(now.ticks-prev.ticks) / clkTck / elapsed)
			}
		}
	}
	c.prevProc, c.prevAt = cur, now
	sort.Slice(procs, func(a, b int) bool {
		if procs[a].CPUPercent != procs[b].CPUPercent {
			return procs[a].CPUPercent > procs[b].CPUPercent
		}
		return procs[a].MemBytes > procs[b].MemBytes
	})
	if len(procs) > topN {
		procs = procs[:topN]
	}
	s.TopProcesses = procs
	return s
}

func round1(f float64) float64 { return float64(int64(f*10+0.5)) / 10 }

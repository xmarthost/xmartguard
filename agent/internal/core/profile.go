package core

import (
	"bytes"
	"context"
	"errors"
	"os"
	"runtime"
	"runtime/pprof"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/pprof/profile"

	"github.com/xmarthost/xmartguard/agent/internal/waf"
)

// ProfileReport says where the agent's own CPU time goes, so a busy agent on
// a live server can be explained without debugging tools.
type ProfileReport struct {
	Seconds    int           `json:"seconds"`
	CPUPercent float64       `json:"cpu_percent"` // the agent process, 100 = one core
	Engine     float64       `json:"engine_percent"`
	Goroutines int           `json:"goroutines"`
	Threads    int           `json:"threads"`
	Activity   Activity      `json:"activity"`
	Areas      []ProfileLine `json:"areas"`
	Functions  []ProfileLine `json:"functions"`
}

// Activity is what the agent handled during the profile, per second.
type Activity struct {
	WAFLines     float64 `json:"waf_log_lines"`
	RTEvents     float64 `json:"realtime_events"`
	RTScanned    float64 `json:"realtime_files_scanned"`
	RTSwept      float64 `json:"realtime_files_swept"`
	Watches      int     `json:"realtime_watches"`
	Unwatched    int     `json:"realtime_unwatched_folders"`
	LastSweepSec float64 `json:"realtime_last_sweep_seconds"`
	ScanRunning  bool    `json:"scan_running"`
}

// ProfileLine is one area or function and its share of the sampled CPU.
type ProfileLine struct {
	Name    string  `json:"name"`
	Percent float64 `json:"percent"` // of one core over the profile
	Share   float64 `json:"share"`   // of the agent's sampled CPU
}

const ourModule = "github.com/xmarthost/xmartguard/agent/"

// areaNames names the agent's packages in words.
var areaNames = map[string]string{
	"scanner":    "Malware scanner (realtime and scan results)",
	"waf":        "WAF (log reading, rules, learning)",
	"logtail":    "Log reader",
	"firewall":   "Firewall and IPDB",
	"hostfw":     "Firewall and IPDB",
	"monitor":    "Process and cron monitor",
	"cms":        "CMS check",
	"reputation": "Domain reputation",
	"clamdb":     "ClamAV-format signatures",
	"ai":         "AI checks",
	"ml":         "AI checks",
	"client":     "Portal connection",
	"protocol":   "Portal connection",
	"store":      "Local database",
	"mail":       "Mail protection",
	"captcha":    "CAPTCHA gate",
	"tor":        "Tor list",
	"trusted":    "Trusted services",
	"core":       "Agent core",
	"panel":      "cPanel integration",
	"updater":    "Updater",
	"sysinfo":    "Server stats",
	"wpcore":     "WordPress core files",
}

var profiling atomic.Bool

// cpuProfile samples the agent for d and groups the time by area.
func (a *Agent) cpuProfile(ctx context.Context, d time.Duration) (*ProfileReport, error) {
	if !profiling.CompareAndSwap(false, true) {
		return nil, errors.New("a profile is already running")
	}
	defer profiling.Store(false)
	var buf bytes.Buffer
	if err := pprof.StartCPUProfile(&buf); err != nil {
		return nil, err
	}
	self0, kids0 := procTicks(os.Getpid()), childTicks()
	waf0, rt0 := waf.LogLines.Load(), a.Realtime.Stats()
	t0 := time.Now()
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
	pprof.StopCPUProfile()
	wall := time.Since(t0).Seconds()
	self1, kids1 := procTicks(os.Getpid()), childTicks()
	waf1, rt1 := waf.LogLines.Load(), a.Realtime.Stats()
	p, err := profile.Parse(&buf)
	if err != nil {
		return nil, err
	}
	rep := summarize(p, wall)
	rep.Seconds = int(wall + 0.5)
	rep.CPUPercent = round1(float64(self1-self0) / clkTck / wall * 100)
	rep.Engine = round1(float64(engineDelta(kids0, kids1)) / clkTck / wall * 100)
	per := func(n int64) float64 { return round1(float64(n) / wall) }
	rep.Activity = Activity{
		WAFLines: per(waf1 - waf0), RTEvents: per(rt1.Events - rt0.Events),
		RTScanned: per(rt1.Scanned - rt0.Scanned), RTSwept: per(rt1.Swept - rt0.Swept),
		Watches: rt1.Watches, Unwatched: rt1.Unwatched, LastSweepSec: rt1.SweepSecs,
		ScanRunning: len(kids1) > 0,
	}
	rep.Goroutines = runtime.NumGoroutine()
	if ents, err := os.ReadDir("/proc/self/task"); err == nil {
		rep.Threads = len(ents)
	}
	return rep, nil
}

// summarize charges every sample to the agent package nearest the top of its
// stack (Go runtime work such as memory cleanup stays "Go runtime").
func summarize(p *profile.Profile, wall float64) *ProfileReport {
	vi := len(p.SampleType) - 1 // cpu nanoseconds
	areas, funcs := map[string]int64{}, map[string]int64{}
	var total int64
	for _, s := range p.Sample {
		v := s.Value[vi]
		total += v
		leaf, area := "", ""
		for _, loc := range s.Location {
			for _, ln := range loc.Line {
				if ln.Function == nil {
					continue
				}
				name := ln.Function.Name
				if leaf == "" {
					leaf = name
				}
				if area == "" && strings.HasPrefix(name, ourModule) {
					area = areaOf(name)
				}
			}
		}
		if area == "" {
			switch {
			case strings.HasPrefix(leaf, "runtime."):
				area = "Go runtime (memory cleanup, scheduling)"
			default:
				area = "Other"
			}
		}
		areas[area] += v
		if leaf != "" {
			funcs[strings.TrimPrefix(leaf, ourModule)] += v
		}
	}
	return &ProfileReport{Areas: top(areas, total, wall, 15), Functions: top(funcs, total, wall, 25)}
}

func areaOf(fn string) string {
	rest := strings.TrimPrefix(fn, ourModule)
	rest = strings.TrimPrefix(rest, "internal/")
	pkg, _, _ := strings.Cut(rest, ".")
	pkg, _, _ = strings.Cut(pkg, "/")
	if n, ok := areaNames[pkg]; ok {
		return n
	}
	return pkg
}

func top(m map[string]int64, total int64, wall float64, n int) []ProfileLine {
	out := make([]ProfileLine, 0, len(m))
	for k, v := range m {
		out = append(out, ProfileLine{
			Name:    k,
			Percent: round1(float64(v) / 1e9 / wall * 100),
			Share:   round1(float64(v) / float64(max(total, 1)) * 100),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Share > out[j].Share })
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func round1(f float64) float64 { return float64(int64(f*10+0.5)) / 10 }

const clkTck = 100

// procTicks is the user+system CPU of a process in clock ticks.
func procTicks(pid int) int64 {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0
	}
	// Fields after the ")" of the command name; utime and stime are 14 and 15.
	i := bytes.LastIndexByte(b, ')')
	if i < 0 {
		return 0
	}
	f := strings.Fields(string(b[i+1:]))
	if len(f) < 13 {
		return 0
	}
	u, _ := strconv.ParseInt(f[11], 10, 64)
	s, _ := strconv.ParseInt(f[12], 10, 64)
	return u + s
}

// childTicks is the CPU of the agent's running child processes (the scan
// engine) by pid. Children belong to the thread that started them, so every
// thread is asked.
func childTicks() map[int]int64 {
	out := map[int]int64{}
	tasks, _ := os.ReadDir("/proc/self/task")
	for _, t := range tasks {
		b, err := os.ReadFile("/proc/self/task/" + t.Name() + "/children")
		if err != nil {
			continue
		}
		for _, f := range strings.Fields(string(b)) {
			if pid, err := strconv.Atoi(f); err == nil {
				out[pid] = procTicks(pid)
			}
		}
	}
	return out
}

func engineDelta(a, b map[int]int64) int64 {
	var d int64
	for pid, t := range b {
		d += t - a[pid] // a child started during the profile counts from 0
	}
	return d
}

package scanner

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/xmarthost/xmartguard/agent/internal/settings"
)

// The scan engine: like other server security tools, a scan runs in its own
// process ("xpguard-scan"), not in the agent. The whole process (every
// thread) gets the lowest CPU priority (nice 19) and the idle disk class,
// and it may use only as many CPU cores as the scan speed allows (low: one,
// auto: a quarter of the cores, fast: half), so a scan never takes the
// server's CPU from the websites, and stopping it simply ends the process.
// The engine reports what it finds; the agent checks each hit again with
// everything it knows (cleared files, plugin checksums) before recording.

// EngineCommand builds the command that runs the scan engine; nil scans in
// this process (tests).
var EngineCommand func() *exec.Cmd

// EngineReq is what the agent sends the engine on stdin.
type EngineReq struct {
	Roots  []string         `json:"roots"`
	Since  int64            `json:"since,omitempty"`
	Config settings.Scanner `json:"config"`
}

// engineMsg is one line the engine writes on stdout.
type engineMsg struct {
	T       string `json:"t"` // total | progress | hit | done
	N       int64  `json:"n,omitempty"`
	Path    string `json:"path,omitempty"`
	Cat     string `json:"cat,omitempty"`
	Name    string `json:"name,omitempty"`
	Recheck bool   `json:"recheck,omitempty"`
	Error   string `json:"error,omitempty"`
}

// EngineCores is how many CPU cores the engine may use at a scan speed.
func EngineCores(speed string, cpus int) int {
	switch speed {
	case "low":
		return 1
	case "fast":
		return max(1, min(cpus/2, 32))
	}
	return max(1, min(cpus/4, 8)) // auto
}

// runEngine runs a scan in the engine process and records its hits.
func (s *Scanner) runEngine(ctx context.Context, roots []string, since time.Time, cfg settings.Scanner, h treeHooks) (int64, error) {
	cmd := EngineCommand()
	cores := EngineCores(cfg.ScanSpeed, runtime.NumCPU())
	if cmd.Env == nil {
		cmd.Env = os.Environ()
	}
	cmd.Env = append(cmd.Env, "GOMAXPROCS="+strconv.Itoa(cores))
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	req := EngineReq{Roots: roots, Config: cfg}
	if !since.IsZero() {
		req.Since = since.Unix()
	}
	in, _ := json.Marshal(req)
	cmd.Stdin = strings.NewReader(string(in))
	out, err := cmd.StdoutPipe()
	if err != nil {
		return 0, err
	}
	var stderr strings.Builder
	cmd.Stderr = &limitWriter{w: &stderr, n: 4096}
	done := make(chan struct{})
	if err := startLowPriority(cmd, done); err != nil {
		return 0, fmt.Errorf("scan engine: %w", err)
	}
	go func() {
		select {
		case <-ctx.Done():
			_ = unix.Kill(-cmd.Process.Pid, unix.SIGKILL)
		case <-done:
		}
	}()
	var files int64
	var engineErr string
	sc := bufio.NewScanner(out)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var m engineMsg
		if json.Unmarshal(sc.Bytes(), &m) != nil {
			continue
		}
		switch m.T {
		case "total":
			if h.total != nil {
				h.total(m.N)
			}
		case "progress":
			files = m.N
			if h.progress != nil {
				h.progress(m.N, m.Path)
			}
		case "hit":
			info, err := os.Lstat(m.Path)
			if err != nil {
				continue
			}
			d := Detection{m.Cat, m.Name}
			if m.Recheck {
				// The engine has no access to the agent's cleared files and
				// plugin checksums: the agent decides.
				det, err := s.CheckFile(m.Path, info, s.Settings.Get().Scanner)
				if err != nil || det == nil {
					continue
				}
				d = *det
			}
			h.hit(m.Path, info, d)
		case "done":
			files, engineErr = m.N, m.Error
		}
	}
	close(done)
	werr := cmd.Wait()
	switch {
	case ctx.Err() != nil:
		return files, context.Canceled
	case engineErr != "":
		return files, errors.New(engineErr)
	case werr != nil:
		return files, fmt.Errorf("scan engine: %v %s", werr, strings.TrimSpace(stderr.String()))
	}
	return files, nil
}

// startLowPriority starts the engine with the lowest CPU and disk
// priority for all its threads: it is started from a thread that has them
// (a new process inherits its parent thread's), and its process group gets
// them again once it runs. The starting thread lives until done closes:
// the engine's parent-death signal is tied to it, so the engine ends with
// the agent, but not before the scan does.
func startLowPriority(cmd *exec.Cmd, done <-chan struct{}) error {
	errc := make(chan error, 1)
	go func() {
		// This thread keeps the low priority and ends with the goroutine
		// (it is never unlocked), so no other goroutine runs on it.
		lowPriorityThread()
		err := cmd.Start()
		errc <- err
		if err == nil {
			<-done
		}
	}()
	if err := <-errc; err != nil {
		return err
	}
	pid := cmd.Process.Pid
	_ = unix.Setpriority(unix.PRIO_PGRP, pid, 19)
	const ioprioClassIdle, ioprioClassShift, ioprioWhoPgrp = 3, 13, 2
	_, _, _ = unix.Syscall(unix.SYS_IOPRIO_SET, ioprioWhoPgrp, uintptr(pid), ioprioClassIdle<<ioprioClassShift)
	return nil
}

// RunEngine is the engine process: it reads the request from in, scans,
// and writes what it finds to out. s is an offline scanner.
func RunEngine(ctx context.Context, s *Scanner, in io.Reader, out io.Writer) error {
	var req EngineReq
	if err := json.NewDecoder(in).Decode(&req); err != nil {
		return err
	}
	var mu sync.Mutex
	enc := json.NewEncoder(out)
	emit := func(m engineMsg) {
		mu.Lock()
		_ = enc.Encode(m)
		mu.Unlock()
	}
	var since time.Time
	if req.Since > 0 {
		since = time.Unix(req.Since, 0)
	}
	files, err := s.scanTree(ctx, req.Roots, since, req.Config, treeHooks{
		total:    func(n int64) { emit(engineMsg{T: "total", N: n}) },
		progress: func(n int64, cur string) { emit(engineMsg{T: "progress", N: n, Path: cur}) },
		hit: func(path string, _ fs.FileInfo, d Detection) {
			// Signature and heuristic hits are checked again by the agent;
			// symlinks and YARA matches are final.
			recheck := d.Category != CatSymlink && !strings.HasPrefix(d.Signature, "YARA.")
			emit(engineMsg{T: "hit", Path: path, Cat: d.Category, Name: d.Signature, Recheck: recheck})
		},
	})
	m := engineMsg{T: "done", N: files}
	if err != nil && !errors.Is(err, context.Canceled) {
		m.Error = err.Error()
	}
	emit(m)
	return nil
}

// limitWriter keeps the first n bytes (the engine's error output).
type limitWriter struct {
	w io.Writer
	n int
}

func (l *limitWriter) Write(p []byte) (int, error) {
	if l.n > 0 {
		k := min(len(p), l.n)
		_, _ = l.w.Write(p[:k])
		l.n -= k
	}
	return len(p), nil
}

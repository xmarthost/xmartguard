// Package logtail follows log files the way `tail -F` does.
package logtail

import (
	"bufio"
	"context"
	"io"
	"os"
	"syscall"
	"time"
)

// Follow follows a file from its end, surviving rotation and truncation.
func Follow(ctx context.Context, path string, lines chan<- string) {
	var f *os.File
	var ino uint64
	var off int64
	open := func(fromEnd bool) bool {
		nf, err := os.Open(path)
		if err != nil {
			return false
		}
		st, _ := nf.Stat()
		if f != nil {
			f.Close()
		}
		f = nf
		ino = st.Sys().(*syscall.Stat_t).Ino
		off = 0
		if fromEnd {
			off = st.Size()
		}
		return true
	}
	opened := open(true)
	defer func() {
		if f != nil {
			f.Close()
		}
	}()
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	var partial string
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if !opened {
			opened = open(true)
			continue
		}
		st, err := os.Stat(path)
		if err != nil {
			continue
		}
		if st.Sys().(*syscall.Stat_t).Ino != ino || st.Size() < off {
			open(false) // rotated or truncated: read the new file from the start
		}
		if st.Size() == off {
			continue
		}
		if _, err := f.Seek(off, io.SeekStart); err != nil {
			continue
		}
		r := bufio.NewReaderSize(io.LimitReader(f, 8<<20), 64*1024)
		for {
			chunk, err := r.ReadString('\n')
			off += int64(len(chunk))
			if err != nil {
				partial += chunk
				break
			}
			select {
			case lines <- partial + chunk:
			case <-ctx.Done():
				return
			}
			partial = ""
		}
	}
}

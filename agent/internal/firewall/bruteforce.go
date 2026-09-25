package firewall

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"regexp"
	"sync"
	"syscall"
	"time"
)

// LogRule detects a failed login in one log file; the first capture group is the IP.
type LogRule struct {
	Service string
	Files   []string
	Re      *regexp.Regexp
}

const ipRe = `((?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{3,39})`

// LogRules cover the services a hosting server exposes.
var LogRules = []LogRule{
	{"SSH", []string{"/var/log/secure", "/var/log/auth.log"},
		regexp.MustCompile(`sshd\[\d+\]: (?:Failed (?:password|publickey) for (?:invalid user )?\S+|Invalid user \S* ?) from ` + ipRe)},
	{"cPanel/WHM/Webmail", []string{"/usr/local/cpanel/logs/login_log"},
		regexp.MustCompile(`\[(?:cpaneld|whostmgrd|webmaild|cpdavd)\] ` + ipRe + ` - .*FAILED LOGIN`)},
	{"Mail (Dovecot)", []string{"/var/log/maillog", "/var/log/mail.log"},
		regexp.MustCompile(`dovecot.*(?:auth failed|Authentication failure|password mismatch).*rip=` + ipRe)},
	{"Mail (Exim SMTP auth)", []string{"/var/log/exim_mainlog"},
		regexp.MustCompile(`authenticator failed for .*\[` + ipRe + `\]`)},
	{"FTP", []string{"/var/log/messages", "/var/log/syslog"},
		regexp.MustCompile(`pure-ftpd: \([^@]*@` + ipRe + `\) \[WARNING\] Authentication failed`)},
}

// ParseLine returns the offending IP if the line is a failed login for rule.
func (r LogRule) ParseLine(line string) (string, bool) {
	m := r.Re.FindStringSubmatch(line)
	if m == nil {
		return "", false
	}
	ip, err := ParseAddr(m[1])
	if err != nil {
		return "", false
	}
	return ip, true
}

// Counter tracks failures per IP in a sliding window.
type Counter struct {
	mu   sync.Mutex
	hits map[string][]time.Time
	Now  func() time.Time
}

// Hit records a failure and returns the number of failures inside window.
func (c *Counter) Hit(ip string, window time.Duration) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.hits == nil {
		c.hits = map[string][]time.Time{}
	}
	now := time.Now()
	if c.Now != nil {
		now = c.Now()
	}
	cut := now.Add(-window)
	keep := c.hits[ip][:0]
	for _, t := range c.hits[ip] {
		if t.After(cut) {
			keep = append(keep, t)
		}
	}
	keep = append(keep, now)
	c.hits[ip] = keep
	// Opportunistic cleanup.
	if len(c.hits) > 50000 {
		for k, v := range c.hits {
			if len(v) == 0 || v[len(v)-1].Before(cut) {
				delete(c.hits, k)
			}
		}
	}
	return len(keep)
}

// Reset forgets an IP (after it was banned).
func (c *Counter) Reset(ip string) {
	c.mu.Lock()
	delete(c.hits, ip)
	c.mu.Unlock()
}

// tail follows a file from its end, surviving rotation and truncation.
func tail(ctx context.Context, path string, lines chan<- string) {
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

// RunBruteForce watches login logs and temp-bans repeat offenders.
func (m *Manager) RunBruteForce(ctx context.Context) {
	counter := &Counter{}
	type hit struct {
		rule LogRule
		line string
	}
	hits := make(chan hit, 1024)
	for _, rule := range LogRules {
		for _, file := range rule.Files {
			if _, err := os.Stat(file); err != nil {
				continue
			}
			lines := make(chan string, 256)
			go tail(ctx, file, lines)
			go func(r LogRule) {
				for {
					select {
					case <-ctx.Done():
						return
					case l := <-lines:
						select {
						case hits <- hit{r, l}:
						default: // overloaded: drop rather than block the tailer
						}
					}
				}
			}(rule)
		}
	}
	for {
		select {
		case <-ctx.Done():
			return
		case h := <-hits:
			cfg := m.Settings.Get().Firewall
			if !cfg.Enabled || !cfg.BruteForce {
				continue
			}
			ip, ok := h.rule.ParseLine(h.line)
			if !ok {
				continue
			}
			n := counter.Hit(ip, time.Duration(cfg.BFWindowMinutes)*time.Minute)
			if n >= cfg.BFThreshold {
				counter.Reset(ip)
				m.AutoBan(ip, fmt.Sprintf("%d failed %s logins in %d min", n, h.rule.Service, cfg.BFWindowMinutes), "bruteforce")
			}
		}
	}
}

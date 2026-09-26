package firewall

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"sync"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/logtail"
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
	{"SSH", []string{"/var/log/secure", "/var/log/auth.log"},
		regexp.MustCompile(`sshd\[\d+\]: (?:Did not receive identification string|Unable to negotiate|Connection closed by authenticating user \S+|Disconnected from invalid user \S+) (?:from )?` + ipRe)},
	{"cPanel/WHM/Webmail", []string{"/usr/local/cpanel/logs/login_log"},
		regexp.MustCompile(`\[(?:cpaneld|whostmgrd|webmaild|cpdavd)\] ` + ipRe + ` - .*FAILED LOGIN`)},
	{"cPanel/WHM/Webmail", []string{"/usr/local/cpanel/logs/login_log"},
		regexp.MustCompile(`FAILED LOGIN (?:cpaneld|whostmgrd|webmaild): .* ip=` + ipRe)},
	{"Mail (Dovecot)", []string{"/var/log/maillog", "/var/log/mail.log"},
		regexp.MustCompile(`dovecot.*(?:auth failed|Authentication failure|[Pp]assword mismatch).*rip=` + ipRe)},
	{"Mail (Dovecot)", []string{"/var/log/maillog", "/var/log/mail.log"},
		regexp.MustCompile(`dovecot.*auth(?:-worker)?\([^,]*,` + ipRe + `[,)].*(?:pam_authenticate\(\) failed|Password mismatch|unknown user)`)},
	{"Mail (Postfix SASL)", []string{"/var/log/maillog", "/var/log/mail.log"},
		regexp.MustCompile(`warning: \S*\[` + ipRe + `\]: SASL \S+ authentication failed`)},
	{"Mail (Exim SMTP auth)", []string{"/var/log/exim_mainlog"},
		regexp.MustCompile(`authenticator failed for .*\[` + ipRe + `\]`)},
	{"Mail (Exim abuse)", []string{"/var/log/exim_mainlog", "/var/log/exim_rejectlog"},
		regexp.MustCompile(`H=.*\[` + ipRe + `\].* rejected RCPT <[^>]*>: (?:Relay not permitted|relay not permitted)`)},
	{"Mail (Exim abuse)", []string{"/var/log/exim_mainlog"},
		regexp.MustCompile(`SMTP (?:call|connection) from .*\[` + ipRe + `\](?::\d+)? (?:dropped: too many (?:nonmail|unrecognized) commands|dropped: too many syntax or protocol errors|closed by DROP in ACL)`)},
	{"Mail (Exim abuse)", []string{"/var/log/exim_mainlog"},
		regexp.MustCompile(`SMTP protocol synchronization error .* H=.*\[` + ipRe + `\]`)},
	{"FTP", []string{"/var/log/messages", "/var/log/syslog"},
		regexp.MustCompile(`pure-ftpd: \([^@]*@` + ipRe + `\) \[WARNING\] Authentication failed`)},
	{"FTP", []string{"/var/log/messages", "/var/log/syslog", "/var/log/proftpd/proftpd.log"},
		regexp.MustCompile(`proftpd.*\[` + ipRe + `\].*(?:no such user|Incorrect password|Login failed)`)},
	{"FTP", []string{"/var/log/vsftpd.log"},
		regexp.MustCompile(`FAIL LOGIN: Client "(?:::ffff:)?` + ipRe + `"`)},
	{"Web (denied)", []string{"/usr/local/apache/logs/error_log", "/etc/apache2/logs/error_log", "/var/log/httpd/error_log", "/var/log/apache2/error.log"},
		regexp.MustCompile(`\[client ` + ipRe + `(?::\d+)?\] (?:AH01630|AH01797|AH01618|AH01617)`)},
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

// RunBruteForce watches login logs and temp-bans repeat offenders.
func (m *Manager) RunBruteForce(ctx context.Context) {
	counter := &Counter{}
	type hit struct {
		rule LogRule
		line string
	}
	hits := make(chan hit, 1024)
	byFile := map[string][]LogRule{}
	for _, rule := range LogRules {
		for _, file := range rule.Files {
			byFile[file] = append(byFile[file], rule)
		}
	}
	for file, rules := range byFile {
		if _, err := os.Stat(file); err != nil {
			continue
		}
		lines := make(chan string, 256)
		go logtail.Follow(ctx, file, lines)
		go func(rules []LogRule) {
			for {
				select {
				case <-ctx.Done():
					return
				case l := <-lines:
					for _, r := range rules {
						if !r.Re.MatchString(l) {
							continue
						}
						select {
						case hits <- hit{r, l}:
						default: // overloaded: drop rather than block the tailer
						}
						break
					}
				}
			}
		}(rules)
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

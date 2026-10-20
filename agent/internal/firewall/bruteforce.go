package firewall

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"slices"
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

// The log lines carry text the client chose (a user name, a HELO name, an
// SMTP command, a URL). Each pattern is anchored to the fixed text the
// daemon writes around the address (the line start, the end of the line or
// the host field), so that text can never put another address where the
// client's is read: it would get that address banned and reported to the
// fleet IPDB.
const (
	// syslogHead is the syslog header before the program name.
	syslogHead = `^(?:\S+\s+){1,5}?`
	// sshTail is what sshd writes after the client address.
	sshTail = `(?: port \d+)?(?: ssh2)?(?:: \S+ \S+)?(?: \[preauth\])?\s*$`
	// eximHead is the start of an Exim log line (date, time, zone and pid).
	eximHead = `^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\S* (?:[+-]\d{4} )?(?:\[\d+\] )?`
	// eximHost is Exim's host field: "[ip]", "(helo) [ip]" or "name (helo)
	// [ip]". Neither the name nor the HELO holds a space, so the address
	// is the first token in brackets.
	eximHost = `(?:\S+ )?(?:\(\S*\) )?\[` + ipRe + `\]`
)

// LogRules cover the services a hosting server exposes.
var LogRules = []LogRule{
	{"SSH", []string{"/var/log/secure", "/var/log/auth.log"},
		regexp.MustCompile(syslogHead + `sshd\[\d+\]: (?:Failed (?:password|publickey) for (?:invalid user )?.*|Invalid user .*) from ` + ipRe + sshTail)},
	{"SSH", []string{"/var/log/secure", "/var/log/auth.log"},
		regexp.MustCompile(syslogHead + `sshd\[\d+\]: (?:Did not receive identification string|Unable to negotiate) (?:from )?` + ipRe)},
	{"SSH", []string{"/var/log/secure", "/var/log/auth.log"},
		regexp.MustCompile(syslogHead + `sshd\[\d+\]: (?:Connection closed by authenticating user|Disconnected from invalid user) .* ` + ipRe + ` port \d+(?: \[preauth\])?\s*$`)},
	{"cPanel/WHM/Webmail", []string{"/usr/local/cpanel/logs/login_log"},
		regexp.MustCompile(`^(?:\[[^\]]*\] )?(?:\w+ )?\[(?:cpaneld|whostmgrd|webmaild|cpdavd)\] ` + ipRe + ` - .*FAILED LOGIN`)},
	{"cPanel/WHM/Webmail", []string{"/usr/local/cpanel/logs/login_log"},
		regexp.MustCompile(`^(?:\[[^\]]*\] )?(?:\w+ )?FAILED LOGIN (?:cpaneld|whostmgrd|webmaild): .*? ip=` + ipRe)},
	{"Mail (Dovecot)", []string{"/var/log/maillog", "/var/log/mail.log"},
		regexp.MustCompile(syslogHead + `dovecot(?:\[\d+\])?: .*(?:auth failed|Authentication failure|[Pp]assword mismatch).*rip=` + ipRe)},
	{"Mail (Dovecot)", []string{"/var/log/maillog", "/var/log/mail.log"},
		regexp.MustCompile(syslogHead + `dovecot(?:\[\d+\])?: .*?auth(?:-worker)?\([^,]*,` + ipRe + `[,)].*(?:pam_authenticate\(\) failed|Password mismatch|unknown user)`)},
	{"Mail (Postfix SASL)", []string{"/var/log/maillog", "/var/log/mail.log"},
		regexp.MustCompile(syslogHead + `postfix(?:/[^\[\s]+)?\[\d+\]: warning: \S*\[` + ipRe + `\]: SASL \S+ authentication failed`)},
	{"Mail (Exim SMTP auth)", []string{"/var/log/exim_mainlog"},
		regexp.MustCompile(eximHead + `\S+ authenticator failed for ` + eximHost)},
	{"Mail (Exim abuse)", []string{"/var/log/exim_mainlog", "/var/log/exim_rejectlog"},
		regexp.MustCompile(eximHead + `H=` + eximHost + `.* rejected RCPT <[^>]*>: (?:Relay not permitted|relay not permitted)`)},
	{"Mail (Exim abuse)", []string{"/var/log/exim_mainlog"},
		regexp.MustCompile(eximHead + `SMTP (?:call|connection) from ` + eximHost + `(?::\d+)?(?: I=\S+)? (?:dropped: too many (?:nonmail|unrecognized) commands|dropped: too many syntax or protocol errors|closed by DROP in ACL)`)},
	// Only the form whose host field comes before any client text: the
	// pipelining form writes the client's own command first.
	{"Mail (Exim abuse)", []string{"/var/log/exim_mainlog"},
		regexp.MustCompile(eximHead + `SMTP protocol synchronization error \([^)]*\): rejected connection from H=` + eximHost)},
	{"FTP", []string{"/var/log/messages", "/var/log/syslog"},
		regexp.MustCompile(syslogHead + `pure-ftpd(?:\[\d+\])?: \([^@]*@` + ipRe + `\) \[WARNING\] Authentication failed`)},
	{"FTP", []string{"/var/log/messages", "/var/log/syslog", "/var/log/proftpd/proftpd.log"},
		regexp.MustCompile(syslogHead + `proftpd\[\d+\]:? \S+ \(\S*\[(?:::ffff:)?` + ipRe + `\]\).*(?:no such user|Incorrect password|Login failed)`)},
	{"FTP", []string{"/var/log/vsftpd.log"},
		regexp.MustCompile(`FAIL LOGIN: Client "(?:::ffff:)?` + ipRe + `"\s*$`)},
	{"Web (denied)", []string{"/usr/local/apache/logs/error_log", "/etc/apache2/logs/error_log", "/var/log/httpd/error_log", "/var/log/apache2/error.log"},
		regexp.MustCompile(`^(?:\[[^\]]*\] )+\[client ` + ipRe + `(?::\d+)?\] (?:AH01630|AH01797|AH01618|AH01617)`)},
}

// Jails lists the Intrusion Defense rule names (services) that can be excluded.
func Jails() []string {
	var out []string
	for _, r := range LogRules {
		if !slices.Contains(out, r.Service) {
			out = append(out, r.Service)
		}
	}
	return out
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
			if slices.Contains(cfg.ExcludedJails, h.rule.Service) {
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

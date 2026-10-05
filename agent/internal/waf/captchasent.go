package waf

import (
	"net"
	"strings"
	"sync"
	"time"
)

// Visitors this server's WAF sent to the portal's CAPTCHA page, from the
// web server's logs. Where the server has no list of its websites (no
// /etc/userdomains), the agent only accepts a solved CAPTCHA for a website
// it really sent there, so the CAPTCHA domain can never send people on to
// a site that is not hosted here (an open redirect).

const captchaSentFor = 2 * time.Hour

type captchaSent struct {
	mu sync.Mutex
	at map[string]time.Time
}

var sentToCaptcha captchaSent

// NormHost is host without a port, a trailing dot or upper case ("" if it
// is not a plain host name or address).
func NormHost(host string) string {
	h := strings.ToLower(strings.TrimSpace(host))
	if hh, _, err := net.SplitHostPort(h); err == nil {
		h = hh
	}
	h = strings.TrimSuffix(strings.Trim(h, "[]"), ".")
	if h == "" || strings.ContainsAny(h, "/?#@&=\\ ") {
		return ""
	}
	return h
}

func sentKey(ip, host string) string {
	if a := net.ParseIP(strings.TrimSpace(ip)); a != nil {
		ip = a.String()
	}
	// The log may name the site with or without www.
	return ip + "|" + strings.TrimPrefix(NormHost(host), "www.")
}

// NoteCaptchaSent records a CAPTCHA redirect read from the logs.
func NoteCaptchaSent(ip, host string, now time.Time) {
	if ip == "" || NormHost(host) == "" {
		return
	}
	s := &sentToCaptcha
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.at == nil || len(s.at) > 100_000 {
		s.at = map[string]time.Time{}
	}
	if len(s.at)%1000 == 999 {
		for k, t := range s.at {
			if now.Sub(t) > captchaSentFor {
				delete(s.at, k)
			}
		}
	}
	s.at[sentKey(ip, host)] = now
}

// SentToCaptcha reports whether this server sent ip to the CAPTCHA page
// for host in the last two hours.
func SentToCaptcha(ip, host string) bool {
	s := &sentToCaptcha
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.at[sentKey(ip, host)]
	return ok && time.Since(t) <= captchaSentFor
}

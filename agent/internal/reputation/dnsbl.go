// Package reputation checks the server's IP addresses against DNS blocklists.
package reputation

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/store"
)

// Listing is one DNSBL answer.
type Listing struct {
	RBL    string `json:"rbl"`
	Listed bool   `json:"listed"`
	Answer string `json:"answer,omitempty"`
	Error  string `json:"error,omitempty"`
}

// Report is the result for one IP.
type Report struct {
	IP         string    `json:"ip"`
	CheckedAt  int64     `json:"checked_at"`
	DurationMs int64     `json:"duration_ms"`
	ListedOn   int       `json:"listed_on"`
	Checked    int       `json:"checked"`
	Results    []Listing `json:"results"`
}

// Query builds the DNSBL query name (reversed octets / nibbles + zone).
func Query(ip, zone string) (string, error) {
	p := net.ParseIP(ip)
	if p == nil {
		return "", fmt.Errorf("invalid IP %q", ip)
	}
	if v4 := p.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.%d.%s", v4[3], v4[2], v4[1], v4[0], zone), nil
	}
	const hex = "0123456789abcdef"
	var b strings.Builder
	for i := len(p) - 1; i >= 0; i-- {
		b.WriteByte(hex[p[i]&0xf])
		b.WriteByte('.')
		b.WriteByte(hex[p[i]>>4])
		b.WriteByte('.')
	}
	return b.String() + zone, nil
}

// Resolver is swappable for tests.
type Resolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// Check queries every RBL for ip concurrently.
func Check(ctx context.Context, r Resolver, ip string, rbls []string) Report {
	start := time.Now()
	rep := Report{IP: ip, CheckedAt: start.Unix(), Results: make([]Listing, len(rbls))}
	var wg sync.WaitGroup
	sem := make(chan struct{}, 16)
	for i, zone := range rbls {
		wg.Add(1)
		go func(i int, zone string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			l := Listing{RBL: zone}
			q, err := Query(ip, zone)
			if err != nil {
				l.Error = err.Error()
				rep.Results[i] = l
				return
			}
			qctx, cancel := context.WithTimeout(ctx, 8*time.Second)
			defer cancel()
			addrs, err := r.LookupHost(qctx, q)
			switch {
			case err == nil && len(addrs) > 0:
				// 127.0.0.x means listed; other answers (e.g. 127.255.255.254) are
				// "query refused/rate limited" responses and are not listings.
				a := addrs[0]
				if strings.HasPrefix(a, "127.0.0.") || strings.HasPrefix(a, "127.0.1.") {
					l.Listed, l.Answer = true, a
				} else {
					l.Error = "blocklist refused the query (" + a + ")"
				}
			case err != nil:
				if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
					break // not listed
				}
				l.Error = "lookup failed"
			}
			rep.Results[i] = l
		}(i, zone)
	}
	wg.Wait()
	for _, l := range rep.Results {
		if l.Error == "" {
			rep.Checked++
		}
		if l.Listed {
			rep.ListedOn++
		}
	}
	rep.DurationMs = time.Since(start).Milliseconds()
	return rep
}

// Save stores the latest report per IP.
func Save(db *sql.DB, rep Report) error {
	b, err := json.Marshal(rep)
	if err != nil {
		return err
	}
	return store.SetKV(db, "rbl:"+rep.IP, string(b))
}

// Load returns the stored report for ip (nil if never checked).
func Load(db *sql.DB, ip string) *Report {
	raw := store.GetKV(db, "rbl:"+ip)
	if raw == "" {
		return nil
	}
	var r Report
	if json.Unmarshal([]byte(raw), &r) != nil {
		return nil
	}
	return &r
}

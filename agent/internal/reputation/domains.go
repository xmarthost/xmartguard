package reputation

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/store"
)

// DomainZone is a DNS domain blocklist with its answer codes.
type DomainZone struct {
	Zone string
	// Reason for an answer address; answers not in the map are ignored
	// (they mean "query refused" or "not listed").
	Codes func(answer string) string
}

// DomainZones are free domain blocklists (low volume use).
var DomainZones = []DomainZone{
	{"dbl.spamhaus.org", func(a string) string {
		switch a {
		case "127.0.1.2":
			return "SPAM (Spamhaus DBL)"
		case "127.0.1.4":
			return "PHISHING (Spamhaus DBL)"
		case "127.0.1.5":
			return "MALWARE (Spamhaus DBL)"
		case "127.0.1.6":
			return "BOTNET_C2 (Spamhaus DBL)"
		case "127.0.1.102", "127.0.1.103", "127.0.1.104", "127.0.1.105", "127.0.1.106":
			return "ABUSED_LEGIT_DOMAIN (Spamhaus DBL)"
		}
		return ""
	}},
	{"multi.surbl.org", func(a string) string {
		ip := net.ParseIP(a).To4()
		if ip == nil || ip[0] != 127 || ip[1] != 0 || ip[2] != 0 {
			return ""
		}
		var r []string
		for bit, name := range map[byte]string{8: "PHISHING", 16: "MALWARE", 64: "ABUSE", 128: "CRACKED"} {
			if ip[3]&bit != 0 {
				r = append(r, name)
			}
		}
		sort.Strings(r)
		if len(r) == 0 {
			return ""
		}
		return strings.Join(r, ",") + " (SURBL)"
	}},
	{"multi.uribl.com", func(a string) string {
		ip := net.ParseIP(a).To4()
		if ip == nil || ip[0] != 127 || ip[1] != 0 || ip[2] != 0 || ip[3] == 1 {
			return "" // 127.0.0.1 = query blocked
		}
		if ip[3]&2 != 0 {
			return "SPAM (URIBL black)"
		}
		return ""
	}},
}

// HostedDomains reads /etc/userdomains (domain: user), skipping the catch-all.
func HostedDomains(path string) map[string]string {
	out := map[string]string{}
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		d, u, ok := strings.Cut(sc.Text(), ":")
		d, u = strings.TrimSpace(strings.ToLower(d)), strings.TrimSpace(u)
		if !ok || d == "" || d == "*" || u == "nobody" || strings.HasPrefix(d, "*.") {
			continue
		}
		out[d] = u
	}
	return out
}

// DomainResult is the reputation of one domain.
type DomainResult struct {
	Domain    string   `json:"domain"`
	User      string   `json:"user"`
	Status    string   `json:"status"` // clean | listed | error
	Reasons   []string `json:"reasons"`
	CheckedAt int64    `json:"checked_at"`
}

// SafeBrowsingURL is the Google Safe Browsing v4 endpoint (tests override it).
var SafeBrowsingURL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

// safeBrowsing looks domains up in Google Safe Browsing (batched).
func safeBrowsing(ctx context.Context, key string, domains []string) (map[string][]string, error) {
	out := map[string][]string{}
	client := &http.Client{Timeout: 30 * time.Second}
	for i := 0; i < len(domains); i += 400 {
		end := min(i+400, len(domains))
		var entries []map[string]string
		for _, d := range domains[i:end] {
			entries = append(entries, map[string]string{"url": "http://" + d + "/"}, map[string]string{"url": "https://" + d + "/"})
		}
		body, _ := json.Marshal(map[string]any{
			"client": map[string]string{"clientId": "xmartguard", "clientVersion": "1"},
			"threatInfo": map[string]any{
				"threatTypes":      []string{"MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"},
				"platformTypes":    []string{"ANY_PLATFORM"},
				"threatEntryTypes": []string{"URL"},
				"threatEntries":    entries,
			},
		})
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, SafeBrowsingURL+"?key="+key, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		res, err := client.Do(req)
		if err != nil {
			return out, err
		}
		b, _ := io.ReadAll(io.LimitReader(res.Body, 8<<20))
		res.Body.Close()
		if res.StatusCode != 200 {
			return out, fmt.Errorf("safe browsing: HTTP %d", res.StatusCode)
		}
		var r struct {
			Matches []struct {
				ThreatType string `json:"threatType"`
				Threat     struct {
					URL string `json:"url"`
				} `json:"threat"`
			} `json:"matches"`
		}
		if err := json.Unmarshal(b, &r); err != nil {
			return out, err
		}
		for _, m := range r.Matches {
			d := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(m.Threat.URL, "https://"), "http://"), "/")
			out[d] = appendUnique(out[d], m.ThreatType+" (Google Safe Browsing)")
		}
	}
	return out, nil
}

func appendUnique(l []string, s string) []string {
	for _, x := range l {
		if x == s {
			return l
		}
	}
	return append(l, s)
}

// CheckDomains checks every domain and stores the results.
func CheckDomains(ctx context.Context, db *sql.DB, r Resolver, domains map[string]string, sbKey string) ([]DomainResult, error) {
	names := make([]string, 0, len(domains))
	for d := range domains {
		names = append(names, d)
	}
	sort.Strings(names)
	results := make([]DomainResult, len(names))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for i, d := range names {
		wg.Add(1)
		go func(i int, d string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			res := DomainResult{Domain: d, User: domains[d], Status: "clean", Reasons: []string{}, CheckedAt: store.Now()}
			failed := 0
			for _, z := range DomainZones {
				qctx, cancel := context.WithTimeout(ctx, 8*time.Second)
				addrs, err := r.LookupHost(qctx, d+"."+z.Zone)
				cancel()
				if err != nil {
					if dnsErr, ok := err.(*net.DNSError); !ok || !dnsErr.IsNotFound {
						failed++
					}
					continue
				}
				for _, a := range addrs {
					if reason := z.Codes(a); reason != "" {
						res.Reasons = appendUnique(res.Reasons, reason)
					}
				}
			}
			if len(res.Reasons) > 0 {
				res.Status = "listed"
			} else if failed == len(DomainZones) {
				res.Status = "error"
			}
			results[i] = res
		}(i, d)
	}
	wg.Wait()
	var sbErr error
	if sbKey != "" && len(names) > 0 {
		hits, err := safeBrowsing(ctx, sbKey, names)
		sbErr = err
		for i := range results {
			for _, reason := range hits[results[i].Domain] {
				results[i].Reasons = appendUnique(results[i].Reasons, reason)
				results[i].Status = "listed"
			}
		}
	}
	tx, err := db.Begin()
	if err != nil {
		return results, err
	}
	_, _ = tx.Exec(`DELETE FROM domain_reputation`)
	for _, r := range results {
		_, _ = tx.Exec(`INSERT INTO domain_reputation (domain, user, status, reasons, checked_at) VALUES (?,?,?,?,?)`,
			r.Domain, r.User, r.Status, strings.Join(r.Reasons, "; "), r.CheckedAt)
	}
	if err := tx.Commit(); err != nil {
		return results, err
	}
	return results, sbErr
}

// DomainSummary is the Domain Reputation page.
type DomainSummary struct {
	Total     int            `json:"total"`
	Flagged   int            `json:"flagged"`
	CheckedAt int64          `json:"checked_at"`
	Listed    []DomainResult `json:"listed"`
	Errors    int            `json:"errors"`
}

// LoadDomains returns stored results (listed domains first).
func LoadDomains(db *sql.DB, q string, limit, offset int) (DomainSummary, []DomainResult, int, error) {
	var s DomainSummary
	_ = db.QueryRow(`SELECT count(*), coalesce(max(checked_at),0) FROM domain_reputation`).Scan(&s.Total, &s.CheckedAt)
	_ = db.QueryRow(`SELECT count(*) FROM domain_reputation WHERE status = 'listed'`).Scan(&s.Flagged)
	_ = db.QueryRow(`SELECT count(*) FROM domain_reputation WHERE status = 'error'`).Scan(&s.Errors)
	s.Listed = []DomainResult{}
	if rows, err := db.Query(`SELECT domain, user, reasons FROM domain_reputation WHERE status = 'listed' ORDER BY domain LIMIT 20`); err == nil {
		for rows.Next() {
			r := DomainResult{Status: "listed"}
			var reasons string
			if rows.Scan(&r.Domain, &r.User, &reasons) == nil {
				r.Reasons = strings.Split(reasons, "; ")
				s.Listed = append(s.Listed, r)
			}
		}
		rows.Close()
	}
	where, args := "1=1", []any{}
	if q != "" {
		where, args = "(domain LIKE ? OR user LIKE ?)", []any{"%" + q + "%", "%" + q + "%"}
	}
	if limit <= 0 || limit > 500 {
		limit = 25
	}
	var total int
	_ = db.QueryRow(`SELECT count(*) FROM domain_reputation WHERE `+where, args...).Scan(&total)
	rows, err := db.Query(`SELECT domain, user, status, reasons, checked_at FROM domain_reputation WHERE `+where+
		` ORDER BY CASE status WHEN 'listed' THEN 0 WHEN 'error' THEN 1 ELSE 2 END, domain LIMIT ? OFFSET ?`, append(args, limit, offset)...)
	if err != nil {
		return s, nil, 0, err
	}
	defer rows.Close()
	out := []DomainResult{}
	for rows.Next() {
		var r DomainResult
		var reasons string
		if err := rows.Scan(&r.Domain, &r.User, &r.Status, &reasons, &r.CheckedAt); err != nil {
			return s, nil, 0, err
		}
		r.Reasons = []string{}
		if reasons != "" {
			r.Reasons = strings.Split(reasons, "; ")
		}
		out = append(out, r)
	}
	return s, out, total, rows.Err()
}

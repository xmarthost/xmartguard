package firewall

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// GeoURL is the per-country aggregated IPv4 zone source (ipdeny.com).
var GeoURL = "https://www.ipdeny.com/ipblocks/data/aggregated/%s-aggregated.zone"

// Geo caches country CIDR lists under <dir>.
type Geo struct {
	Dir string
	Log *slog.Logger

	mu    sync.Mutex
	cache map[string][]string
}

func (g *Geo) file(cc string) string { return filepath.Join(g.Dir, strings.ToLower(cc)+".zone") }

// Refresh downloads lists that are missing (or all, when force).
func (g *Geo) Refresh(codes []string, force bool) {
	_ = os.MkdirAll(g.Dir, 0o700)
	client := &http.Client{Timeout: 60 * time.Second}
	for _, cc := range codes {
		cc = strings.ToLower(cc)
		if st, err := os.Stat(g.file(cc)); err == nil && !force && time.Since(st.ModTime()) < 7*24*time.Hour {
			continue
		}
		res, err := client.Get(fmt.Sprintf(GeoURL, cc))
		if err != nil {
			g.Log.Warn("country list download failed", "country", cc, "err", err)
			continue
		}
		body, err := io.ReadAll(io.LimitReader(res.Body, 20<<20))
		res.Body.Close()
		if err != nil || res.StatusCode != 200 || len(body) == 0 {
			g.Log.Warn("country list download failed", "country", cc, "status", res.StatusCode)
			continue
		}
		tmp := g.file(cc) + ".tmp"
		if os.WriteFile(tmp, body, 0o600) == nil {
			_ = os.Rename(tmp, g.file(cc))
		}
		g.mu.Lock()
		delete(g.cache, cc)
		g.mu.Unlock()
	}
}

func (g *Geo) load(cc string) []string {
	cc = strings.ToLower(cc)
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.cache == nil {
		g.cache = map[string][]string{}
	}
	if c, ok := g.cache[cc]; ok {
		return c
	}
	f, err := os.Open(g.file(cc))
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if _, _, err := net.ParseCIDR(line); err == nil && !strings.Contains(line, ":") {
			out = append(out, line)
		}
	}
	g.cache[cc] = out
	return out
}

// CIDRs returns the union of the given countries' networks (downloading as needed).
func (g *Geo) CIDRs(codes []string) []string {
	if len(codes) == 0 {
		return nil
	}
	g.Refresh(codes, false)
	var out []string
	for _, cc := range codes {
		out = append(out, g.load(cc)...)
	}
	return out
}

// Lookup returns which of the given countries contains ip ("" if none).
func (g *Geo) Lookup(ip string, codes []string) string {
	p := net.ParseIP(ip)
	if p == nil {
		return ""
	}
	for _, cc := range codes {
		for _, c := range g.load(cc) {
			if _, n, err := net.ParseCIDR(c); err == nil && n.Contains(p) {
				return strings.ToUpper(cc)
			}
		}
	}
	return ""
}

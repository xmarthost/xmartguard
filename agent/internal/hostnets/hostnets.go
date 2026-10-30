// Package hostnets keeps the networks of hosting, cloud and VPS companies.
// Stolen WordPress passwords are used from servers rented there (server1,
// 2026-10-28: six logins with known passwords from six such addresses,
// each the first POST), while a site's owner logs in from a home, office
// or mobile network. A login page visited from these networks gets the
// CAPTCHA first (central CAPTCHA, waf.Central.Hosting); nothing else on
// the websites changes.
//
// Routes come from the RADb registry by AS number, refreshed daily and
// cached on disk. RADb is not authoritative (anyone can register a route),
// so only routes of a normal size count and a bad entry costs at most a
// CAPTCHA on a login page.
package hostnets

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/store"
	"github.com/xmarthost/xmartguard/agent/internal/trusted"
)

// ASNs are hosting, cloud and VPS networks (no consumer ISPs, CDNs or
// search engines: Googlebot's AS15169 and Cloudflare's AS13335 are not
// here).
var ASNs = []string{
	"AS16509", "AS14618", // Amazon AWS
	"AS396982",            // Google Cloud
	"AS8075",              // Microsoft Azure
	"AS31898",             // Oracle Cloud
	"AS14061", "AS200130", // DigitalOcean
	"AS63949",             // Linode (Akamai)
	"AS20473",             // Vultr (Choopa)
	"AS24940", "AS213230", // Hetzner
	"AS16276",                       // OVH
	"AS51167",                       // Contabo
	"AS60781", "AS28753", "AS16265", // Leaseweb
	"AS9009",   // M247
	"AS12876",  // Scaleway
	"AS45102",  // Alibaba Cloud
	"AS132203", // Tencent Cloud
	"AS136907", // Huawei Cloud
	"AS8560",   // IONOS
	"AS47583",  // Hostinger
	"AS22612",  // Namecheap
	"AS26496",  // GoDaddy
	"AS46606",  // Unified Layer
	"AS60068",  // Datacamp / CDN77
	"AS40676",  // Psychz
	"AS36352",  // ColoCrossing
	"AS8100",   // QuadraNet
	"AS36007",  // Kamatera
	"AS53667",  // FranTech / BuyVM
	"AS54290",  // Hostwinds
	"AS44477",  // Stark Industries
	"AS210644", // Aeza
	"AS49505",  // Selectel
	"AS9123",   // Timeweb
	"AS62240",  // Clouvider
}

// Routes shorter than these are no single company's servers.
const minBits4, minBits6 = 12, 24

// RefreshEvery is how often the routes are read again.
var RefreshEvery = 24 * time.Hour

// Store holds the current networks.
type Store struct {
	mu   sync.Mutex
	nets []string
	at   time.Time
	// Routes replaces RADb in tests.
	Routes func(ctx context.Context, as string) ([]string, error)
}

func cachePath() string { return filepath.Join(store.StateDir(), "hostnets.json") }

type cache struct {
	At   int64    `json:"at"`
	Nets []string `json:"nets"`
}

// Load reads the cached networks.
func (s *Store) Load() {
	var c cache
	if raw, err := os.ReadFile(cachePath()); err == nil && json.Unmarshal(raw, &c) == nil {
		s.mu.Lock()
		s.nets, s.at = c.Nets, time.Unix(c.At, 0)
		s.mu.Unlock()
	}
}

// Nets are the networks (nil before the first refresh).
func (s *Store) Nets() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.nets
}

// Refresh reads every AS's routes when the copy is older than RefreshEvery;
// an AS that does not answer keeps nothing back (the others still count),
// and a refresh that read nothing keeps the old copy.
func (s *Store) Refresh(ctx context.Context) bool {
	s.mu.Lock()
	fresh := time.Since(s.at) < RefreshEvery
	s.mu.Unlock()
	if fresh {
		return false
	}
	routes := s.Routes
	if routes == nil {
		routes = trusted.RADBRoutes
	}
	set := map[string]bool{}
	for _, as := range ASNs {
		rctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		raw, err := routes(rctx, as)
		cancel()
		if err != nil {
			continue
		}
		for _, r := range raw {
			if ok := normal(r); ok != "" {
				set[ok] = true
			}
		}
	}
	if len(set) == 0 {
		return false
	}
	out := aggregate(set)
	s.mu.Lock()
	s.nets, s.at = out, time.Now()
	s.mu.Unlock()
	if b, err := json.Marshal(cache{At: time.Now().Unix(), Nets: out}); err == nil {
		_ = os.MkdirAll(filepath.Dir(cachePath()), 0o700)
		_ = os.WriteFile(cachePath(), b, 0o600)
	}
	return true
}

// MaxNets caps the list (every web server process loads it).
const MaxNets = 60000

// aggregate drops routes inside another route of the set (AWS and Azure
// announce many more specific routes) and keeps at most MaxNets, widest
// first.
func aggregate(set map[string]bool) []string {
	type route struct {
		n    *net.IPNet
		bits int
		s    string
	}
	var rs []route
	for c := range set {
		if _, n, err := net.ParseCIDR(c); err == nil {
			b, _ := n.Mask.Size()
			rs = append(rs, route{n, b, c})
		}
	}
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].bits != rs[j].bits {
			return rs[i].bits < rs[j].bits
		}
		return rs[i].s < rs[j].s
	})
	kept := map[string]bool{}
	var out []string
	for _, r := range rs {
		_, size := r.n.Mask.Size()
		inside := false
		for b := r.bits - 1; b >= 8 && !inside; b-- {
			p := &net.IPNet{IP: r.n.IP.Mask(net.CIDRMask(b, size)), Mask: net.CIDRMask(b, size)}
			inside = kept[p.String()]
		}
		if inside {
			continue
		}
		kept[r.s] = true
		out = append(out, r.s)
		if len(out) == MaxNets {
			break
		}
	}
	sort.Strings(out)
	return out
}

// normal returns a route in canonical form, or "" when it is too wide.
func normal(r string) string {
	_, n, err := net.ParseCIDR(r)
	if err != nil {
		return ""
	}
	bits, size := n.Mask.Size()
	if size == 32 && bits < minBits4 || size == 128 && bits < minBits6 {
		return ""
	}
	return n.String()
}

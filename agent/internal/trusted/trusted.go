// Package trusted keeps the addresses of services a hosting server must
// never block: search engine crawlers (SEO), uptime monitors, CDN and
// payment callbacks, and the vendors' own update servers. The firewall
// exempts them from every block (IPDB, bans, country blocks), automatic
// bans skip them, and the WAF's bot rules do not apply to them.
//
// Lists come from each provider's official published source and are
// refreshed daily; a built-in copy is used until the first refresh (or when
// a source is unreachable). Services without a published list are
// resolved from their host names.
package trusted

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Service is one trusted service.
type Service struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Group string `json:"group"` // search, monitor, cdn, payment, vendor
	// URL of the official list and its format: "prefixes" (Google/Bing
	// JSON), "lines" (one address or CIDR per line).
	URL    string   `json:"url,omitempty"`
	Format string   `json:"-"`
	Hosts  []string `json:"hosts,omitempty"` // resolved when there is no list
	// Builtin is used until a refresh succeeds.
	Builtin []string `json:"-"`
}

// Services are the built-in trusted services.
var Services = []Service{
	{ID: "googlebot", Name: "Googlebot (Google Search)", Group: "search", Format: "prefixes",
		URL:     "https://developers.google.com/static/search/apis/ipranges/googlebot.json",
		Builtin: []string{"66.249.64.0/19"}},
	{ID: "google-special", Name: "Google special crawlers (AdsBot, Site Verification, Inspection Tool)", Group: "search", Format: "prefixes",
		URL: "https://developers.google.com/static/search/apis/ipranges/special-crawlers.json"},
	{ID: "google-fetchers", Name: "Google user-triggered fetchers (Feedfetcher, Site Verifier)", Group: "search", Format: "prefixes",
		URL: "https://developers.google.com/static/search/apis/ipranges/user-triggered-fetchers.json"},
	{ID: "bingbot", Name: "Bingbot (Microsoft Bing)", Group: "search", Format: "prefixes",
		URL:     "https://www.bing.com/toolbox/bingbot.json",
		Builtin: []string{"157.55.39.0/24", "207.46.13.0/24", "40.77.167.0/24"}},
	{ID: "applebot", Name: "Applebot (Siri, Spotlight)", Group: "search", Format: "prefixes",
		URL: "https://search.developer.apple.com/applebot.json"},
	{ID: "duckduckbot", Name: "DuckDuckBot (DuckDuckGo)", Group: "search", Format: "prefixes",
		URL: "https://duckduckgo.com/duckduckbot.json"},
	{ID: "uptimerobot", Name: "UptimeRobot", Group: "monitor", Format: "lines",
		URL: "https://uptimerobot.com/inc/files/ips/IPv4andIPv6.txt"},
	{ID: "pingdom", Name: "Pingdom", Group: "monitor", Format: "lines",
		URL: "https://my.pingdom.com/probes/ipv4"},
	{ID: "statuscake", Name: "StatusCake", Group: "monitor", Format: "lines",
		URL: "https://app.statuscake.com/Workfloor/Locations.php?format=txt"},
	{ID: "betterstack", Name: "Better Stack Uptime", Group: "monitor", Format: "lines",
		URL: "https://uptime.betterstack.com/ips.txt"},
	{ID: "cloudflare", Name: "Cloudflare (CDN, proxied sites)", Group: "cdn", Format: "lines",
		URL: "https://www.cloudflare.com/ips-v4",
		Builtin: []string{"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
			"190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
			"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22", "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
			"2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32"}},
	{ID: "stripe", Name: "Stripe webhooks", Group: "payment", Format: "lines",
		URL: "https://stripe.com/files/ips/ips_webhooks.txt"},
	{ID: "paypal", Name: "PayPal IPN / webhooks", Group: "payment",
		Hosts: []string{"ipnpb.paypal.com", "notify.paypal.com", "api.paypal.com", "ipn.sandbox.paypal.com"}},
	{ID: "jetpack", Name: "Jetpack / WordPress.com", Group: "vendor",
		Builtin: []string{"122.248.245.244/32", "54.217.201.243/32", "54.232.116.4/32", "192.0.80.0/20", "192.0.96.0/20", "192.0.112.0/20", "195.234.108.0/22"}},
	{ID: "softaculous", Name: "Softaculous", Group: "vendor",
		Hosts: []string{"www.softaculous.com", "api.softaculous.com", "s1.softaculous.com", "s2.softaculous.com", "s3.softaculous.com", "s4.softaculous.com"}},
	{ID: "cpanel", Name: "cPanel update and license servers", Group: "vendor",
		Hosts: []string{"httpupdate.cpanel.net", "verify.cpanel.net", "auth.cpanel.net", "store.cpanel.net"}},
}

// State is one service's current list.
type State struct {
	Service
	CIDRs   []string `json:"cidrs"`
	Source  string   `json:"source"` // "official", "dns", "builtin", "none"
	Updated int64    `json:"updated"`
	Error   string   `json:"error,omitempty"`
}

// Store holds the lists (cached on disk between restarts).
type Store struct {
	Path   string // cache file
	Client *http.Client
	// Resolve looks host names up (tests override it).
	Resolve func(ctx context.Context, host string) ([]string, error)

	mu    sync.RWMutex
	state map[string]State
	set   []*net.IPNet
}

// New loads the cache (or the built-in lists).
func New(path string) *Store {
	s := &Store{Path: path, Client: &http.Client{Timeout: 30 * time.Second},
		Resolve: func(ctx context.Context, h string) ([]string, error) { return net.DefaultResolver.LookupHost(ctx, h) }}
	s.load()
	return s
}

func (s *Store) load() {
	st := map[string]State{}
	if b, err := os.ReadFile(s.Path); err == nil {
		var saved []State
		if json.Unmarshal(b, &saved) == nil {
			for _, x := range saved {
				st[x.ID] = x
			}
		}
	}
	for _, svc := range Services {
		cur, ok := st[svc.ID]
		if !ok || len(cur.CIDRs) == 0 {
			cur = State{CIDRs: clean(svc.Builtin), Source: "builtin"}
			if len(cur.CIDRs) == 0 {
				cur.Source = "none"
			}
		}
		cur.Service = svc
		st[svc.ID] = cur
	}
	s.mu.Lock()
	s.state = st
	s.rebuild()
	s.mu.Unlock()
}

// rebuild recomputes the lookup set (caller holds mu).
func (s *Store) rebuild() {
	s.set = s.set[:0]
	for _, x := range s.state {
		for _, c := range x.CIDRs {
			if _, n, err := net.ParseCIDR(toCIDR(c)); err == nil {
				s.set = append(s.set, n)
			}
		}
	}
}

func toCIDR(a string) string {
	if strings.Contains(a, "/") {
		return a
	}
	if strings.Contains(a, ":") {
		return a + "/128"
	}
	return a + "/32"
}

// clean keeps valid addresses and networks, normalised and sorted.
func clean(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, a := range in {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		if ip := net.ParseIP(a); ip != nil {
			a = ip.String()
		} else if _, n, err := net.ParseCIDR(a); err == nil {
			ones, bits := n.Mask.Size()
			// A trusted range wider than /8 (v4) or /16 (v6) is refused: no
			// real crawler list needs it and it would exempt half the Internet.
			if (bits == 32 && ones < 8) || (bits == 128 && ones < 16) {
				continue
			}
			a = n.String()
		} else {
			continue
		}
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	sort.Strings(out)
	return out
}

// parsePrefixes reads Google/Bing/Apple style JSON.
func parsePrefixes(b []byte) ([]string, error) {
	var doc struct {
		Prefixes []struct {
			V4 string `json:"ipv4Prefix"`
			V6 string `json:"ipv6Prefix"`
		} `json:"prefixes"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	var out []string
	for _, p := range doc.Prefixes {
		if p.V4 != "" {
			out = append(out, p.V4)
		}
		if p.V6 != "" {
			out = append(out, p.V6)
		}
	}
	return out, nil
}

// parseLines reads one address per line (commas and spaces also split).
func parseLines(b []byte) []string {
	var out []string
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	for sc.Scan() {
		l := sc.Text()
		if i := strings.IndexByte(l, '#'); i >= 0 {
			l = l[:i]
		}
		out = append(out, strings.FieldsFunc(l, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == ';' })...)
	}
	return out
}

func (s *Store) fetch(ctx context.Context, svc Service) ([]string, string, error) {
	if svc.URL != "" {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, svc.URL, nil)
		req.Header.Set("User-Agent", "XMartGuard-Agent (trusted services list)")
		resp, err := s.Client.Do(req)
		if err != nil {
			return nil, "", err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, "", fmt.Errorf("%s: HTTP %d", svc.URL, resp.StatusCode)
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		if err != nil {
			return nil, "", err
		}
		var raw []string
		if svc.Format == "prefixes" {
			if raw, err = parsePrefixes(b); err != nil {
				return nil, "", err
			}
		} else {
			raw = parseLines(b)
		}
		// Cloudflare publishes IPv6 separately.
		if svc.ID == "cloudflare" {
			if v6, _, err := s.fetch(ctx, Service{ID: "cloudflare-v6", URL: "https://www.cloudflare.com/ips-v6", Format: "lines"}); err == nil {
				raw = append(raw, v6...)
			}
		}
		if svc.ID == "pingdom" {
			if v6, _, err := s.fetch(ctx, Service{ID: "pingdom-v6", URL: "https://my.pingdom.com/probes/ipv6", Format: "lines"}); err == nil {
				raw = append(raw, v6...)
			}
		}
		return raw, "official", nil
	}
	if len(svc.Hosts) > 0 {
		var raw []string
		var lastErr error
		for _, h := range svc.Hosts {
			a, err := s.Resolve(ctx, h)
			if err != nil {
				lastErr = err
				continue
			}
			raw = append(raw, a...)
		}
		if len(raw) == 0 && lastErr != nil {
			return nil, "", lastErr
		}
		return raw, "dns", nil
	}
	return svc.Builtin, "builtin", nil
}

// Refresh downloads every list; a failed source keeps its previous list.
// It reports whether anything changed.
func (s *Store) Refresh(ctx context.Context) bool {
	changed := false
	for _, svc := range Services {
		raw, src, err := s.fetch(ctx, svc)
		cidrs := clean(raw)
		s.mu.Lock()
		cur := s.state[svc.ID]
		if err != nil || len(cidrs) == 0 {
			if err == nil {
				err = errors.New("the list was empty")
			}
			cur.Error = err.Error()
		} else {
			if strings.Join(cidrs, ",") != strings.Join(cur.CIDRs, ",") {
				changed = true
			}
			cur.CIDRs, cur.Source, cur.Updated, cur.Error = cidrs, src, time.Now().Unix(), ""
		}
		cur.Service = svc
		s.state[svc.ID] = cur
		s.mu.Unlock()
	}
	s.mu.Lock()
	s.rebuild()
	list := make([]State, 0, len(s.state))
	for _, x := range s.state {
		list = append(list, x)
	}
	s.mu.Unlock()
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	if b, err := json.Marshal(list); err == nil {
		_ = os.MkdirAll(filepath.Dir(s.Path), 0o700)
		_ = os.WriteFile(s.Path, b, 0o600)
	}
	return changed
}

// CIDRs returns the addresses of the enabled services (disabled: IDs off).
func (s *Store) CIDRs(disabled []string) []string {
	off := map[string]bool{}
	for _, d := range disabled {
		off[d] = true
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []string
	for _, svc := range Services {
		if !off[svc.ID] {
			out = append(out, s.state[svc.ID].CIDRs...)
		}
	}
	return clean(out)
}

// Match reports the trusted service an address belongs to ("" = none).
func (s *Store) Match(ip string, disabled []string) string {
	p := net.ParseIP(ip)
	if p == nil {
		return ""
	}
	off := map[string]bool{}
	for _, d := range disabled {
		off[d] = true
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, svc := range Services {
		if off[svc.ID] {
			continue
		}
		for _, c := range s.state[svc.ID].CIDRs {
			if _, n, err := net.ParseCIDR(toCIDR(c)); err == nil && n.Contains(p) {
				return svc.Name
			}
		}
	}
	return ""
}

// Status lists every service with its current list size.
func (s *Store) Status(disabled []string) []map[string]any {
	off := map[string]bool{}
	for _, d := range disabled {
		off[d] = true
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []map[string]any{}
	for _, svc := range Services {
		x := s.state[svc.ID]
		out = append(out, map[string]any{"id": svc.ID, "name": svc.Name, "group": svc.Group, "enabled": !off[svc.ID],
			"addresses": len(x.CIDRs), "source": x.Source, "updated": x.Updated, "error": x.Error})
	}
	return out
}

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
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Service is one trusted service.
type Service struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Group string `json:"group"` // search, social, ai, monitor, cdn, payment, wordpress, vendor
	// URL of the official list and its format: "prefixes" (Google/Bing
	// JSON), "lines" (one address or CIDR per line), "scan" (any JSON or
	// text: every address in it), "radb" (URL is an AS number; its routes
	// are read from the RADb routing registry).
	URL    string   `json:"url,omitempty"`
	Format string   `json:"-"`
	Hosts  []string `json:"hosts,omitempty"` // resolved when there is no list
	// Builtin is used until a refresh succeeds.
	Builtin []string `json:"-"`
}

// Services are the built-in trusted services: what hosting security
// products (Imunify360, BitNinja) allow by default, plus AI assistants and
// MCP clients. Each comes from the provider's official list when there is
// one; otherwise from the provider's network (RADb) or host names.
var Services = []Service{
	// Search engines (SEO).
	{ID: "googlebot", Name: "Googlebot (Google Search)", Group: "search", Format: "prefixes",
		URL:     "https://developers.google.com/static/search/apis/ipranges/googlebot.json",
		Builtin: []string{"66.249.64.0/19"}},
	{ID: "google-special", Name: "Google special crawlers (AdsBot, Site Verification, Inspection Tool)", Group: "search", Format: "prefixes",
		URL: "https://developers.google.com/static/search/apis/ipranges/special-crawlers.json"},
	{ID: "google-fetchers", Name: "Google user-triggered fetchers (Feedfetcher, Site Verifier, Read Aloud)", Group: "search", Format: "prefixes",
		URL: "https://developers.google.com/static/search/apis/ipranges/user-triggered-fetchers.json"},
	{ID: "google-fetchers-google", Name: "Google-owned user-triggered fetchers", Group: "search", Format: "prefixes",
		URL: "https://developers.google.com/static/search/apis/ipranges/user-triggered-fetchers-google.json"},
	{ID: "bingbot", Name: "Bingbot (Microsoft Bing, Copilot)", Group: "search", Format: "prefixes",
		URL:     "https://www.bing.com/toolbox/bingbot.json",
		Builtin: []string{"157.55.39.0/24", "207.46.13.0/24", "40.77.167.0/24"}},
	{ID: "applebot", Name: "Applebot (Siri, Spotlight)", Group: "search", Format: "prefixes",
		URL: "https://search.developer.apple.com/applebot.json"},
	{ID: "duckduckbot", Name: "DuckDuckBot (DuckDuckGo)", Group: "search", Format: "prefixes",
		URL: "https://duckduckgo.com/duckduckbot.json"},
	{ID: "yandex", Name: "YandexBot (Yandex)", Group: "search", Format: "radb", URL: "AS13238",
		Builtin: []string{"5.45.192.0/18", "5.255.192.0/18", "37.9.64.0/18", "37.140.128.0/18", "77.88.0.0/18", "84.252.160.0/19",
			"87.250.224.0/19", "90.156.176.0/22", "93.158.128.0/18", "95.108.128.0/17", "141.8.128.0/18", "178.154.128.0/18",
			"199.21.96.0/22", "213.180.192.0/19", "2a02:6b8::/32"}},
	{ID: "baidu", Name: "Baiduspider (Baidu)", Group: "search",
		Builtin: []string{"116.179.32.0/24", "116.179.37.0/24", "123.125.71.0/24", "180.76.5.0/24", "180.76.15.0/24",
			"220.181.108.0/24", "111.206.198.0/24", "111.206.221.0/24", "220.181.124.0/24"}},

	// Social networks: link previews when a page is shared.
	{ID: "meta", Name: "Meta: Facebook, Instagram, WhatsApp link previews (facebookexternalhit)", Group: "social", Format: "radb", URL: "AS32934",
		Builtin: []string{"31.13.24.0/21", "31.13.64.0/18", "45.64.40.0/22", "66.220.144.0/20", "69.63.176.0/20", "69.171.224.0/19",
			"74.119.76.0/22", "102.132.96.0/20", "103.4.96.0/22", "129.134.0.0/16", "157.240.0.0/16", "163.70.128.0/17",
			"173.252.64.0/18", "179.60.192.0/22", "185.60.216.0/22", "185.89.216.0/22", "204.15.20.0/22", "2a03:2880::/29", "2620:0:1c00::/40"}},
	{ID: "telegram", Name: "Telegram (link previews, bot webhooks)", Group: "social", Format: "lines",
		URL:     "https://core.telegram.org/resources/cidr.txt",
		Builtin: []string{"91.108.4.0/22", "91.108.8.0/22", "91.108.12.0/22", "91.108.16.0/22", "91.108.20.0/22", "91.108.56.0/22", "95.161.64.0/20", "149.154.160.0/20", "185.76.151.0/24", "2001:67c:4e8::/48", "2001:b28:f23c::/47", "2001:b28:f23f::/48", "2a0a:f280::/32"}},

	// AI assistants and MCP clients: answers that open a page, and tool
	// calls to MCP servers hosted on the sites.
	{ID: "anthropic", Name: "Claude (Anthropic): MCP connectors, web fetch", Group: "ai",
		Builtin: []string{"160.79.104.0/21"}},
	{ID: "openai-chatgpt-user", Name: "ChatGPT (OpenAI): user actions, GPT actions, connectors", Group: "ai", Format: "prefixes",
		URL: "https://openai.com/chatgpt-user.json"},
	{ID: "openai-searchbot", Name: "OAI-SearchBot (ChatGPT search)", Group: "ai", Format: "prefixes",
		URL: "https://openai.com/searchbot.json"},
	{ID: "openai-gptbot", Name: "GPTBot (OpenAI crawler)", Group: "ai", Format: "prefixes",
		URL: "https://openai.com/gptbot.json"},
	{ID: "perplexity-user", Name: "Perplexity-User (Perplexity answers)", Group: "ai", Format: "prefixes",
		URL: "https://www.perplexity.com/perplexity-user.json"},
	{ID: "perplexitybot", Name: "PerplexityBot (Perplexity search)", Group: "ai", Format: "prefixes",
		URL: "https://www.perplexity.com/perplexitybot.json"},

	// Uptime monitors.
	{ID: "uptimerobot", Name: "UptimeRobot", Group: "monitor", Format: "lines",
		URL: "https://uptimerobot.com/inc/files/ips/IPv4andIPv6.txt"},
	{ID: "pingdom", Name: "Pingdom", Group: "monitor", Format: "lines",
		URL: "https://my.pingdom.com/probes/ipv4"},
	{ID: "statuscake", Name: "StatusCake", Group: "monitor", Format: "lines",
		URL: "https://app.statuscake.com/Workfloor/Locations.php?format=txt"},
	{ID: "betterstack", Name: "Better Stack Uptime", Group: "monitor", Format: "lines",
		URL: "https://uptime.betterstack.com/ips.txt"},
	{ID: "hetrixtools", Name: "HetrixTools", Group: "monitor", Format: "lines",
		URL: "https://hetrixtools.com/resources/uptime-monitor-ips.txt"},

	// CDNs and website firewalls in front of the sites: blocking one of
	// their addresses cuts off every visitor behind it.
	{ID: "cloudflare", Name: "Cloudflare (CDN, proxied sites)", Group: "cdn", Format: "lines",
		URL: "https://www.cloudflare.com/ips-v4",
		Builtin: []string{"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
			"190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
			"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22", "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
			"2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32"}},
	{ID: "quic-cloud", Name: "QUIC.cloud (LiteSpeed CDN)", Group: "cdn", Format: "scan",
		URL: "https://quic.cloud/ips?ln"},
	{ID: "fastly", Name: "Fastly", Group: "cdn", Format: "scan",
		URL: "https://api.fastly.com/public-ip-list"},
	{ID: "bunnycdn", Name: "Bunny CDN", Group: "cdn", Format: "scan",
		URL: "https://bunnycdn.com/api/system/edgeserverlist"},
	{ID: "cloudfront", Name: "Amazon CloudFront", Group: "cdn", Format: "scan",
		URL: "https://d7uri8nf7uskq.cloudfront.net/tools/list-cloudfront-ips"},
	{ID: "sucuri", Name: "Sucuri website firewall", Group: "cdn",
		Builtin: []string{"192.88.134.0/23", "185.93.228.0/22", "66.248.200.0/22", "208.109.0.0/22", "2a02:fe80::/29"}},
	{ID: "imperva", Name: "Imperva / Incapsula", Group: "cdn",
		Builtin: []string{"199.83.128.0/21", "198.143.32.0/19", "149.126.72.0/21", "103.28.248.0/22", "185.11.124.0/22", "192.230.64.0/18",
			"45.64.64.0/22", "107.154.0.0/16", "45.60.0.0/16", "45.223.0.0/16", "131.125.128.0/17", "2a02:e980::/29"}},

	// Payment callbacks (order confirmations).
	{ID: "stripe", Name: "Stripe webhooks", Group: "payment", Format: "lines",
		URL: "https://stripe.com/files/ips/ips_webhooks.txt"},
	{ID: "paypal", Name: "PayPal IPN / webhooks", Group: "payment",
		Hosts: []string{"ipnpb.paypal.com", "notify.paypal.com", "api.paypal.com", "ipn.sandbox.paypal.com"}},

	// WordPress and hosting vendors (updates, licenses, remote management).
	{ID: "jetpack", Name: "Jetpack / WordPress.com", Group: "wordpress",
		Builtin: []string{"122.248.245.244/32", "54.217.201.243/32", "54.232.116.4/32", "192.0.80.0/20", "192.0.96.0/20", "192.0.112.0/20", "195.234.108.0/22"}},
	{ID: "wordpress-org", Name: "WordPress.org (updates, plugins, themes)", Group: "wordpress",
		Hosts: []string{"api.wordpress.org", "downloads.wordpress.org", "wordpress.org", "s.w.org", "planet.wordpress.org"}},
	{ID: "woocommerce", Name: "WooCommerce.com (extension updates, licenses)", Group: "wordpress",
		Hosts: []string{"woocommerce.com", "api.woocommerce.com"}},
	{ID: "softaculous", Name: "Softaculous", Group: "vendor",
		Hosts: []string{"www.softaculous.com", "api.softaculous.com", "s1.softaculous.com", "s2.softaculous.com", "s3.softaculous.com", "s4.softaculous.com"}},
	{ID: "cpanel", Name: "cPanel update and license servers", Group: "vendor",
		Hosts: []string{"httpupdate.cpanel.net", "verify.cpanel.net", "auth.cpanel.net", "store.cpanel.net", "securedownloads.cpanel.net", "manage2.cpanel.net", "api.cpanel.net"}},
	{ID: "litespeed", Name: "LiteSpeed license and update servers", Group: "vendor",
		Hosts: []string{"license.litespeedtech.com", "license2.litespeedtech.com", "update.litespeedtech.com", "www.litespeedtech.com"}},
	{ID: "cloudlinux", Name: "CloudLinux / Imunify license and repositories", Group: "vendor",
		Hosts: []string{"cln.cloudlinux.com", "repo.cloudlinux.com", "repo.imunify360.cloudlinux.com"}},
	{ID: "malware-expert", Name: "Malware.Expert (rule and RBL servers)", Group: "vendor",
		Hosts: []string{"rules.malware.expert", "www.malware.expert"}},
}

// Groups whose addresses the WAF's bot rules also skip. CDN addresses carry
// every visitor of a proxied site, and AI crawlers follow the "Block AI
// crawlers" switch, so those two groups are only kept out of bans.
var wafGroups = map[string]bool{"search": true, "social": true, "monitor": true, "payment": true, "wordpress": true, "vendor": true, "custom": true}

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

	mu     sync.RWMutex
	state  map[string]State
	set    []*net.IPNet
	custom []string // the administrator's own trusted addresses (portal)
}

// CustomID names the administrator's own list.
const CustomID = "custom"

// SetCustom replaces the administrator's own trusted addresses.
func (s *Store) SetCustom(list []string) {
	s.mu.Lock()
	s.custom = clean(list)
	s.rebuild()
	s.mu.Unlock()
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
	for _, c := range s.custom {
		if _, n, err := net.ParseCIDR(toCIDR(c)); err == nil {
			s.set = append(s.set, n)
		}
	}
}

var (
	reIPv4 = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?\b`)
	reIPv6 = regexp.MustCompile(`[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?:/\d{1,3})?`)
)

// scanAddrs finds every address or network in a JSON or text document.
func scanAddrs(b []byte) []string {
	out := reIPv4.FindAllString(string(b), -1)
	for _, m := range reIPv6.FindAllString(string(b), -1) {
		if strings.Contains(m, "::") || strings.Count(m, ":") >= 7 {
			out = append(out, m)
		}
	}
	return out
}

// RADBAddr is the routing registry queried for "radb" services (tests
// point it at a local server).
var RADBAddr = "whois.radb.net:43"

// radbRoutes lists the routes an AS announces, from the RADb registry.
func radbRoutes(ctx context.Context, as string) ([]string, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", RADBAddr)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	} else {
		_ = c.SetDeadline(time.Now().Add(60 * time.Second))
	}
	if _, err := io.WriteString(c, "-i origin "+as+"\r\n"); err != nil {
		return nil, err
	}
	var out []string
	sc := bufio.NewScanner(io.LimitReader(c, 8<<20))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if ok && (k == "route" || k == "route6") {
			out = append(out, strings.TrimSpace(v))
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("RADb: no routes for %s", as)
	}
	return out, nil
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
	if svc.Format == "radb" {
		raw, err := radbRoutes(ctx, svc.URL)
		if err != nil {
			return nil, "", err
		}
		return raw, "official", nil
	}
	if svc.URL != "" {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, svc.URL, nil)
		req.Header.Set("User-Agent", "xPGuard-Agent (trusted services list)")
		req.Header.Set("Accept", "application/json, text/plain;q=0.9, */*;q=0.5")
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
		switch svc.Format {
		case "prefixes":
			if raw, err = parsePrefixes(b); err != nil {
				return nil, "", err
			}
		case "scan":
			raw = scanAddrs(b)
		default:
			raw = parseLines(b)
		}
		// Cloudflare publishes IPv6 separately.
		if svc.ID == "cloudflare" {
			if v6, _, err := s.fetch(ctx, Service{ID: "cloudflare-v6", URL: "https://www.cloudflare.com/ips-v6", Format: "lines"}); err == nil {
				raw = append(raw, v6...)
			}
		}
		if svc.ID == "bunnycdn" {
			if v6, _, err := s.fetch(ctx, Service{ID: "bunnycdn-v6", URL: "https://bunnycdn.com/api/system/edgeserverlist/ipv6", Format: "scan"}); err == nil {
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

// CIDRs returns the addresses of the enabled services (disabled: IDs off)
// and the administrator's own list. The firewall exempts all of them.
func (s *Store) CIDRs(disabled []string) []string { return s.cidrs(disabled, nil) }

// WAFCIDRs is CIDRs without the CDN and AI groups, for the WAF's bot rules.
func (s *Store) WAFCIDRs(disabled []string) []string { return s.cidrs(disabled, wafGroups) }

func (s *Store) cidrs(disabled []string, groups map[string]bool) []string {
	off := map[string]bool{}
	for _, d := range disabled {
		off[d] = true
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []string
	for _, svc := range Services {
		if !off[svc.ID] && (groups == nil || groups[svc.Group]) {
			out = append(out, s.state[svc.ID].CIDRs...)
		}
	}
	if !off[CustomID] {
		out = append(out, s.custom...)
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
	if !off[CustomID] {
		for _, c := range s.custom {
			if _, n, err := net.ParseCIDR(toCIDR(c)); err == nil && n.Contains(p) {
				return "your trusted list"
			}
		}
	}
	return ""
}

// Official reports whether a service's list came from its provider (not
// the built-in copy).
func (s *Store) Official(id string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state[id].Source == "official" && len(s.state[id].CIDRs) > 0
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
	if len(s.custom) > 0 {
		out = append(out, map[string]any{"id": CustomID, "name": "Your trusted addresses", "group": "custom", "enabled": !off[CustomID],
			"addresses": len(s.custom), "source": "portal"})
	}
	return out
}

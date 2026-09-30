package waf

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/xmarthost/xmartguard/agent/internal/settings"
	"github.com/xmarthost/xmartguard/agent/internal/store"
)

// Automatic false-positive protection. A request that real visitors of one
// website keep sending, and that one CRS rule keeps blocking, is almost
// always the website working as designed. When several clean visitors (not
// on the IPDB or a ban list, seen on no other website, blocked by no other
// rule) from different networks are blocked on the same path by the same
// rule, the rule is switched off for that website and path only. Attackers
// hit many websites, trip several rules and are on the lists, so they do
// not qualify; attack payloads still meet every other rule there.

// AutoExclusion is a learned (or suggested) false positive.
type AutoExclusion struct {
	settings.RuleExclusion
	Key     string `json:"key"`
	Where   string `json:"where,omitempty"` // where the rule matched (REQUEST_COOKIES:x)
	Sample  string `json:"sample,omitempty"`
	Msg     string `json:"msg,omitempty"`
	IPs     int    `json:"ips"`
	Hits    int    `json:"hits"`
	Learned int64  `json:"learned"`
	Expires int64  `json:"expires"`
	State   string `json:"state"` // active | suggested | rejected
}

const (
	kvAutoExcl = "waf_auto_exclusions"
	// Learning thresholds: distinct clean visitors (more for a whole
	// website) from at least two networks, over the last day.
	learnMinIPs     = 3
	learnMinIPsSite = 5
	learnMinNets    = 2
	learnWindow     = 24 * 3600
	learnKeep       = 30 * 86400
	learnPerDomain  = 20
)

// reProbePath: paths only scanners request; never learned.
var reProbePath = regexp.MustCompile(`(?i)(?:/\.|\.(?:env|git|sql|bak|old|orig|swp|ya?ml|ini|log|conf|cfg|sh|zip|tar|gz|rar|7z)$|wlwmanifest|phpinfo|config|credential|passwd|docker|\.\.|batch/v1|xmlrpc|wp-config|cgi-bin|/vendor/|\.aws|actuator|debug|setup-config|install\.php|eval-stdin|/wp-content/+(?:plugins|themes)/+[^/]+/+[^/]+\.php$)`)

// reVolatile: path segments that differ per request (ids, hashes, dates).
var reVolatile = regexp.MustCompile(`^(?:\d+|[0-9a-f]{16,}|[0-9a-f-]{32,36})$`)

// learnPath is the path prefix an exclusion covers: the request path up to
// its first volatile segment ("/wp-json/wp/v2/posts/912/autosaves" becomes
// "/wp-json/wp/v2/posts/"). "" means the whole website (the home page).
func learnPath(uri string) string {
	p := uri
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	p = regexp.MustCompile(`/{2,}`).ReplaceAllString(p, "/")
	segs := strings.Split(p, "/")
	for i, s := range segs {
		if i > 0 && reVolatile.MatchString(strings.ToLower(s)) {
			p = strings.Join(segs[:i], "/") + "/"
			break
		}
	}
	if p == "/" || p == "" {
		return ""
	}
	if !regexp.MustCompile(`^/[A-Za-z0-9._~/-]*$`).MatchString(p) || len(p) > 200 {
		return "-" // not learnable
	}
	return p
}

// parseScored reads "Matched rules: 942100 (ARGS:q), 941100".
func parseScored(detail string) (ids []int, where map[int]string) {
	where = map[int]string{}
	if !strings.HasPrefix(detail, ScoredPrefix) {
		return nil, where
	}
	for _, m := range regexp.MustCompile(`(\d{6,7})(?: \(([^)]*)\))?`).FindAllStringSubmatch(detail[len(ScoredPrefix):], -1) {
		n, _ := strconv.Atoi(m[1])
		ids = append(ids, n)
		if m[2] != "" {
			where[n] = m[2]
		}
	}
	return ids, where
}

// learnable are the CRS rules a false positive may be learned for: the
// method, protocol and attack rules, not the scanner or score rules.
func learnable(id int) bool {
	return id >= 911000 && id < 945000 && !(id >= 913000 && id < 914000)
}

// ipList checks addresses against exact addresses and networks.
type ipList struct {
	ips  map[string]bool
	nets []*net.IPNet
}

func newIPList(lists ...[]string) *ipList {
	l := &ipList{ips: map[string]bool{}}
	for _, list := range lists {
		for _, a := range list {
			if _, n, err := net.ParseCIDR(a); err == nil {
				l.nets = append(l.nets, n)
			} else if ip := net.ParseIP(a); ip != nil {
				l.ips[ip.String()] = true
			}
		}
	}
	return l
}

func (l *ipList) has(a string) bool {
	ip := net.ParseIP(a)
	if ip == nil {
		return false
	}
	if l.ips[ip.String()] {
		return true
	}
	for _, n := range l.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// network groups addresses: /16 for IPv4, /32 for IPv6.
func network(a string) string {
	ip := net.ParseIP(a)
	if ip == nil {
		return a
	}
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d", v4[0], v4[1])
	}
	return ip.Mask(net.CIDRMask(32, 128)).String()
}

// AutoExclusions returns the learned list.
func (m *Manager) AutoExclusions() []AutoExclusion {
	var out []AutoExclusion
	if m.DB != nil {
		_ = json.Unmarshal([]byte(store.GetKV(m.DB, kvAutoExcl)), &out)
	}
	return out
}

func (m *Manager) saveAuto(list []AutoExclusion) {
	sort.Slice(list, func(i, j int) bool { return list[i].Learned > list[j].Learned })
	b, _ := json.Marshal(list)
	_ = store.SetKV(m.DB, kvAutoExcl, string(b))
}

// activeAuto are the learned exclusions the rules use.
func (m *Manager) activeAuto() []settings.RuleExclusion {
	if m.Settings.Get().WAF.AutoExclusions != "auto" {
		return nil
	}
	var out []settings.RuleExclusion
	for _, e := range m.AutoExclusions() {
		if e.State == "active" {
			out = append(out, e.RuleExclusion)
		}
	}
	return out
}

// dynamic is what this server adds to the settings' exclusions.
func (m *Manager) dynamic() Dynamic {
	return Dynamic{Auto: m.activeAuto(), CPanelOff: CPanelModsecOff()}
}

// strictList: addresses with a bad reputation (IPDB, Tor, bans).
func (m *Manager) strictList() []string {
	var out []string
	for _, f := range []func() []string{m.IPDBIPs, m.TorIPs, m.BlockedIPs} {
		if f != nil {
			out = append(out, f()...)
		}
	}
	return out
}

// Learn looks at the last day's blocks for false positives. It reports
// whether the active list changed (the rules need a reload).
func (m *Manager) Learn(now int64) (bool, error) {
	mode := m.Settings.Get().WAF.AutoExclusions
	list := m.AutoExclusions()
	changed := false
	// Expired learned exclusions go (they are learned again if still needed).
	keep := list[:0]
	for _, e := range list {
		if e.State != "rejected" && e.Expires > 0 && e.Expires < now {
			changed = changed || e.State == "active"
			continue
		}
		keep = append(keep, e)
	}
	list = keep
	if mode == "off" {
		if changed {
			m.saveAuto(list)
		}
		return changed, nil
	}
	rows, err := m.DB.Query(`SELECT ip, host, uri, rule_id, msg, detail FROM waf_events WHERE at >= ? AND category != 'login'`, now-learnWindow)
	if err != nil {
		return changed, err
	}
	type ev struct {
		ip, host, uri, msg, detail string
		rule                       int
	}
	var evs []ev
	hosts := map[string]map[string]bool{}
	other := map[string]int{}
	for rows.Next() {
		var e ev
		if rows.Scan(&e.ip, &e.host, &e.uri, &e.rule, &e.msg, &e.detail) != nil {
			continue
		}
		e.host = strings.TrimPrefix(strings.ToLower(e.host), "www.")
		evs = append(evs, e)
		if hosts[e.ip] == nil {
			hosts[e.ip] = map[string]bool{}
		}
		hosts[e.ip][e.host] = true
		if !isScoreRule(e.rule) {
			other[e.ip]++
		}
	}
	rows.Close()
	strict := newIPList(m.strictList())
	type cluster struct {
		clean, dirty map[string]bool
		nets         map[string]bool
		hits         int
		sample, msg  string
		where        string
		domain, path string
		rule         int
	}
	clusters := map[string]*cluster{}
	cleanIP := map[string]bool{}
	for ip := range hosts {
		cleanIP[ip] = len(hosts[ip]) == 1 && other[ip] == 0 && !strict.has(ip)
	}
	for _, e := range evs {
		if !isScoreRule(e.rule) || !settings.ValidDomain(e.host) || reProbePath.MatchString(e.uri) {
			continue
		}
		path := learnPath(e.uri)
		if path == "-" {
			continue
		}
		ids, where := parseScored(e.detail)
		for _, id := range ids {
			if !learnable(id) {
				continue
			}
			k := fmt.Sprintf("%d|%s|%s", id, e.host, path)
			c := clusters[k]
			if c == nil {
				c = &cluster{clean: map[string]bool{}, dirty: map[string]bool{}, nets: map[string]bool{}, domain: e.host, path: path, rule: id, sample: e.uri, msg: e.msg, where: where[id]}
				clusters[k] = c
			}
			c.hits++
			if cleanIP[e.ip] {
				c.clean[e.ip] = true
				c.nets[network(e.ip)] = true
			} else {
				c.dirty[e.ip] = true
			}
		}
	}
	have := map[string]bool{}
	perDomain := map[string]int{}
	for _, e := range list {
		have[e.Key] = true
		if e.State != "rejected" {
			perDomain[e.Domain]++
		}
	}
	keys := make([]string, 0, len(clusters))
	for k := range clusters {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		c := clusters[k]
		need := learnMinIPs
		if c.path == "" {
			need = learnMinIPsSite
		}
		if have[k] || len(c.clean) < need || len(c.nets) < learnMinNets || len(c.dirty) > len(c.clean) || perDomain[c.domain] >= learnPerDomain || len(list) >= maxAutoExcl {
			continue
		}
		state := "suggested"
		if mode == "auto" {
			state = "active"
			changed = true
		}
		sample := c.sample
		if len(sample) > 200 {
			sample = sample[:200]
		}
		list = append(list, AutoExclusion{
			RuleExclusion: settings.RuleExclusion{Rule: c.rule, Domain: c.domain, Path: c.path, Note: "learned: " + strconv.Itoa(len(c.clean)) + " visitors"},
			Key:           k, Where: c.where, Sample: sample, Msg: c.msg, IPs: len(c.clean), Hits: c.hits,
			Learned: now, Expires: now + learnKeep, State: state,
		})
		perDomain[c.domain]++
		if m.Log != nil {
			m.Log.Info("WAF false positive learned", "rule", c.rule, "domain", c.domain, "path", c.path, "visitors", len(c.clean), "state", state)
		}
	}
	m.saveAuto(list)
	return changed, nil
}

// SetAutoExclusion accepts (suggested -> active), rejects (never used or
// learned again) or forgets (may be learned again) a learned exclusion.
func (m *Manager) SetAutoExclusion(key, action string) error {
	list := m.AutoExclusions()
	for i := range list {
		if list[i].Key != key {
			continue
		}
		switch action {
		case "accept":
			list[i].State = "active"
		case "reject":
			list[i].State = "rejected"
			list[i].Expires = 0
		case "forget":
			list = append(list[:i], list[i+1:]...)
		default:
			return fmt.Errorf("unknown action %q", action)
		}
		m.saveAuto(list)
		return nil
	}
	return errors.New("learned exclusion not found")
}

// CPanelUserdata is where cPanel keeps per-website Apache includes; its
// ModSecurity page writes "SecRuleEngine Off" there for a website switched
// off (a variable for tests).
var CPanelUserdata = "/etc/apache2/conf.d/userdata"

var reEngineOff = regexp.MustCompile(`(?im)^\s*SecRuleEngine\s+Off\b`)

// CPanelModsecOff lists the websites whose ModSecurity is switched off in
// cPanel » ModSecurity (or by WHM for a website), sorted.
func CPanelModsecOff() []string {
	files, _ := filepath.Glob(filepath.Join(CPanelUserdata, "*", "2_4", "*", "*", "*.conf"))
	seen := map[string]bool{}
	var out []string
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil || len(b) > 1<<20 || !reEngineOff.Match(b) {
			continue
		}
		d := strings.ToLower(filepath.Base(filepath.Dir(f)))
		if !seen[d] && settings.ValidDomain(d) {
			seen[d] = true
			out = append(out, d)
		}
	}
	sort.Strings(out)
	return out
}

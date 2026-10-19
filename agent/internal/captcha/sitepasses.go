package captcha

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"
)

// Pass cookies of the check on the website's own address. One shared value
// would let a visitor who solved the check once hand the cookie to a whole
// botnet. So the cookie takes one of SiteSlots values a day, each pass is
// recorded with the address it was given to, and the WAF logs which value
// a suspect address sends (one rule per value). A value sent by an address
// it was never given to is withdrawn: the WAF is applied without it, and
// everyone who held it solves the check again.

// SiteSlots is how many pass-cookie values a day the WAF accepts.
const SiteSlots = 8

// passLife is how long a pass is remembered: its value is accepted for
// today and yesterday (UTC days), so at most two days.
const passLife = 49 * time.Hour

// withdrawQuiet: reports for a withdrawn value that arrive before the WAF
// runs without it are the same misuse, not a new one.
const withdrawQuiet = 2 * time.Minute

// SitePasses records the pass cookies the website-address check gave out.
type SitePasses struct {
	Secret []byte
	// Load and Save keep the state across agent restarts (may be nil).
	Load func() []byte
	Save func([]byte)

	mu     sync.Mutex
	loaded bool
	st     sitePassState
	quiet  map[int]time.Time
}

type sitePassState struct {
	// Gen counts the withdrawals of a value: "day|slot" -> generation.
	Gen map[string]int `json:"gen"`
	// Given lists who got each value: token -> address key -> expiry (unix).
	Given map[string]map[string]int64 `json:"given"`
}

func day(t time.Time) int64 { return t.UTC().Unix() / 86400 }

func (p *SitePasses) load() {
	if p.loaded {
		return
	}
	p.loaded = true
	if p.Load != nil {
		_ = json.Unmarshal(p.Load(), &p.st)
	}
	if p.st.Gen == nil {
		p.st.Gen = map[string]int{}
	}
	if p.st.Given == nil {
		p.st.Given = map[string]map[string]int64{}
	}
}

func (p *SitePasses) save() {
	if p.Save == nil {
		return
	}
	if b, err := json.Marshal(p.st); err == nil {
		p.Save(b)
	}
}

func (p *SitePasses) token(d int64, slot int) string {
	m := hmac.New(sha256.New, p.Secret)
	fmt.Fprintf(m, "site|%d|%d|%d", d, slot, p.st.Gen[fmt.Sprintf("%d|%d", d, slot)])
	return hex.EncodeToString(m.Sum(nil))[:32]
}

// Slots are the values the WAF accepts now, by slot: today's, then
// yesterday's.
func (p *SitePasses) Slots(now time.Time) [][]string {
	if len(p.Secret) == 0 {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.load()
	d := day(now)
	out := make([][]string, SiteSlots)
	for s := range out {
		out[s] = []string{p.token(d, s), p.token(d-1, s)}
	}
	return out
}

// addrKey is the address a pass belongs to: an IPv6 visitor is its /64
// (privacy addresses change within it).
func addrKey(ip string) string {
	a := net.ParseIP(ip)
	if a == nil {
		return ""
	}
	if a.To4() == nil {
		return a.Mask(net.CIDRMask(64, 128)).String() + "/64"
	}
	return a.String()
}

// Give returns a pass-cookie value for the visitor at ip and records it.
func (p *SitePasses) Give(ip string, now time.Time) string {
	k := addrKey(ip)
	if len(p.Secret) == 0 || k == "" {
		return ""
	}
	n, err := rand.Int(rand.Reader, big.NewInt(SiteSlots))
	if err != nil {
		return ""
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.load()
	tok := p.token(day(now), int(n.Int64()))
	p.forget(now)
	if p.st.Given[tok] == nil {
		p.st.Given[tok] = map[string]int64{}
	}
	p.st.Given[tok][k] = now.Add(passLife).Unix()
	p.save()
	return tok
}

// forget drops expired passes and generations of days no longer accepted.
func (p *SitePasses) forget(now time.Time) {
	n := 0
	for tok, m := range p.st.Given {
		for k, exp := range m {
			if exp < now.Unix() {
				delete(m, k)
			}
		}
		if len(m) == 0 {
			delete(p.st.Given, tok)
		}
		n += len(m)
	}
	// A flood of passes cannot grow the state without end.
	if n > 100_000 {
		p.st.Given = map[string]map[string]int64{}
	}
	d := day(now)
	for k := range p.st.Gen {
		var kd int64
		var s int
		if _, err := fmt.Sscanf(k, "%d|%d", &kd, &s); err != nil || kd < d-1 {
			delete(p.st.Gen, k)
		}
	}
}

// Used is the WAF's report that the address ip sent the value of slot. It
// returns true when that value was not given to ip: it is withdrawn and the
// WAF must be applied again.
func (p *SitePasses) Used(ip string, slot int, now time.Time) bool {
	k := addrKey(ip)
	if len(p.Secret) == 0 || k == "" || slot < 0 || slot >= SiteSlots {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.load()
	if t, ok := p.quiet[slot]; ok && now.Sub(t) < withdrawQuiet {
		return false
	}
	d := day(now)
	for _, dd := range []int64{d, d - 1} {
		if exp, ok := p.st.Given[p.token(dd, slot)][k]; ok && exp >= now.Unix() {
			return false
		}
	}
	for _, dd := range []int64{d, d - 1} {
		delete(p.st.Given, p.token(dd, slot))
		p.st.Gen[fmt.Sprintf("%d|%d", dd, slot)]++
	}
	if p.quiet == nil {
		p.quiet = map[int]time.Time{}
	}
	p.quiet[slot] = now
	p.save()
	return true
}

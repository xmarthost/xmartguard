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
	"sync/atomic"
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
	// pending is set while a WAF apply for withdrawn values waits to run.
	pending atomic.Bool
	// saving is the timer of a save that gathers the passes given meanwhile.
	saving *time.Timer
}

// saveDelay gathers the passes given together into one save: the state can
// hold many thousand passes (audit A5 F19).
var saveDelay = 2 * time.Second

// saveSoon saves within saveDelay (p.mu held).
func (p *SitePasses) saveSoon() {
	if p.Save == nil || p.saving != nil {
		return
	}
	p.saving = time.AfterFunc(saveDelay, func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		p.saving = nil
		p.save()
	})
}

// applyDelay gathers the withdrawals that arrive together into one apply.
var applyDelay = 2 * time.Second

// ApplyWithdrawn runs apply (the WAF without the withdrawn values) once for
// the withdrawals that arrive while one is already waiting: each apply is a
// web server restart, and one shared cookie can withdraw several values.
func (p *SitePasses) ApplyWithdrawn(apply func()) {
	if !p.pending.CompareAndSwap(false, true) {
		return // the waiting apply covers this withdrawal too
	}
	go func() {
		time.Sleep(applyDelay)
		p.pending.Store(false) // a withdrawal from now on needs a new apply
		apply()
	}()
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

// Slots are the values the WAF accepts now, by slot: today's first, then
// those of the whole week (UTC days, weeks from the epoch) and the two
// days before it. They change only with the week (or a withdrawn value),
// so the web server is not reloaded every day for them (owner's rule,
// 2026-11-07: no restarts that are not needed); the last day of a week is
// in the next week's values too, so a pass given before the reload for a
// new week stays good.
func (p *SitePasses) Slots(now time.Time) [][]string {
	if len(p.Secret) == 0 {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.load()
	d := day(now)
	base := Week(now) * 7
	out := make([][]string, SiteSlots)
	for s := range out {
		out[s] = []string{p.token(d, s)}
		for dd := base - 2; dd <= base+7; dd++ {
			if dd != d {
				out[s] = append(out[s], p.token(dd, s))
			}
		}
	}
	return out
}

// Week is the UTC week (days since the epoch / 7) the pass values belong to.
func Week(now time.Time) int64 { return day(now) / 7 }

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
func (p *SitePasses) Give(ip string, now time.Time) string { return p.GiveAll(now, ip) }

// GiveAll returns one pass-cookie value for a visitor seen at several
// addresses (the website's, and the one it solved the check from: mobile
// networks reach sites from different addresses) and records it for each.
func (p *SitePasses) GiveAll(now time.Time, ips ...string) string {
	var keys []string
	for _, ip := range ips {
		if k := addrKey(ip); k != "" {
			keys = append(keys, k)
		}
	}
	if len(p.Secret) == 0 || len(keys) == 0 || addrKey(ips[0]) == "" {
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
	for _, k := range keys {
		p.st.Given[tok][k] = now.Add(passLife).Unix()
	}
	p.saveSoon()
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
		if _, err := fmt.Sscanf(k, "%d|%d", &kd, &s); err != nil || kd < min(d-1, Week(now)*7-2) {
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
	// Given within the last passLife (a cookie lives at most two days).
	for _, dd := range []int64{d, d - 1, d - 2} {
		if exp, ok := p.st.Given[p.token(dd, slot)][k]; ok && exp >= now.Unix() {
			return false
		}
	}
	// Every value of the slot the WAF accepts changes (the week's too: a
	// shared value of any day of it).
	base := Week(now) * 7
	for dd := min(d-2, base-2); dd <= max(d, base+7); dd++ {
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

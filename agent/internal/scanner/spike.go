package scanner

import (
	"encoding/json"
	"sort"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/store"
)

// Spike guard: a signature that suddenly quarantines very many files is
// more likely wrong than a real outbreak of that size (a bad rule once
// quarantined 51,000 files). After SpikeLimit files within an hour the
// signature is paused on this server: its new detections are only listed
// (status detected, nothing moved), the administrator is alerted, and
// unpausing (or a bulk action) quarantines them after review.

// SpikeLimit is how many files one signature may quarantine or disable
// within SpikeWindow before it is paused (0 = never paused).
var (
	SpikeLimit  = 500
	SpikeWindow = time.Hour
)

// NotePaused marks detections listed while their signature was paused.
const NotePaused = "Signature paused: it quarantined too many files at once. Review it, then unpause it or quarantine these files."

const kvPaused = "scanner.paused_signatures"

type spikeCount struct {
	start  int64
	n      int
	owners map[string]int
}

// PausedSignature is a signature whose quarantine is paused.
type PausedSignature struct {
	Signature string `json:"signature"`
	At        int64  `json:"at"`
	Files     int    `json:"files"`
}

func (s *Scanner) pausedMap() map[string]PausedSignature {
	m := map[string]PausedSignature{}
	_ = json.Unmarshal([]byte(store.GetKV(s.DB, kvPaused)), &m)
	return m
}

// Paused lists the paused signatures with how many files wait for review.
func (s *Scanner) Paused() []PausedSignature {
	s.mu.Lock()
	m := s.pausedMap()
	s.mu.Unlock()
	out := make([]PausedSignature, 0, len(m))
	for _, p := range m {
		_ = s.DB.QueryRow(`SELECT count(*) FROM findings WHERE signature = ? AND status = 'detected'`, p.Signature).Scan(&p.Files)
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].At > out[j].At })
	return out
}

// Unpause lets a signature quarantine again (its waiting files stay
// listed; quarantine them with a bulk action).
func (s *Scanner) Unpause(sig string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.pausedMap()
	delete(m, sig)
	b, _ := json.Marshal(m)
	_ = store.SetKV(s.DB, kvPaused, string(b))
	delete(s.spikes, sig)
}

// spikeAllows counts one quarantine of sig in owner's files and reports
// whether it may go ahead; it pauses the signature when the limit is passed
// (paused = true the first time, for the alert). One account cannot pause a
// signature for the whole server: only files outside the account with the
// most hits count toward the limit, and an account passing the limit on its
// own has only its further files listed instead of quarantined (for the
// window).
func (s *Scanner) spikeAllows(sig, owner string) (ok, paused bool) {
	if SpikeLimit <= 0 {
		return true, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.pausedMap()
	if _, on := m[sig]; on {
		return false, false
	}
	if s.spikes == nil {
		s.spikes = map[string]*spikeCount{}
	}
	now := store.Now()
	c := s.spikes[sig]
	if c == nil || now-c.start >= int64(SpikeWindow/time.Second) {
		c = &spikeCount{start: now, owners: map[string]int{}}
		s.spikes[sig] = c
	}
	c.owners[owner]++
	if c.owners[owner] > SpikeLimit {
		return false, false
	}
	c.n++
	top := 0
	for _, n := range c.owners {
		top = max(top, min(n, SpikeLimit))
	}
	if c.n-top < SpikeLimit {
		return true, false
	}
	m[sig] = PausedSignature{Signature: sig, At: now}
	b, _ := json.Marshal(m)
	_ = store.SetKV(s.DB, kvPaused, string(b))
	return false, true
}

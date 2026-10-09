package scanner

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/xmarthost/xmartguard/agent/internal/store"
)

// Signature decisions from the portal's AI Learning page, for every server:
// a signature that kept flagging files the AI then found clean is either
// put on review (its matches are reported as suspicious and wait for the
// AI instead of being quarantined and restored again and again) or off.
const (
	OverrideReview = "review"
	OverrideOff    = "off"
)

var overrides struct {
	mu     sync.RWMutex
	loaded bool
	m      map[string]string
}

// OverridesPath is where the decisions are kept (read by the scan engine too).
func OverridesPath() string { return store.StateDir() + "/sigs/overrides.json" }

func loadOverrides() map[string]string {
	overrides.mu.RLock()
	if overrides.loaded {
		m := overrides.m
		overrides.mu.RUnlock()
		return m
	}
	overrides.mu.RUnlock()
	overrides.mu.Lock()
	defer overrides.mu.Unlock()
	if !overrides.loaded {
		m := map[string]string{}
		if b, err := os.ReadFile(OverridesPath()); err == nil {
			_ = json.Unmarshal(b, &m)
		}
		overrides.m, overrides.loaded = validOverrides(m), true
	}
	return overrides.m
}

func validOverrides(m map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range m {
		if k != "" && (v == OverrideReview || v == OverrideOff) {
			out[k] = v
		}
	}
	return out
}

// SetOverrides saves new decisions and applies them at once.
func SetOverrides(m map[string]string) error {
	m = validOverrides(m)
	b, _ := json.Marshal(m)
	p := OverridesPath()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	if old, err := os.ReadFile(p); err != nil || !bytes.Equal(old, b) {
		if err := os.WriteFile(p+".tmp", b, 0o600); err != nil {
			return err
		}
		if err := os.Rename(p+".tmp", p); err != nil {
			return err
		}
	}
	overrides.mu.Lock()
	overrides.m, overrides.loaded = m, true
	overrides.mu.Unlock()
	return nil
}

// Overrides returns the current decisions.
func Overrides() map[string]string { return loadOverrides() }

// InReview reports whether a signature is on review.
func InReview(sig string) bool { return loadOverrides()[sig] == OverrideReview }

// applyOverride drops a detection whose signature is off and reports one on
// review as suspicious.
func applyOverride(d *Detection) *Detection {
	if d == nil {
		return nil
	}
	switch loadOverrides()[d.Signature] {
	case OverrideOff:
		return nil
	case OverrideReview:
		if d.Category == CatVirus {
			return &Detection{CatSuspicious, d.Signature}
		}
	}
	return d
}

// Locate finds the line a content signature matched and the code around
// it, for the portal's AI Learning report. Heuristic and hash signatures
// have no single matching line: line 0.
func Locate(sig string, content []byte) (int, string) {
	var at, end int = -1, -1
	for i := range Rules {
		r := &Rules[i]
		if r.Name != sig {
			continue
		}
		if r.lit != nil {
			if k := bytes.Index(content, r.lit); k >= 0 {
				at, end = k, k+len(r.lit)
			}
		} else if loc := r.re.FindIndex(content); loc != nil {
			at, end = loc[0], loc[1]
		}
		break
	}
	if at < 0 {
		return 0, ""
	}
	line := bytes.Count(content[:at], []byte("\n")) + 1
	last := line + bytes.Count(content[at:end], []byte("\n"))
	// Two lines before and after the match, each cut to 240 characters.
	lines := bytes.Split(content, []byte("\n"))
	var b strings.Builder
	for i := max(1, line-2); i <= min(len(lines), last+2); i++ {
		l := lines[i-1]
		if len(l) > 240 {
			b.Write(l[:240])
			b.WriteString("…")
		} else {
			b.Write(l)
		}
		b.WriteByte('\n')
		if b.Len() > 2000 {
			break
		}
	}
	return line, strings.TrimRight(b.String(), "\n")
}

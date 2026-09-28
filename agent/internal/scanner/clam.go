package scanner

import (
	"strings"
	"sync/atomic"

	"github.com/xmarthost/xmartguard/agent/internal/clamdb"
)

// ClamAV-format signatures, matched in this process (see package clamdb).
var clamEngine atomic.Pointer[clamdb.Engine]

// SetClamDB installs the loaded ClamAV-format signatures (nil = none).
func SetClamDB(e *clamdb.Engine) { clamEngine.Store(e) }

// ClamDB returns the active ClamAV-format signatures (nil = none).
func ClamDB() *clamdb.Engine { return clamEngine.Load() }

// clamCheck returns a detection for ClamAV-format signature hits.
func clamCheck(content []byte) *Detection {
	e := clamEngine.Load()
	if e == nil {
		return nil
	}
	name := e.Scan(content)
	if name == "" {
		return nil
	}
	low := strings.ToLower(name)
	if strings.HasPrefix(low, "heuristics.") || strings.HasPrefix(low, "pua.") || strings.Contains(low, "suspicious") {
		return &Detection{CatSuspicious, name}
	}
	return &Detection{CatVirus, name}
}

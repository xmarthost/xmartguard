package captcha

import (
	"sync/atomic"
	"testing"
	"time"
)

// Withdrawals that arrive together share one WAF apply (a web server
// restart each), and a withdrawal after that apply started gets its own
// (A5 F19).
func TestApplyWithdrawnCoalesced(t *testing.T) {
	old := applyDelay
	applyDelay = 50 * time.Millisecond
	defer func() { applyDelay = old }()
	p := &SitePasses{}
	var n atomic.Int32
	apply := func() { n.Add(1) }
	for i := 0; i < 8; i++ {
		p.ApplyWithdrawn(apply)
	}
	time.Sleep(200 * time.Millisecond)
	if n.Load() != 1 {
		t.Fatalf("%d applies for one burst", n.Load())
	}
	p.ApplyWithdrawn(apply)
	time.Sleep(200 * time.Millisecond)
	if n.Load() != 2 {
		t.Fatalf("a later withdrawal was not applied: %d", n.Load())
	}
}

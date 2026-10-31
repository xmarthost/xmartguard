package core

import (
	"context"
	"sync"
	"time"
)

// The dashboard's counts run over whole tables (millions of WAF events on a
// busy server) on the only database connection: computed on every open, a
// server nobody opened for a while took 10 s and more to show. The answer
// is kept per period: a page gets the kept one at once, and one older than
// dashFresh is counted again in the background (the page's next refresh
// shows it). The default period is counted every dashWarmEvery, so even a
// first open is quick and its numbers are minutes old at most.
const (
	dashFresh     = time.Minute
	dashWarmEvery = 10 * time.Minute
	dashWarmDays  = 30
)

type dashEntry struct {
	run  sync.Mutex // one count at a time per period
	v    map[string]any
	at   time.Time
	busy bool
}

type dashCache struct {
	mu sync.Mutex
	m  map[int]*dashEntry
}

func (c *dashCache) entry(days int) *dashEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[int]*dashEntry{}
	}
	e := c.m[days]
	if e == nil {
		e = &dashEntry{}
		c.m[days] = e
	}
	return e
}

// get returns the kept answer (counting it first if there is none) and
// counts again in the background when it is older than dashFresh.
func (c *dashCache) get(days int, compute func(int) map[string]any) map[string]any {
	e := c.entry(days)
	c.mu.Lock()
	v, stale := e.v, e.v != nil && time.Since(e.at) > dashFresh && !e.busy
	if stale {
		e.busy = true
	}
	c.mu.Unlock()
	if v == nil {
		return c.refresh(days, compute)
	}
	if stale {
		go func() {
			c.refresh(days, compute)
			c.mu.Lock()
			e.busy = false
			c.mu.Unlock()
		}()
	}
	return v
}

// refresh counts now (a count already running for the period is waited
// for and its answer used).
func (c *dashCache) refresh(days int, compute func(int) map[string]any) map[string]any {
	e := c.entry(days)
	asked := time.Now()
	e.run.Lock()
	defer e.run.Unlock()
	c.mu.Lock()
	if e.v != nil && !e.at.Before(asked) {
		v := e.v
		c.mu.Unlock()
		return v
	}
	c.mu.Unlock()
	v := compute(days)
	c.mu.Lock()
	e.v, e.at = v, time.Now()
	c.mu.Unlock()
	return v
}

// Dashboard is the server overview, from the kept answer.
func (a *Agent) Dashboard(days int) map[string]any {
	return a.dash.get(dashDays(days), a.dashboard)
}

func dashDays(days int) int {
	if days != 7 && days != 30 && days != 90 {
		return 30
	}
	return days
}

// dashboardLoop keeps the default period's answer counted.
func (a *Agent) dashboardLoop(ctx context.Context) {
	t := time.NewTimer(2 * time.Minute) // after the start's own work
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		a.dash.refresh(dashWarmDays, a.dashboard)
		t.Reset(dashWarmEvery)
	}
}

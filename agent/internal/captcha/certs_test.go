package captcha

import (
	"crypto/tls"
	"fmt"
	"sync"
	"testing"
	"time"
)

// The index is rebuilt in the background: a handshake does not wait for
// it, and handshakes run in parallel without one lock around file reads
// (run with -race) (A5 F15).
func TestCertIndexRebuildInBackground(t *testing.T) {
	c := &CertStore{Dirs: []string{t.TempDir()}}
	if _, err := c.Get(&tls.ClientHelloInfo{ServerName: "a.example"}); err != nil {
		t.Fatal(err)
	}
	// An old index is used while a new one is built.
	c.mu.Lock()
	c.index, c.indexAt = map[string]string{"old.example": "/nonexistent"}, time.Now().Add(-time.Hour)
	c.mu.Unlock()
	if idx := c.currentIndex(); idx["old.example"] == "" {
		t.Fatal("the handshake waited for the rebuild")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		c.mu.Lock()
		done := !c.building && time.Since(c.indexAt) < time.Minute
		c.mu.Unlock()
		if done {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the index was not rebuilt")
		}
		time.Sleep(10 * time.Millisecond)
	}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if cert, err := c.Get(&tls.ClientHelloInfo{ServerName: fmt.Sprintf("n%d.example", i%7)}); err != nil || cert == nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
}

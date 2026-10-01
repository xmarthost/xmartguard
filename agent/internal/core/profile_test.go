package core

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/scanner"
)

// burn keeps one core busy in this package until stop closes.
func burn(stop <-chan struct{}) {
	b := make([]byte, 4096)
	for {
		select {
		case <-stop:
			return
		default:
			s := sha256.Sum256(b)
			b[0] = s[0]
		}
	}
}

func TestCPUProfileNamesBusyArea(t *testing.T) {
	a := &Agent{Realtime: &scanner.Realtime{}}
	stop := make(chan struct{})
	go burn(stop)
	rep, err := a.cpuProfile(context.Background(), 2*time.Second)
	close(stop)
	if err != nil {
		t.Fatal(err)
	}
	if rep.CPUPercent < 50 || len(rep.Areas) == 0 {
		t.Fatalf("report %+v", rep)
	}
	if rep.Areas[0].Name != "Agent core" || rep.Areas[0].Share < 50 {
		t.Fatalf("top area %+v, want Agent core", rep.Areas[0])
	}
	if _, err := a.cpuProfile(context.Background(), 0); err != nil {
		t.Fatal("a second profile after the first should work:", err)
	}
}

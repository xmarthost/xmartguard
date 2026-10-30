package hostnets

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

// Routes of a normal size count (RADb is not authoritative), one inside
// another is dropped; an AS that
// does not answer costs only its own routes; the copy survives a restart
// and a refresh that read nothing.
func TestRefresh(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XG_STATE_DIR", filepath.Join(dir, "state"))
	calls := 0
	s := &Store{Routes: func(_ context.Context, as string) ([]string, error) {
		calls++
		switch as {
		case "AS24940":
			return []string{"5.9.0.0/16", "5.9.1.0/24", "0.0.0.0/1", "10.0.0.0/8", "2a01:4f8::/29", "::/0", "bad"}, nil
		case "AS16276":
			return nil, errors.New("timeout")
		}
		return nil, errors.New("no routes")
	}}
	if !s.Refresh(context.Background()) {
		t.Fatal("no refresh")
	}
	got := map[string]bool{}
	for _, n := range s.Nets() {
		got[n] = true
	}
	if len(got) != 2 || !got["5.9.0.0/16"] || !got["2a01:4f8::/29"] {
		t.Fatalf("nets: %v", s.Nets())
	}
	if s.Refresh(context.Background()) || calls != len(ASNs) {
		t.Fatalf("refreshed again within a day (%d calls)", calls)
	}
	r := &Store{}
	r.Load()
	if len(r.Nets()) != 2 {
		t.Fatalf("cache: %v", r.Nets())
	}
	r.at = r.at.AddDate(0, 0, -2)
	r.Routes = func(context.Context, string) ([]string, error) { return nil, errors.New("down") }
	if r.Refresh(context.Background()) || len(r.Nets()) != 2 {
		t.Fatalf("failed refresh dropped the copy: %v", r.Nets())
	}
}

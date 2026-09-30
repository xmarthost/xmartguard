package core

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/xmarthost/xmartguard/agent/internal/firewall"
)

// The portal's list of this account's servers: never blocked, shown as
// XPGUARD-SERVER in Check IP.
func TestFleetWhitelist(t *testing.T) {
	a := newTestAgent(t, `{"firewall":{"enabled":false}}`)
	set := func(body string) map[string]any {
		t.Helper()
		r, err := a.Handlers()["fleet.set"](context.Background(), json.RawMessage(body))
		if err != nil {
			t.Fatal(err)
		}
		return r.(map[string]any)
	}
	r := set(`{"servers":[{"ip":"198.51.100.9","host":"business900.example"},{"ip":"10.0.0.5","host":"lan"},{"ip":"bad","host":"x"},{"ip":"198.51.100.9","host":"dup"}]}`)
	if r["changed"] != true || r["servers"] != 1 {
		t.Fatalf("%v", r)
	}
	if r := set(`{"servers":[{"ip":"198.51.100.9","host":"business900.example"}]}`); r["changed"] != false {
		t.Fatalf("unchanged list reported as changed: %v", r)
	}
	if _, err := a.Firewall.Add(firewall.KindDeny, "198.51.100.9", "", 0); err == nil || !strings.Contains(err.Error(), "xPGuard server") {
		t.Fatalf("fleet server blacklisted: %v", err)
	}
	a.Firewall.AutoBan("198.51.100.9", "brute force", "lfd")
	if l, _ := a.Firewall.List(firewall.KindTempBan); len(l) != 0 {
		t.Fatalf("fleet server banned: %+v", l)
	}
	c, err := a.Firewall.Check("198.51.100.9")
	if err != nil || c.Server != "business900.example" || c.Status != "allowed" || strings.Join(c.Found, ",") != "XPGUARD-SERVER" {
		t.Fatalf("%+v %v", c, err)
	}
	// A server removed from the account is no longer protected.
	set(`{"servers":[]}`)
	if _, err := a.Firewall.Add(firewall.KindDeny, "198.51.100.9", "", 0); err != nil {
		t.Fatal(err)
	}
}

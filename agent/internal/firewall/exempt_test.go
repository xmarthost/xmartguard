package firewall

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xmarthost/xmartguard/agent/internal/settings"
	"github.com/xmarthost/xmartguard/agent/internal/store"
)

// unitManager is a Manager with a database and settings but no kernel
// backend (nothing is loaded into nftables or iptables).
func unitManager(t *testing.T) *Manager {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XG_STATE_DIR", filepath.Join(dir, "state"))
	t.Setenv("XG_CONFIG_DIR", filepath.Join(dir, "conf"))
	db, err := store.Open()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	st, _ := settings.Load()
	if _, err := st.Patch([]byte(`{"firewall":{"provider":"nftables"}}`)); err != nil {
		t.Fatal(err)
	}
	return &Manager{DB: db, Settings: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Protected: func() []string { return []string{"192.0.2.250"} }}
}

// A whitelisted country, a trusted service or an ignore entry is exempt
// from xPGuard's blocks (IPDB, blacklist, bans, countries) but not from
// the port filter; only the real whitelist and this server/the portal
// pass every rule. Both backends render it the same way.
func TestExemptStillMeetsPortFilter(t *testing.T) {
	m := unitManager(t)
	geoDir := t.TempDir()
	os.WriteFile(filepath.Join(geoDir, "zz.zone"), []byte("10.99.0.0/16\n"), 0o600)
	m.Geo = &Geo{Dir: geoDir, Log: m.Log}
	m.Trusted = func() []string { return []string{"198.51.100.0/24"} }
	if _, err := m.Settings.Patch([]byte(`{"firewall":{"ignored_countries":["ZZ"],"port_filter":true,"tcp_in":"22,80,443"}}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := m.store(KindIgnore, "203.0.113.5", "", 0, AllowOpts{}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.store(KindAllow, "203.0.113.9", "office", 0, AllowOpts{}); err != nil {
		t.Fatal(err)
	}
	rs, err := m.Build()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []string{"10.99.0.0/16", "198.51.100.0/24", "203.0.113.5"} {
		if contains(rs.Allow, c) || !contains(rs.Ignore, c) {
			t.Errorf("%s: allow %v ignore %v", c, rs.Allow, rs.Ignore)
		}
	}
	for _, c := range []string{"203.0.113.9", "192.0.2.250"} {
		if !contains(rs.Allow, c) {
			t.Errorf("%s not in the whitelist set: %v", c, rs.Allow)
		}
	}
	rs.IPDB = []string{"10.99.5.0/24"}

	nft := rs.Render()
	ex := nft[strings.Index(nft, "chain exempt {"):]
	ex = ex[:strings.Index(ex, "\t}\n")]
	for _, want := range []string{"tcp dport { 22, 80, 443", `counter drop comment "xg-port"`} {
		if !strings.Contains(ex, want) {
			t.Errorf("exempt chain missing %q:\n%s", want, ex)
		}
	}
	allow4 := nft[strings.Index(nft, "set allow4"):]
	allow4 = allow4[:strings.Index(allow4, "}")]
	if strings.Contains(allow4, "10.99.0.0") || strings.Contains(allow4, "198.51.100.0") {
		t.Errorf("exempt networks in allow4: %s", allow4)
	}
	in := nft[strings.Index(nft, "chain input"):]
	if j, d := strings.Index(in, "ip saddr @exempt4 jump exempt"), strings.Index(in, "@ipdb4 counter jump drop_ipdb"); j < 0 || d < 0 || j > d {
		t.Errorf("exempt jump must come before the IPDB drop:\n%s", in)
	}

	ipt := renderRules(rs, false)
	for _, want := range []string{"-A XPGUARD -m set --match-set xg_exempt4 src -j XPGUARD_EXEMPT", "-A XPGUARD -m set --match-set xg_exempt4 src -j RETURN",
		"-A XPGUARD_EXEMPT -p tcp -m multiport --dports 22,80,443", `-A XPGUARD_EXEMPT -p tcp -m comment --comment "xg-port" -j DROP`} {
		if !strings.Contains(ipt, want) {
			t.Errorf("iptables missing %q:\n%s", want, ipt)
		}
	}
	if strings.Index(ipt, "xg_exempt4 src -j RETURN") > strings.Index(ipt, "xg_ipdb4") {
		t.Error("exempt return after the IPDB drop")
	}
	sets := renderIPSet(rs)
	if !strings.Contains(sets, "add xg_exempt4_n 10.99.0.0/16") || strings.Contains(sets, "add xg_allow4_n 10.99.0.0/16") {
		t.Errorf("ipset: %s", sets)
	}
}

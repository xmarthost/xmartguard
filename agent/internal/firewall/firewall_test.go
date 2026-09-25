package firewall

import (
	"context"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/settings"
	"github.com/xmarthost/xmartguard/agent/internal/store"
)

func TestParseAddr(t *testing.T) {
	good := map[string]string{
		"1.2.3.4": "1.2.3.4", " 10.0.0.0/8 ": "10.0.0.0/8", "192.168.1.7/24": "192.168.1.0/24",
		"1.2.3.4/32": "1.2.3.4", "2001:db8::1": "2001:db8::1", "2001:db8::/32": "2001:db8::/32",
	}
	for in, want := range good {
		got, err := ParseAddr(in)
		if err != nil || got != want {
			t.Errorf("ParseAddr(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "abc", "1.2.3", "0.0.0.0/0", "10.0.0.0/4", "::/0", "1.2.3.4; drop table"} {
		if _, err := ParseAddr(bad); err == nil {
			t.Errorf("ParseAddr(%q) accepted", bad)
		}
	}
}

func TestLogRules(t *testing.T) {
	cases := []struct {
		service, line, ip string
	}{
		{"SSH", "Sep 26 10:01:02 host sshd[1234]: Failed password for root from 203.0.113.9 port 51234 ssh2", "203.0.113.9"},
		{"SSH", "Sep 26 10:01:02 host sshd[1234]: Failed password for invalid user admin from 198.51.100.4 port 1 ssh2", "198.51.100.4"},
		{"SSH", "Sep 26 10:01:02 host sshd[99]: Invalid user oracle from 2001:db8::5 port 22", "2001:db8::5"},
		{"cPanel/WHM/Webmail", `[2026-09-26 10:00:00 +0000] info [whostmgrd] 192.0.2.44 - root "POST /login/?login_only=1 HTTP/1.1" FAILED LOGIN whostmgrd: user password incorrect`, "192.0.2.44"},
		{"Mail (Dovecot)", "Sep 26 10:00:00 host dovecot[1]: imap-login: Disconnected (auth failed, 3 attempts in 12 secs): user=<a@b.c>, method=PLAIN, rip=198.51.100.23, lip=10.0.0.1", "198.51.100.23"},
		{"Mail (Exim SMTP auth)", "2026-09-26 10:00:00 dovecot_login authenticator failed for ([10.0.0.1]) [203.0.113.77]:5555: 535 Incorrect authentication data", "203.0.113.77"},
		{"FTP", "Sep 26 10:00:00 host pure-ftpd: (?@192.0.2.8) [WARNING] Authentication failed for user [bob]", "192.0.2.8"},
	}
	byName := map[string]LogRule{}
	for _, r := range LogRules {
		byName[r.Service] = r
	}
	for _, c := range cases {
		ip, ok := byName[c.service].ParseLine(c.line)
		if !ok || ip != c.ip {
			t.Errorf("%s: got %q %v, want %q", c.service, ip, ok, c.ip)
		}
	}
	if _, ok := byName["SSH"].ParseLine("sshd[1]: Accepted password for root from 203.0.113.9 port 1 ssh2"); ok {
		t.Error("successful login matched")
	}
}

func TestCounterWindow(t *testing.T) {
	now := time.Unix(1000, 0)
	c := &Counter{Now: func() time.Time { return now }}
	for i := 1; i <= 3; i++ {
		if n := c.Hit("1.1.1.1", time.Minute); n != i {
			t.Fatalf("hit %d -> %d", i, n)
		}
	}
	now = now.Add(2 * time.Minute)
	if n := c.Hit("1.1.1.1", time.Minute); n != 1 {
		t.Fatalf("old hits not expired: %d", n)
	}
}

func TestRenderIsValidNFT(t *testing.T) {
	rs := Ruleset{
		Allow: []string{"203.0.113.0/24", "2001:db8::/32"}, Deny: []string{"198.51.100.7"}, Ignore: []string{"192.0.2.1"},
		TempBan:      map[string]time.Duration{"198.51.100.9": time.Hour, "2001:db8::9": time.Minute},
		TempAllow:    map[string]time.Duration{"192.0.2.99": time.Hour},
		CountryBlock: []string{"1.0.0.0/24", "1.0.1.0/24"}, CountryAllow: []string{"5.0.0.0/16"},
		DoS: true, DoSPerMinute: 150, DoSBanSeconds: 600,
	}
	script := rs.Render()
	for _, want := range []string{"delete table inet xmartguard", "@deny4 counter drop", "update @dos4", "198.51.100.9 timeout 3600s"} {
		if !strings.Contains(script, want) {
			t.Errorf("script missing %q", want)
		}
	}
	nft := FindNFT()
	if nft.Bin == "" || os.Geteuid() != 0 {
		t.Skip("nft not available")
	}
	if out, err := exec.Command(nft.Bin, "-c", "-f", "-").CombinedOutput(); err != nil {
		_ = out
	}
	cmd := exec.Command(nft.Bin, "-c", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("nft rejected ruleset: %v\n%s\n%s", err, out, script)
	}
}

func newManager(t *testing.T, provider string) *Manager {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	nft, ipt := FindNFT(), FindIPTables()
	switch provider {
	case ProviderNFTables:
		if nft.Bin == "" || exec.Command(nft.Bin, "list", "tables").Run() != nil {
			t.Skip("nft not usable here")
		}
	case ProviderIPTables:
		if ipt.Available() != nil || exec.Command(ipt.IPSet, "list", "-n").Run() != nil {
			t.Skip("iptables/ipset not usable here")
		}
	}
	dir := t.TempDir()
	t.Setenv("XG_STATE_DIR", filepath.Join(dir, "state"))
	t.Setenv("XG_CONFIG_DIR", filepath.Join(dir, "conf"))
	db, err := store.Open()
	if err != nil {
		t.Fatal(err)
	}
	st, _ := settings.Load()
	if _, err := st.Patch([]byte(`{"firewall":{"provider":"` + provider + `"}}`)); err != nil {
		t.Fatal(err)
	}
	m := &Manager{DB: db, Settings: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), NFT: nft, IPT: ipt,
		Protected: func() []string { return []string{"192.0.2.250"} }}
	t.Cleanup(func() { _ = nft.Remove(); _ = ipt.Remove(); db.Close() })
	return m
}

// kernelDump returns the loaded rules and set contents for assertions.
func kernelDump(m *Manager) string {
	if m.Backend().Name() == ProviderNFTables {
		out, _ := exec.Command(m.NFT.Bin, "list", "table", "inet", Table).CombinedOutput()
		return string(out)
	}
	a, _ := exec.Command(m.IPT.IPSet, "list").CombinedOutput()
	b, _ := exec.Command(m.IPT.IPT, "-S", ChainMain).CombinedOutput()
	c, _ := exec.Command(m.IPT.IPT, "-S", "INPUT").CombinedOutput()
	return string(a) + string(b) + string(c)
}

func providers(t *testing.T, fn func(t *testing.T, provider string)) {
	for _, p := range []string{ProviderIPTables, ProviderNFTables} {
		t.Run(p, func(t *testing.T) { fn(t, p) })
	}
}

func TestManagerLifecycleOnKernel(t *testing.T) {
	providers(t, func(t *testing.T, provider string) {
		m := newManager(t, provider)
		if err := m.Apply(); err != nil {
			t.Fatal(err)
		}
		if !m.Backend().Healthy() {
			t.Fatal("not healthy after apply")
		}
		if _, err := m.Add(KindDeny, "198.51.100.0/24", "bad net", 0); err != nil {
			t.Fatal(err)
		}
		if _, err := m.Add(KindDeny, "192.0.2.250", "", 0); err == nil {
			t.Fatal("blocking a protected IP was allowed")
		}
		if _, err := m.Add(KindTempBan, "203.0.113.5", "test", 30*time.Minute); err != nil {
			t.Fatal(err)
		}
		if _, err := m.Add(KindTempBan, "203.0.113.0/24", "", time.Hour); err == nil {
			t.Fatal("temp ban with CIDR accepted")
		}
		dump := kernelDump(m)
		for _, want := range []string{"198.51.100.0/24", "203.0.113.5", "192.0.2.250"} {
			if !strings.Contains(dump, want) {
				t.Fatalf("kernel missing %s:\n%s", want, dump)
			}
		}
		if c, _ := m.Check("198.51.100.77"); c.Status != "blocked" {
			t.Fatalf("check: %+v", c)
		}
		m.AutoBan("203.0.113.66", "5 failed SSH logins", "bruteforce")
		els, err := m.Backend().TempBanned()
		if err != nil || !contains(els, "203.0.113.66") {
			t.Fatalf("temp bans = %v, %v", els, err)
		}
		m.AutoBan("192.0.2.250", "x", "bruteforce") // protected: ignored
		if _, total, _ := m.Events(EventFilter{}); total != 3 {
			t.Fatalf("events %d", total)
		}
		if err := m.Unblock("203.0.113.66"); err != nil {
			t.Fatal(err)
		}
		if els, _ := m.Backend().TempBanned(); contains(els, "203.0.113.66") {
			t.Fatal("unblock left the kernel entry")
		}
		if _, err := m.Add(KindAllow, "198.51.100.0/24", "", 0); err != nil {
			t.Fatal(err)
		}
		if c, _ := m.Check("198.51.100.77"); c.Status != "allowed" {
			t.Fatalf("after allow: %+v", c)
		}
		if st := m.Stats(); st.DroppedPackets == nil {
			t.Fatal("no counters")
		}
		// Simulate another firewall flushing our rules; the maintenance check notices.
		_ = m.Backend().Remove()
		if m.Backend().Healthy() {
			t.Fatal("healthy after removal")
		}
		if err := m.Apply(); err != nil || !m.Backend().Healthy() {
			t.Fatalf("reapply: %v", err)
		}
		// Disabling removes everything.
		m.Settings.Patch([]byte(`{"firewall":{"enabled":false}}`))
		if err := m.Apply(); err != nil {
			t.Fatal(err)
		}
		if m.Backend().Healthy() {
			t.Fatal("rules still loaded after disable")
		}
	})
}

func TestProviderSwitchRemovesOldRules(t *testing.T) {
	m := newManager(t, ProviderIPTables)
	if m.NFT.Available() != nil {
		t.Skip("nft missing")
	}
	if err := m.Apply(); err != nil {
		t.Fatal(err)
	}
	m.Settings.Patch([]byte(`{"firewall":{"provider":"nftables"}}`))
	if err := m.Apply(); err != nil {
		t.Fatal(err)
	}
	if m.IPT.Healthy() || !m.NFT.Healthy() {
		t.Fatal("switch to nftables left iptables rules or did not load nft")
	}
	m.Settings.Patch([]byte(`{"firewall":{"provider":"iptables"}}`))
	if err := m.Apply(); err != nil {
		t.Fatal(err)
	}
	if !m.IPT.Healthy() || m.NFT.Healthy() {
		t.Fatal("switch back failed")
	}
}

func TestDoSRulesetLoads(t *testing.T) {
	providers(t, func(t *testing.T, provider string) {
		m := newManager(t, provider)
		m.Settings.Patch([]byte(`{"firewall":{"dos":true,"dos_threshold":100}}`))
		if err := m.Apply(); err != nil {
			t.Fatal(err)
		}
		if dump := kernelDump(m); !strings.Contains(dump, "xg-dos") && !strings.Contains(dump, ChainDoS) {
			t.Fatalf("dos rule missing:\n%s", dump)
		}
	})
}

func TestBruteForceEndToEnd(t *testing.T) {
	m := newManager(t, ProviderIPTables)
	m.Apply()
	log := filepath.Join(t.TempDir(), "secure")
	os.WriteFile(log, []byte("old line\n"), 0o600)
	rule := LogRule{Service: "SSH", Files: []string{log}, Re: LogRules[0].Re}
	saved := LogRules
	LogRules = []LogRule{rule}
	defer func() { LogRules = saved }()
	ctx, cancel := contextWithTimeout(20 * time.Second)
	defer cancel()
	go m.RunBruteForce(ctx)
	time.Sleep(2500 * time.Millisecond)
	f, _ := os.OpenFile(log, os.O_APPEND|os.O_WRONLY, 0o600)
	for i := 0; i < 5; i++ {
		f.WriteString("Sep 26 10:01:02 host sshd[1234]: Failed password for root from 203.0.113.200 port 5 ssh2\n")
	}
	f.Close()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if c, _ := m.Check("203.0.113.200"); c.Status == "temp-blocked" {
			if els, _ := m.Backend().TempBanned(); !contains(els, "203.0.113.200") {
				t.Fatal("ban not in kernel")
			}
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("brute force did not ban the attacker")
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func contextWithTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}

func TestCollapse(t *testing.T) {
	got := Collapse([]string{"198.51.100.9", "198.51.100.0/24", "198.51.0.0/16", "203.0.113.7", "203.0.113.7", "2001:db8::1", "2001:db8::/48", "10.0.0.1"})
	want := []string{"10.0.0.1", "198.51.0.0/16", "2001:db8::/48", "203.0.113.7"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestCounterParsers(t *testing.T) {
	out := map[string]uint64{}
	parseIPSetCounters("Name: xg_ipdb4\nType: hash:net\nHeader: family inet hashsize 1024 maxelem 1048576 counters\nMembers:\n198.51.100.0/24 packets 7 bytes 420\n203.0.113.7 packets 0 bytes 0\n", out)
	if out["198.51.100.0/24"] != 7 || len(out) != 1 {
		t.Fatalf("ipset: %v", out)
	}
	out = map[string]uint64{}
	parseNFTSetCounters([]byte(`{"nftables":[{"metainfo":{}},{"set":{"name":"ipdb4","elem":[
		{"elem":{"val":{"prefix":{"addr":"198.51.100.0","len":24}},"counter":{"packets":3,"bytes":1}}},
		{"elem":{"val":"203.0.113.7","counter":{"packets":2,"bytes":1}}},
		{"elem":{"val":"203.0.113.8","counter":{"packets":0,"bytes":0}}}]}}]}`), out)
	if out["198.51.100.0/24"] != 3 || out["203.0.113.7"] != 2 || len(out) != 2 {
		t.Fatalf("nft: %v", out)
	}
}

func TestIPDBOnKernel(t *testing.T) {
	providers(t, func(t *testing.T, provider string) {
		m := newManager(t, provider)
		m.IPDB = &IPDB{}
		n, err := m.ApplyIPDB("v1", []string{"198.51.100.0/24 US", "198.51.100.9 US", "203.0.113.7 CN", "192.0.2.250 XX", "2001:db8::/48 DE", "10.99.0.2 ZZ", "bogus"})
		if err != nil || n != 6 {
			t.Fatalf("apply: %d %v", n, err)
		}
		dump := kernelDump(m)
		if !strings.Contains(dump, "203.0.113.7") || !strings.Contains(dump, "xg-ipdb") {
			t.Fatalf("ipdb not loaded:\n%s", dump)
		}
		if strings.Contains(dump, "192.0.2.250") && !strings.Contains(dump, "allow") {
			t.Fatal("protected address was put in the IPDB set")
		}
		if c, _ := m.Check("203.0.113.7"); !strings.HasPrefix(c.Status, "ipdb-blocked") {
			t.Fatalf("check: %+v", c)
		}
		if c, _ := m.Check("192.0.2.250"); strings.HasPrefix(c.Status, "ipdb") {
			t.Fatalf("protected listed: %+v", c)
		}
		// The list survives a restart.
		v, entries := (&IPDB{}).Snapshot()
		if v != "v1" || len(entries) != 6 {
			t.Fatalf("reload: %s %v", v, entries)
		}
		// Generate real traffic from a network namespace to count hits.
		sh := func(args ...string) error { return exec.Command(args[0], args[1:]...).Run() }
		_ = sh("ip", "netns", "del", "xgtest")
		if sh("ip", "netns", "add", "xgtest") != nil {
			t.Log("no netns support; skipping hit counting")
			return
		}
		defer sh("ip", "netns", "del", "xgtest")
		defer sh("ip", "link", "del", "xgv0")
		for _, c := range [][]string{
			{"ip", "link", "add", "xgv0", "type", "veth", "peer", "name", "xgv1"},
			{"ip", "link", "set", "xgv1", "netns", "xgtest"},
			{"ip", "addr", "add", "10.99.0.1/30", "dev", "xgv0"},
			{"ip", "link", "set", "xgv0", "up"},
			{"ip", "netns", "exec", "xgtest", "ip", "addr", "add", "10.99.0.2/30", "dev", "xgv1"},
			{"ip", "netns", "exec", "xgtest", "ip", "link", "set", "xgv1", "up"},
		} {
			if err := sh(c...); err != nil {
				t.Logf("netns setup failed (%v); skipping hit counting", c)
				return
			}
		}
		_ = sh("ip", "netns", "exec", "xgtest", "ping", "-c", "3", "-i", "0.2", "-W", "1", "10.99.0.1")
		m.pollIPDBHits()
		st := m.IPDBStatus()
		if st.HitsTotal < 1 || len(st.Recent) == 0 || st.Recent[0].Entry != "10.99.0.2" || st.Countries["ZZ"] < 1 {
			t.Fatalf("hits not recorded: %+v", st)
		}
		hits, _ := m.TakePendingHits(10)
		if len(hits) != 1 || hits[0].Hits < 1 {
			t.Fatalf("pending: %+v", hits)
		}
		if again, _ := m.TakePendingHits(10); len(again) != 0 {
			t.Fatalf("pending not cleared: %+v", again)
		}
	})
}

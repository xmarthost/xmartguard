package firewall

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// A reflection attack (2026-11-10) made thousands of servers send SYN-ACKs
// and DNS/NTP answers here. The DoS limit counted the SYN-ACKs as new
// connections (2.17 million bans, the set filled and every apply failed)
// and the UDP answers filled the connection table. Only real connection
// attempts are counted now, reflected UDP is not tracked, and the bans
// loaded are capped.
func TestReflectionFloodRules(t *testing.T) {
	pf := &PortFilter{TCPIn: []string{"22", "80", "443"}, UDPIn: []string{"53"}}
	rs := Ruleset{DoS: true, DoSPerMinute: 150, ReflectGuard: true, LocalPorts: "32768-60999", Ports: pf}

	nft := rs.Render()
	for _, want := range []string{
		"tcp flags & (fin|syn|rst|ack) == syn update @dos4",
		"type filter hook prerouting priority raw; policy accept;",
		`iifname != "lo" udp sport { 19, 53, 123, 161, 389, 1900, 3283, 3389, 3702, 5353, 10001, 11211, 37810 } udp dport 32768-60999 notrack`,
		"ct state untracked udp sport { 19, 53, 123, 161, 389, 1900, 3283, 3389, 3702, 5353, 10001, 11211, 37810 } udp dport 32768-60999 accept",
	} {
		if !strings.Contains(nft, want) {
			t.Errorf("nft missing %q", want)
		}
	}
	// Answers are let in before the port filter's drop, in both chains.
	if strings.Count(nft, "ct state untracked") != 2 || strings.Index(nft, "ct state untracked") > strings.Index(nft, `comment "xg-port"`) {
		t.Error("untracked answers not let in ahead of the port filter")
	}

	ipt := renderRules(rs, false)
	for _, want := range []string{
		"-p tcp --syn -m conntrack --ctstate NEW -m hashlimit",
		"-A XPGUARD -p udp --dport 32768:60999 -m conntrack --ctstate UNTRACKED -m multiport --sports 19,53,123,161,389,1900,3283,3389,3702,5353,10001,11211,37810 -j RETURN",
		"-A XPGUARD_EXEMPT -p udp --dport 32768:60999 -m conntrack --ctstate UNTRACKED",
	} {
		if !strings.Contains(ipt, want) {
			t.Errorf("iptables missing %q in\n%s", want, ipt)
		}
	}
	raw := renderRaw(rs)
	if !strings.Contains(raw, "-A XPGUARD_RAW ! -i lo -p udp --dport 32768:60999 -m multiport --sports 19,53,123,161,389,1900,3283,3389,3702,5353,10001,11211,37810 -j CT --notrack") {
		t.Errorf("raw:\n%s", raw)
	}
	if len(ReflectionPorts) > 15 {
		t.Error("iptables multiport takes at most 15 ports")
	}

	// Off (CSF owns the rules): nothing is untracked.
	rs.ReflectGuard = false
	if strings.Contains(rs.Render(), "notrack") || strings.Contains(renderRaw(rs), "notrack") || strings.Contains(renderRules(rs, false), "UNTRACKED") {
		t.Error("reflection guard rendered while off")
	}
	// A bad or missing range falls back to the Linux default.
	for _, v := range []string{"", "junk", "80-90", "60000-1000"} {
		if lo, hi := (Ruleset{LocalPorts: v}).localPortRange(); lo != 32768 || hi != 60999 {
			t.Errorf("%q: %d-%d", v, lo, hi)
		}
	}
	if lo, hi := (Ruleset{LocalPorts: "1024-65000"}).localPortRange(); lo != 1024 || hi != 65000 {
		t.Errorf("custom range: %d-%d", lo, hi)
	}

	nftBin := FindNFT()
	if nftBin.Bin == "" || os.Geteuid() != 0 {
		return
	}
	rs.ReflectGuard = true
	cmd := exec.Command(nftBin.Bin, "-c", "-f", "-")
	cmd.Stdin = strings.NewReader(rs.Render())
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("nft rejected ruleset: %v\n%s", err, out)
	}
}

func TestTempBansCapped(t *testing.T) {
	m := map[string]time.Duration{}
	for i := 0; i < 10; i++ {
		m[fmt.Sprintf("198.51.100.%d", i)] = time.Duration(i) * time.Minute
	}
	if n := capTempBans(m, 20); n != 0 || len(m) != 10 {
		t.Fatalf("under the cap: dropped %d", n)
	}
	if n := capTempBans(m, 4); n != 6 || len(m) != 4 {
		t.Fatalf("dropped %d, kept %d", n, len(m))
	}
	for i := 6; i < 10; i++ {
		if _, ok := m[fmt.Sprintf("198.51.100.%d", i)]; !ok {
			t.Errorf("ban with the longest time left (%d) dropped", i)
		}
	}
	if maxTempBans >= ipsetMaxElem {
		t.Errorf("cap %d not below the set size %d", maxTempBans, ipsetMaxElem)
	}
}

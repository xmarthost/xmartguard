package firewall

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParsePorts(t *testing.T) {
	got, err := ParsePorts(" 22, 8080;80 1000-2000,22 ")
	if err != nil || strings.Join(got, ",") != "22,8080,80,1000-2000" {
		t.Fatalf("%v %v", got, err)
	}
	for _, bad := range []string{"0", "65536", "80-20", "ssh", "1-"} {
		if _, err := ParsePorts(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, err := (AllowOpts{Proto: "icmp"}).clean(); err == nil {
		t.Error("icmp accepted")
	}
	if o, err := (AllowOpts{Proto: "Any", Dir: "both"}).clean(); err != nil || o != (AllowOpts{}) {
		t.Errorf("%+v %v", o, err)
	}
}

func TestAdvancedAllowRender(t *testing.T) {
	rs := Ruleset{
		Allow: []string{"198.51.100.9"},
		AllowRules: []Rule{
			{Kind: KindAllow, CIDR: "203.0.113.7", Proto: "tcp", Ports: "22,2000-2100", Dir: DirIn},
			{Kind: KindAllow, CIDR: "203.0.113.8", Ports: "53", Dir: DirOut},
			{Kind: KindAllow, CIDR: "2001:db8::1", Proto: "udp"},
		},
		Ports: &PortFilter{TCPIn: []string{"80"}, TCPOut: []string{"443"}},
	}
	ipt := renderRules(rs, false)
	for _, want := range []string{
		"-A XPGUARD -s 203.0.113.7 -p tcp -m multiport --dports 22,2000:2100 -j RETURN",
		"-A XPGUARD_OUT -d 198.51.100.9 -j RETURN",
		"-A XPGUARD_OUT -d 203.0.113.8 -p tcp -m multiport --dports 53 -j RETURN",
		"-A XPGUARD_OUT -d 203.0.113.8 -p udp -m multiport --dports 53 -j RETURN",
	} {
		if !strings.Contains(ipt, want) {
			t.Errorf("iptables: missing %q\n%s", want, ipt)
		}
	}
	if strings.Contains(ipt, "-s 203.0.113.8") || strings.Contains(ipt, "-d 203.0.113.7") || strings.Contains(ipt, "2001:db8") {
		t.Errorf("rule in the wrong direction or family:\n%s", ipt)
	}
	if v6 := renderRules(rs, true); !strings.Contains(v6, "-A XPGUARD -s 2001:db8::1 -p udp -j RETURN") || !strings.Contains(v6, "-A XPGUARD_OUT -d 2001:db8::1 -p udp -j RETURN") {
		t.Errorf("ip6tables:\n%s", v6)
	}
	nft := rs.Render()
	for _, want := range []string{
		"ip saddr 203.0.113.7 tcp dport { 22, 2000-2100 } accept",
		"ip daddr 203.0.113.8 meta l4proto { tcp, udp } th dport { 53 } accept",
		"ip6 saddr 2001:db8::1 meta l4proto udp accept",
		"ip daddr 198.51.100.9 accept",
	} {
		if !strings.Contains(nft, want) {
			t.Errorf("nft: missing %q\n%s", want, nft)
		}
	}
}

// A whitelisted country: every address of it is allowed and shown as
// WHITELIST-COUNTRY, and never banned automatically.
func TestWhitelistCountry(t *testing.T) {
	providers(t, func(t *testing.T, provider string) {
		m := newManager(t, provider)
		geoDir := t.TempDir()
		os.WriteFile(filepath.Join(geoDir, "zz.zone"), []byte("10.99.0.0/30\n"), 0o600)
		m.Geo = &Geo{Dir: geoDir, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
		if _, err := m.Settings.Patch([]byte(`{"firewall":{"ignored_countries":["ZZ"]}}`)); err != nil {
			t.Fatal(err)
		}
		c, err := m.Check("10.99.0.2")
		if err != nil || c.Status != "allowed" || c.Country != "ZZ" || strings.Join(c.Found, ",") != "WHITELIST-COUNTRY" {
			t.Fatalf("%+v %v", c, err)
		}
		m.AutoBan("10.99.0.2", "brute force", "lfd")
		if r, _ := m.rules(KindTempBan); len(r) != 0 {
			t.Fatalf("whitelisted country banned: %+v", r)
		}
		m.Add(KindDeny, "10.99.0.2", "manual", 0)
		if c, _ := m.Check("10.99.0.2"); c.Status != "allowed" || strings.Join(c.Found, ",") != "BLACKLIST,WHITELIST-COUNTRY" {
			t.Fatalf("%+v", c)
		}
	})
}

// Advanced whitelist entries let an address in on their ports only; the
// rest of its traffic still meets the blacklist.
func TestAdvancedAllowOnKernel(t *testing.T) {
	if os.Getenv("XG_DESTRUCTIVE_TESTS") != "1" {
		t.Skip("set XG_DESTRUCTIVE_TESTS=1")
	}
	providers(t, func(t *testing.T, provider string) {
		m := newManager(t, provider)
		in := netns(t)
		for _, p := range []string{"8081", "8082"} {
			l, err := net.Listen("tcp", "0.0.0.0:"+p)
			if err != nil {
				t.Skip("port busy")
			}
			defer l.Close()
			go http.Serve(l, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "site") }))
		}
		if _, err := m.Settings.Patch([]byte(`{"firewall":{"enabled":true}}`)); err != nil {
			t.Fatal(err)
		}
		get := func(p string) string {
			o, _ := in("curl", "-s", "-m", "2", "http://10.99.0.1:"+p+"/")
			return string(o)
		}
		if _, err := m.Add(KindDeny, "10.99.0.2", "", 0); err != nil {
			t.Fatal(err)
		}
		if get("8081") == "site" {
			t.Fatalf("blacklist not applied\n%s", kernelDump(m))
		}
		r, err := m.AddAllow("10.99.0.2", "ssh only", AllowOpts{Proto: "tcp", Ports: "8081", Dir: "in"})
		if err != nil || r.Ports != "8081" {
			t.Fatalf("%+v %v", r, err)
		}
		if get("8081") != "site" {
			t.Fatalf("advanced allow not applied\n%s", kernelDump(m))
		}
		if get("8082") == "site" {
			t.Fatalf("other port let in\n%s", kernelDump(m))
		}
		if l, _ := m.List(KindAllow); len(l) != 1 || l[0].Proto != "tcp" || l[0].Dir != "in" {
			t.Fatalf("%+v", l)
		}
		m.Remove(KindDeny, "10.99.0.2")
		if c, _ := m.Check("10.99.0.2"); c.Status != "allowed only for TCP port 8081 IN" {
			t.Fatalf("%+v", c)
		}
		m.Add(KindDeny, "10.99.0.2", "", 0)
		if c, _ := m.Check("10.99.0.2"); c.Status != "blocked" || strings.Join(c.Found, ",") != "BLACKLIST,WHITELIST" {
			t.Fatalf("%+v", c)
		}
	})
}

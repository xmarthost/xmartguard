package firewall

import (
	"os/exec"
	"strings"
	"testing"
	"time"
)

// A site calling a third-party API whose address is on the IPDB, deny or
// ban lists still gets the answer; new connections from that address are
// still dropped.
func TestAnswersFromListedAddressesOnKernel(t *testing.T) {
	providers(t, func(t *testing.T, provider string) {
		m := newManager(t, provider)
		m.IPDB = &IPDB{}
		sh := func(args ...string) error { return exec.Command(args[0], args[1:]...).Run() }
		_ = sh("ip", "netns", "del", "xgapi")
		if sh("ip", "netns", "add", "xgapi") != nil {
			t.Skip("no netns support")
		}
		defer sh("ip", "netns", "del", "xgapi")
		defer sh("ip", "link", "del", "xga0")
		for _, c := range [][]string{
			{"ip", "link", "add", "xga0", "type", "veth", "peer", "name", "xga1"},
			{"ip", "link", "set", "xga1", "netns", "xgapi"},
			{"ip", "addr", "add", "10.98.0.1/30", "dev", "xga0"},
			{"ip", "link", "set", "xga0", "up"},
			{"ip", "netns", "exec", "xgapi", "ip", "addr", "add", "10.98.0.2/30", "dev", "xga1"},
			{"ip", "netns", "exec", "xgapi", "ip", "link", "set", "xga1", "up"},
			{"ip", "netns", "exec", "xgapi", "ip", "link", "set", "lo", "up"},
		} {
			if err := sh(c...); err != nil {
				t.Skipf("netns setup failed: %v", c)
			}
		}
		// The "API" in the namespace, and a listener on the host.
		api := exec.Command("ip", "netns", "exec", "xgapi", "python3", "-m", "http.server", "--bind", "10.98.0.2", "8443")
		if err := api.Start(); err != nil {
			t.Skip("python3 not available")
		}
		defer api.Process.Kill()
		host := exec.Command("python3", "-m", "http.server", "--bind", "10.98.0.1", "8444")
		if err := host.Start(); err != nil {
			t.Fatal(err)
		}
		defer host.Process.Kill()
		time.Sleep(time.Second)

		call := func() bool {
			return sh("curl", "-s", "-o", "/dev/null", "-m", "3", "http://10.98.0.2:8443/") == nil
		}
		inbound := func() bool {
			return sh("ip", "netns", "exec", "xgapi", "curl", "-s", "-o", "/dev/null", "-m", "3", "http://10.98.0.1:8444/") == nil
		}
		if !call() || !inbound() {
			t.Fatal("test network does not work without lists")
		}
		if _, err := m.ApplyIPDB("v1", []string{"10.98.0.2 ZZ"}); err != nil {
			t.Fatal(err)
		}
		if _, err := m.Add(KindTempBan, "10.98.0.2", "test", 30*time.Minute); err != nil {
			t.Fatal(err)
		}
		if dump := kernelDump(m); !strings.Contains(dump, "10.98.0.2") {
			t.Fatalf("address not listed:\n%s", dump)
		}
		if !call() {
			t.Error("the answer of a listed API server was dropped")
		}
		if inbound() {
			t.Error("a listed address could open a connection")
		}
	})
}

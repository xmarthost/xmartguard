package firewall

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// Docker's own chains (nat DOCKER with its port DNAT) survive everything
// the agent does to the firewall: apply, CAPTCHA/DoS/port filter changes,
// switching provider and turning the firewall off.
func TestDockerChainsSurvive(t *testing.T) {
	if os.Getenv("XG_DESTRUCTIVE_TESTS") != "1" {
		t.Skip("changes the nat table of this machine; set XG_DESTRUCTIVE_TESTS=1")
	}
	providers(t, func(t *testing.T, provider string) {
		m := newManager(t, provider)
		sh := func(a ...string) string { o, _ := exec.Command(a[0], a[1:]...).CombinedOutput(); return string(o) }
		sh("iptables", "-t", "nat", "-N", "DOCKER")
		sh("iptables", "-t", "nat", "-A", "DOCKER", "-p", "tcp", "-d", "127.0.0.1", "--dport", "18080", "-j", "DNAT", "--to-destination", "172.18.0.3:8080")
		sh("iptables", "-t", "nat", "-A", "PREROUTING", "-m", "addrtype", "--dst-type", "LOCAL", "-j", "DOCKER")
		defer sh("iptables", "-t", "nat", "-F", "DOCKER")
		defer sh("iptables", "-t", "nat", "-D", "PREROUTING", "-m", "addrtype", "--dst-type", "LOCAL", "-j", "DOCKER")
		check := func(step string) {
			out := sh("iptables", "-t", "nat", "-S")
			if !strings.Contains(out, "-A DOCKER") {
				t.Fatalf("%s: DOCKER chain gone:\n%s", step, out)
			}
		}
		steps := []struct {
			name, patch string
		}{
			{"enable", `{"firewall":{"enabled":true}}`},
			{"captcha", `{"firewall":{"captcha":true,"dos":true}}`},
			{"captcha off", `{"firewall":{"captcha":false}}`},
			{"ports", `{"firewall":{"port_filter":true}}`},
		}
		for _, s := range steps {
			m.Settings.Patch([]byte(s.patch))
			if err := m.Apply(); err != nil {
				t.Logf("%s: apply: %v", s.name, err)
			}
			check(s.name)
		}
		other := ProviderNFTables
		if provider == other {
			other = ProviderIPTables
		}
		m.Settings.Patch([]byte(`{"firewall":{"provider":"` + other + `"}}`))
		m.Apply()
		check("switch provider")
		m.Settings.Patch([]byte(`{"firewall":{"enabled":false}}`))
		m.Apply()
		check("disable")
	})
}

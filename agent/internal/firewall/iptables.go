package firewall

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Backend is a packet-filtering provider.
type Backend interface {
	Name() string
	Available() error
	Apply(Ruleset) error
	Remove() error
	AddTempBan(ip string, seconds int) error
	TempBanned() ([]string, error)
	Counters() map[string]uint64
	// IPDBCounters returns packets dropped per IPDB list entry.
	IPDBCounters() map[string]uint64
	// Healthy reports whether our rules are still loaded (CSF/firewalld
	// restarts can flush them).
	Healthy() bool
}

// Provider names.
const (
	ProviderIPTables = "iptables"
	ProviderNFTables = "nftables"
)

// ---------------------------------------------------------------- nftables adapter

func (n NFT) Name() string { return ProviderNFTables }

func (n NFT) Available() error {
	if n.Bin == "" {
		return fmt.Errorf("nftables (nft) is not installed")
	}
	return nil
}

func (n NFT) AddTempBan(ip string, seconds int) error {
	set := "tempban4"
	if strings.Contains(ip, ":") {
		set = "tempban6"
	}
	return n.AddElement(set, fmt.Sprintf("%s timeout %ds", ip, seconds))
}

func (n NFT) TempBanned() ([]string, error) {
	a, err := n.SetElements("tempban4")
	if err != nil {
		return nil, err
	}
	b, _ := n.SetElements("tempban6")
	return append(a, b...), nil
}

func (n NFT) Healthy() bool {
	if n.Bin == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := n.run(ctx, "", "list", "chain", "inet", Table, "input")
	return err == nil
}

// ---------------------------------------------------------------- iptables + ipset

// Chain names and ipset names used by the iptables provider.
const (
	ChainMain = "XMARTGUARD"
	ChainDoS  = "XMARTGUARD_DOS"
)

type ipset struct {
	name, typ, family string
	timeout, counters bool
}

func ipsets() []ipset {
	return []ipset{
		{"xg_allow4", "hash:net", "inet", false, false}, {"xg_allow6", "hash:net", "inet6", false, false},
		{"xg_deny4", "hash:net", "inet", false, false}, {"xg_deny6", "hash:net", "inet6", false, false},
		{"xg_tallow4", "hash:ip", "inet", true, false}, {"xg_tallow6", "hash:ip", "inet6", true, false},
		{"xg_tban4", "hash:ip", "inet", true, false}, {"xg_tban6", "hash:ip", "inet6", true, false},
		{"xg_cblock4", "hash:net", "inet", false, false}, {"xg_callow4", "hash:net", "inet", false, false},
		{"xg_ipdb4", "hash:net", "inet", false, true}, {"xg_ipdb6", "hash:net", "inet6", false, true},
	}
}

// IPTables drives iptables/ip6tables with ipset. It owns only the
// XMARTGUARD chains (jumped to from the top of INPUT) and the xg_* sets.
type IPTables struct {
	IPT, IP6T, Restore, Restore6, IPSet string
}

// FindIPTables locates the binaries.
func FindIPTables() IPTables {
	look := func(names ...string) string {
		for _, n := range names {
			if p, err := exec.LookPath(n); err == nil {
				return p
			}
		}
		return ""
	}
	return IPTables{
		IPT: look("iptables"), IP6T: look("ip6tables"),
		Restore: look("iptables-restore"), Restore6: look("ip6tables-restore"),
		IPSet: look("ipset"),
	}
}

func (t IPTables) Name() string { return ProviderIPTables }

func (t IPTables) Available() error {
	switch {
	case t.IPT == "" || t.Restore == "":
		return fmt.Errorf("iptables is not installed")
	case t.IPSet == "":
		return fmt.Errorf("ipset is not installed (dnf install ipset)")
	}
	return nil
}

func run(ctx context.Context, stdin, bin string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("%s %s: %v: %s", bin, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

func ctx60() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 60*time.Second)
}

// renderIPSet builds an `ipset restore` script that swaps fresh contents in.
func renderIPSet(r Ruleset) string {
	a4, a6 := split(append(append([]string{}, r.Allow...), r.Ignore...))
	d4, d6 := split(r.Deny)
	cb4, _ := split(r.CountryBlock)
	ca4, _ := split(r.CountryAllow)
	p4, p6 := split(r.IPDB)
	timed := func(m map[string]time.Duration, v6 bool) []string {
		var out []string
		for ip, d := range m {
			if strings.Contains(ip, ":") != v6 || d < time.Second {
				continue
			}
			out = append(out, fmt.Sprintf("%s timeout %d", ip, int(d.Seconds())))
		}
		sort.Strings(out)
		return out
	}
	content := map[string][]string{
		"xg_allow4": a4, "xg_allow6": a6, "xg_deny4": d4, "xg_deny6": d6,
		"xg_tallow4": timed(r.TempAllow, false), "xg_tallow6": timed(r.TempAllow, true),
		"xg_tban4": timed(r.TempBan, false), "xg_tban6": timed(r.TempBan, true),
		"xg_cblock4": cb4, "xg_callow4": ca4, "xg_ipdb4": p4, "xg_ipdb6": p6,
	}
	var b strings.Builder
	for _, s := range ipsets() {
		opts := fmt.Sprintf("%s family %s maxelem 1048576", s.typ, s.family)
		if s.timeout {
			opts += " timeout 0"
		}
		if s.counters {
			opts += " counters"
		}
		fmt.Fprintf(&b, "create %s %s -exist\n", s.name, opts)
		tmp := s.name + "_n"
		fmt.Fprintf(&b, "create %s %s -exist\nflush %s\n", tmp, opts, tmp)
		for _, e := range content[s.name] {
			fmt.Fprintf(&b, "add %s %s -exist\n", tmp, e)
		}
		fmt.Fprintf(&b, "swap %s %s\ndestroy %s\n", tmp, s.name, tmp)
	}
	return b.String()
}

// renderRules builds an iptables-restore --noflush script for one family.
func renderRules(r Ruleset, v6 bool) string {
	sfx := "4"
	if v6 {
		sfx = "6"
	}
	var b strings.Builder
	b.WriteString("*filter\n")
	fmt.Fprintf(&b, ":%s - [0:0]\n:%s - [0:0]\n", ChainMain, ChainDoS)
	add := func(rule string) { fmt.Fprintf(&b, "-A %s %s\n", ChainMain, rule) }
	add("-i lo -j RETURN")
	add("-m set --match-set xg_allow" + sfx + " src -j RETURN")
	add("-m set --match-set xg_tallow" + sfx + " src -j RETURN")
	// drop logs a rate-limited sample (kernel debug level, so syslog does not
	// store it by default) for the live monitors, then drops.
	drop := func(match, comment, prefix string) {
		if r.LogDrops {
			add(fmt.Sprintf(`%s -m limit --limit %d/sec --limit-burst %d -j LOG --log-prefix "%s" --log-level 7`, match, LogRate, LogRate*2, prefix))
		}
		add(fmt.Sprintf(`%s -m comment --comment "%s" -j DROP`, match, comment))
	}
	if len(r.IPDB) > 0 {
		drop("-m set --match-set xg_ipdb"+sfx+" src", "xg-ipdb", LogPrefixIPDB)
	}
	drop("-m set --match-set xg_deny"+sfx+" src", "xg-deny", LogPrefixDeny)
	drop("-m set --match-set xg_tban"+sfx+" src", "xg-tempban", LogPrefixTempBan)
	if !v6 && len(r.CountryBlock) > 0 {
		if len(r.CountryAllow) > 0 {
			add("-m set --match-set xg_callow4 src -j RETURN")
		}
		drop("-m set --match-set xg_cblock4 src", "xg-country", LogPrefixCountry)
	}
	if r.DoS {
		ban := r.DoSBanSeconds
		if ban <= 0 {
			ban = 600
		}
		add(fmt.Sprintf("-p tcp -m conntrack --ctstate NEW -m hashlimit --hashlimit-above %d/minute --hashlimit-burst %d --hashlimit-mode srcip --hashlimit-name xgdos%s -j %s",
			r.DoSPerMinute, r.DoSPerMinute/2+1, sfx, ChainDoS))
		fmt.Fprintf(&b, "-A %s -j SET --add-set xg_tban%s src --exist --timeout %d\n", ChainDoS, sfx, ban)
		fmt.Fprintf(&b, "-A %s -m comment --comment \"xg-dos\" -j DROP\n", ChainDoS)
	}
	b.WriteString("COMMIT\n")
	return b.String()
}

func (t IPTables) families() []struct {
	ipt, restore string
	v6           bool
} {
	out := []struct {
		ipt, restore string
		v6           bool
	}{{t.IPT, t.Restore, false}}
	if t.IP6T != "" && t.Restore6 != "" {
		out = append(out, struct {
			ipt, restore string
			v6           bool
		}{t.IP6T, t.Restore6, true})
	}
	return out
}

func (t IPTables) Apply(r Ruleset) error {
	if err := t.Available(); err != nil {
		return err
	}
	ctx, cancel := ctx60()
	defer cancel()
	if _, err := run(ctx, renderIPSet(r), t.IPSet, "restore"); err != nil {
		return err
	}
	for _, f := range t.families() {
		if _, err := run(ctx, renderRules(r, f.v6), f.restore, "--noflush"); err != nil {
			if !r.LogDrops {
				return err
			}
			// The LOG target is unavailable (some containers): load without it.
			r.LogDrops = false
			if _, err2 := run(ctx, renderRules(r, f.v6), f.restore, "--noflush"); err2 != nil {
				return err
			}
		}
		if _, err := run(ctx, "", f.ipt, "-w", "-C", "INPUT", "-j", ChainMain); err != nil {
			if _, err := run(ctx, "", f.ipt, "-w", "-I", "INPUT", "1", "-j", ChainMain); err != nil {
				return err
			}
		}
	}
	return nil
}

func (t IPTables) Remove() error {
	if t.IPT == "" {
		return nil
	}
	ctx, cancel := ctx60()
	defer cancel()
	for _, f := range t.families() {
		for i := 0; i < 10; i++ { // remove every jump, however many were added
			if _, err := run(ctx, "", f.ipt, "-w", "-D", "INPUT", "-j", ChainMain); err != nil {
				break
			}
		}
		for _, c := range []string{ChainMain, ChainDoS} {
			_, _ = run(ctx, "", f.ipt, "-w", "-F", c)
		}
		for _, c := range []string{ChainMain, ChainDoS} {
			_, _ = run(ctx, "", f.ipt, "-w", "-X", c)
		}
	}
	if t.IPSet != "" {
		for _, s := range ipsets() {
			_, _ = run(ctx, "", t.IPSet, "destroy", s.name)
			_, _ = run(ctx, "", t.IPSet, "destroy", s.name+"_n")
		}
	}
	return nil
}

func (t IPTables) AddTempBan(ip string, seconds int) error {
	set := "xg_tban4"
	if strings.Contains(ip, ":") {
		set = "xg_tban6"
	}
	ctx, cancel := ctx60()
	defer cancel()
	_, err := run(ctx, "", t.IPSet, "add", set, ip, "timeout", strconv.Itoa(seconds), "-exist")
	return err
}

func (t IPTables) setMembers(name string) ([]string, error) {
	ctx, cancel := ctx60()
	defer cancel()
	out, err := run(ctx, "", t.IPSet, "list", name)
	if err != nil {
		return nil, err
	}
	var res []string
	members := false
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "Members:" {
			members = true
			continue
		}
		if members && line != "" {
			res = append(res, strings.Fields(line)[0])
		}
	}
	return res, nil
}

// IPDBCounters parses `ipset list` member lines: "1.2.3.0/24 packets 5 bytes 300".
func (t IPTables) IPDBCounters() map[string]uint64 {
	out := map[string]uint64{}
	if t.IPSet == "" {
		return out
	}
	ctx, cancel := ctx60()
	defer cancel()
	for _, name := range []string{"xg_ipdb4", "xg_ipdb6"} {
		raw, err := run(ctx, "", t.IPSet, "list", name)
		if err != nil {
			continue
		}
		parseIPSetCounters(string(raw), out)
	}
	return out
}

func parseIPSetCounters(raw string, out map[string]uint64) {
	members := false
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "Members:" {
			members = true
			continue
		}
		f := strings.Fields(line)
		if !members || len(f) < 3 {
			continue
		}
		for i := 1; i+1 < len(f); i++ {
			if f[i] == "packets" {
				if n, err := strconv.ParseUint(f[i+1], 10, 64); err == nil && n > 0 {
					out[f[0]] = n
				}
			}
		}
	}
}

func (t IPTables) TempBanned() ([]string, error) {
	a, err := t.setMembers("xg_tban4")
	if err != nil {
		return nil, err
	}
	b, _ := t.setMembers("xg_tban6")
	return append(a, b...), nil
}

func (t IPTables) Counters() map[string]uint64 {
	out := map[string]uint64{}
	ctx, cancel := ctx60()
	defer cancel()
	for _, f := range t.families() {
		for _, chain := range []string{ChainMain, ChainDoS} {
			raw, err := run(ctx, "", f.ipt, "-w", "-L", chain, "-v", "-n", "-x")
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(raw), "\n") {
				i := strings.Index(line, "/* xg-")
				if i < 0 {
					continue
				}
				name := strings.TrimSuffix(strings.Fields(line[i+3:])[0], "*/")
				fields := strings.Fields(line)
				if len(fields) > 0 {
					n, _ := strconv.ParseUint(fields[0], 10, 64)
					out[strings.TrimSpace(name)] += n
				}
			}
		}
	}
	return out
}

func (t IPTables) Healthy() bool {
	if t.Available() != nil {
		return false
	}
	ctx, cancel := ctx60()
	defer cancel()
	if _, err := run(ctx, "", t.IPT, "-w", "-C", "INPUT", "-j", ChainMain); err != nil {
		return false
	}
	_, err := run(ctx, "", t.IPSet, "list", "-n", "xg_tban4")
	return err == nil
}

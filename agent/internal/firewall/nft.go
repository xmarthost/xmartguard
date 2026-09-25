// Package firewall manages XMart Guard's own nftables table ("inet
// xmartguard"). It never edits other tables, so it coexists with firewalld,
// CSF and cPanel's rules: our drops always apply, our accepts only exempt
// traffic from XMart Guard's own blocks.
package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// Table is the nftables table name owned by the agent.
const Table = "xmartguard"

// Ruleset is the desired state rendered into nft syntax.
type Ruleset struct {
	Allow, Deny, Ignore        []string // IPs/CIDRs (both families)
	TempAllow, TempBan         map[string]time.Duration
	CountryBlock, CountryAllow []string // IPv4 CIDRs
	DoS                        bool
	DoSPerMinute               int
	DoSBanSeconds              int
	// IPDB is the shared blocklist from the portal (both families).
	IPDB []string
	// NoSetCounters disables per-element counters (old nftables versions).
	NoSetCounters bool
}

func split(list []string) (v4, v6 []string) {
	for _, c := range list {
		if strings.Contains(c, ":") {
			v6 = append(v6, c)
		} else {
			v4 = append(v4, c)
		}
	}
	sort.Strings(v4)
	sort.Strings(v6)
	return
}

func splitTimed(m map[string]time.Duration) (v4, v6 []string) {
	for ip, d := range m {
		secs := int(d.Seconds())
		if secs < 1 {
			continue
		}
		el := fmt.Sprintf("%s timeout %ds", ip, secs)
		if strings.Contains(ip, ":") {
			v6 = append(v6, el)
		} else {
			v4 = append(v4, el)
		}
	}
	sort.Strings(v4)
	sort.Strings(v6)
	return
}

func set(b *strings.Builder, name, typ, flags string, elems []string) {
	fmt.Fprintf(b, "\tset %s {\n\t\ttype %s\n", name, typ)
	if flags != "" {
		fmt.Fprintf(b, "\t\tflags %s\n", flags)
		if strings.Contains(flags, "interval") {
			b.WriteString("\t\tauto-merge\n")
		}
	}
	if len(elems) > 0 {
		fmt.Fprintf(b, "\t\telements = { %s }\n", strings.Join(elems, ", "))
	}
	b.WriteString("\t}\n")
}

// counterSet declares an interval set whose elements count matched packets.
func counterSet(b *strings.Builder, name, typ string, counters bool, elems []string) {
	fmt.Fprintf(b, "\tset %s {\n\t\ttype %s\n\t\tflags interval\n", name, typ)
	if counters {
		b.WriteString("\t\tcounter\n")
	}
	if len(elems) > 0 {
		fmt.Fprintf(b, "\t\telements = { %s }\n", strings.Join(elems, ", "))
	}
	b.WriteString("\t}\n")
}

// Render produces an atomic nft script that replaces our table.
func (r Ruleset) Render() string {
	var b strings.Builder
	// "add" then "delete" guarantees the delete succeeds; the whole file is one transaction.
	fmt.Fprintf(&b, "add table inet %s\ndelete table inet %s\ntable inet %s {\n", Table, Table, Table)
	a4, a6 := split(r.Allow)
	d4, d6 := split(r.Deny)
	i4, i6 := split(r.Ignore)
	ta4, ta6 := splitTimed(r.TempAllow)
	tb4, tb6 := splitTimed(r.TempBan)
	cb4, _ := split(r.CountryBlock)
	ca4, _ := split(r.CountryAllow)
	set(&b, "allow4", "ipv4_addr", "interval", append(a4, i4...))
	set(&b, "allow6", "ipv6_addr", "interval", append(a6, i6...))
	set(&b, "deny4", "ipv4_addr", "interval", d4)
	set(&b, "deny6", "ipv6_addr", "interval", d6)
	set(&b, "tempallow4", "ipv4_addr", "timeout", ta4)
	set(&b, "tempallow6", "ipv6_addr", "timeout", ta6)
	set(&b, "tempban4", "ipv4_addr", "timeout", tb4)
	set(&b, "tempban6", "ipv6_addr", "timeout", tb6)
	set(&b, "country_allow4", "ipv4_addr", "interval", ca4)
	set(&b, "country_block4", "ipv4_addr", "interval", cb4)
	p4, p6 := split(Collapse(r.IPDB))
	counterSet(&b, "ipdb4", "ipv4_addr", !r.NoSetCounters, p4)
	counterSet(&b, "ipdb6", "ipv6_addr", !r.NoSetCounters, p6)
	if r.DoS {
		b.WriteString("\tset dos4 {\n\t\ttype ipv4_addr\n\t\tflags dynamic,timeout\n\t\ttimeout 1m\n\t}\n")
		b.WriteString("\tset dos6 {\n\t\ttype ipv6_addr\n\t\tflags dynamic,timeout\n\t\ttimeout 1m\n\t}\n")
	}
	b.WriteString("\tchain input {\n\t\ttype filter hook input priority filter - 5; policy accept;\n")
	b.WriteString("\t\tiifname \"lo\" accept\n")
	b.WriteString("\t\tip saddr @allow4 accept\n\t\tip6 saddr @allow6 accept\n")
	b.WriteString("\t\tip saddr @tempallow4 accept\n\t\tip6 saddr @tempallow6 accept\n")
	b.WriteString("\t\tip saddr @ipdb4 counter drop comment \"xg-ipdb\"\n\t\tip6 saddr @ipdb6 counter drop comment \"xg-ipdb\"\n")
	b.WriteString("\t\tip saddr @deny4 counter drop comment \"xg-deny\"\n\t\tip6 saddr @deny6 counter drop comment \"xg-deny\"\n")
	b.WriteString("\t\tip saddr @tempban4 counter drop comment \"xg-tempban\"\n\t\tip6 saddr @tempban6 counter drop comment \"xg-tempban\"\n")
	if len(cb4) > 0 {
		if len(ca4) > 0 {
			b.WriteString("\t\tip saddr @country_allow4 accept\n")
		}
		b.WriteString("\t\tip saddr @country_block4 counter drop comment \"xg-country\"\n")
	}
	if r.DoS {
		ban := r.DoSBanSeconds
		if ban <= 0 {
			ban = 600
		}
		fmt.Fprintf(&b, "\t\tct state new update @dos4 { ip saddr limit rate over %d/minute burst %d packets } add @tempban4 { ip saddr timeout %ds } counter drop comment \"xg-dos\"\n", r.DoSPerMinute, r.DoSPerMinute/2+1, ban)
		fmt.Fprintf(&b, "\t\tct state new update @dos6 { ip6 saddr limit rate over %d/minute burst %d packets } add @tempban6 { ip6 saddr timeout %ds } counter drop comment \"xg-dos\"\n", r.DoSPerMinute, r.DoSPerMinute/2+1, ban)
	}
	b.WriteString("\t}\n}\n")
	return b.String()
}

// NFT runs the nft binary.
type NFT struct{ Bin string }

// FindNFT locates nft; empty Bin means unavailable.
func FindNFT() NFT {
	for _, p := range []string{"/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"} {
		if _, err := exec.LookPath(p); err == nil {
			return NFT{Bin: p}
		}
	}
	return NFT{}
}

func (n NFT) run(ctx context.Context, stdin string, args ...string) ([]byte, error) {
	if n.Bin == "" {
		return nil, fmt.Errorf("nftables (nft) is not installed")
	}
	cmd := exec.CommandContext(ctx, n.Bin, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return out, fmt.Errorf("nft %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// Apply validates then loads the ruleset atomically.
func (n NFT) Apply(r Ruleset) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	script := r.Render()
	if _, err := n.run(ctx, script, "-c", "-f", "-"); err != nil {
		// nftables < 0.9.5 cannot count per set element: load without counters.
		r.NoSetCounters = true
		script = r.Render()
		if _, err2 := n.run(ctx, script, "-c", "-f", "-"); err2 != nil {
			return err
		}
	}
	_, err := n.run(ctx, script, "-f", "-")
	return err
}

// Remove deletes our table (used when the firewall is disabled).
func (n NFT) Remove() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err := n.run(ctx, fmt.Sprintf("add table inet %s\ndelete table inet %s\n", Table, Table), "-f", "-")
	return err
}

// AddElement inserts into a set without rebuilding the table.
func (n NFT) AddElement(setName, elem string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, err := n.run(ctx, "", "add", "element", "inet", Table, setName, "{ "+elem+" }")
	return err
}

// SetElements lists the addresses currently in a set (timeouts stripped).
func (n NFT) SetElements(setName string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := n.run(ctx, "", "-j", "list", "set", "inet", Table, setName)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		return nil, err
	}
	var res []string
	for _, item := range doc.Nftables {
		raw, ok := item["set"]
		if !ok {
			continue
		}
		var s struct {
			Elem []json.RawMessage `json:"elem"`
		}
		_ = json.Unmarshal(raw, &s)
		for _, e := range s.Elem {
			var plain string
			if json.Unmarshal(e, &plain) == nil {
				res = append(res, plain)
				continue
			}
			var wrapped struct {
				Elem struct {
					Val json.RawMessage `json:"val"`
				} `json:"elem"`
			}
			if json.Unmarshal(e, &wrapped) == nil && json.Unmarshal(wrapped.Elem.Val, &plain) == nil {
				res = append(res, plain)
			}
		}
	}
	return res, nil
}

// IPDBCounters returns packets matched per IPDB set element.
func (n NFT) IPDBCounters() map[string]uint64 {
	out := map[string]uint64{}
	for _, name := range []string{"ipdb4", "ipdb6"} {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		raw, err := n.run(ctx, "", "-j", "list", "set", "inet", Table, name)
		cancel()
		if err == nil {
			parseNFTSetCounters(raw, out)
		}
	}
	return out
}

func parseNFTSetCounters(raw []byte, out map[string]uint64) {
	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if json.Unmarshal(raw, &doc) != nil {
		return
	}
	for _, item := range doc.Nftables {
		rs, ok := item["set"]
		if !ok {
			continue
		}
		var s struct {
			Elem []json.RawMessage `json:"elem"`
		}
		_ = json.Unmarshal(rs, &s)
		for _, e := range s.Elem {
			var w struct {
				Elem struct {
					Val     json.RawMessage `json:"val"`
					Counter struct {
						Packets uint64 `json:"packets"`
					} `json:"counter"`
				} `json:"elem"`
			}
			if json.Unmarshal(e, &w) != nil || w.Elem.Counter.Packets == 0 {
				continue
			}
			if key := nftValue(w.Elem.Val); key != "" {
				out[key] = w.Elem.Counter.Packets
			}
		}
	}
}

// nftValue renders an element value ("1.2.3.4", prefix or range) as text.
func nftValue(v json.RawMessage) string {
	var plain string
	if json.Unmarshal(v, &plain) == nil {
		return plain
	}
	var p struct {
		Prefix *struct {
			Addr string `json:"addr"`
			Len  int    `json:"len"`
		} `json:"prefix"`
		Range []string `json:"range"`
	}
	if json.Unmarshal(v, &p) != nil {
		return ""
	}
	if p.Prefix != nil {
		return fmt.Sprintf("%s/%d", p.Prefix.Addr, p.Prefix.Len)
	}
	if len(p.Range) == 2 {
		return p.Range[0] + "-" + p.Range[1]
	}
	return ""
}

// Counters returns packets dropped per rule comment (xg-deny, xg-tempban, ...).
func (n NFT) Counters() map[string]uint64 {
	out := map[string]uint64{}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	raw, err := n.run(ctx, "", "-j", "list", "chain", "inet", Table, "input")
	if err != nil {
		return out
	}
	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if json.Unmarshal(raw, &doc) != nil {
		return out
	}
	for _, item := range doc.Nftables {
		r, ok := item["rule"]
		if !ok {
			continue
		}
		var rule struct {
			Comment string                       `json:"comment"`
			Expr    []map[string]json.RawMessage `json:"expr"`
		}
		if json.Unmarshal(r, &rule) != nil || rule.Comment == "" {
			continue
		}
		for _, e := range rule.Expr {
			if c, ok := e["counter"]; ok {
				var cnt struct {
					Packets uint64 `json:"packets"`
				}
				_ = json.Unmarshal(c, &cnt)
				out[rule.Comment] += cnt.Packets
			}
		}
	}
	return out
}

// ParseAddr validates an IP or CIDR and returns its canonical form.
func ParseAddr(s string) (string, error) {
	s = strings.TrimSpace(s)
	if ip := net.ParseIP(s); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4.String(), nil
		}
		return ip.String(), nil
	}
	ip, n, err := net.ParseCIDR(s)
	if err != nil {
		return "", fmt.Errorf("invalid IP address or CIDR: %q", s)
	}
	ones, bits := n.Mask.Size()
	if (bits == 32 && ones < 8) || (bits == 128 && ones < 16) {
		return "", fmt.Errorf("CIDR %s is too large", s)
	}
	if ip.To4() != nil && ones == 32 || ip.To4() == nil && ones == 128 {
		return ip.String(), nil
	}
	return n.String(), nil
}

// Contains reports whether ip falls inside addr (IP or CIDR).
func Contains(addr, ip string) bool {
	p := net.ParseIP(ip)
	if p == nil {
		return false
	}
	if _, n, err := net.ParseCIDR(addr); err == nil {
		return n.Contains(p)
	}
	a := net.ParseIP(addr)
	return a != nil && a.Equal(p)
}

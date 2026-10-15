package mail

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// cPanel greylisting (WHM » Greylisting) delays mail from senders it has not
// seen. Mail relays such as MailBaby send from many addresses and retry from
// another one, so their mail can be held for a long time: the relays' own
// cPanel guide adds their networks as Trusted Hosts, which this does for
// the mail relays on the trusted services list.

// WHMAPI runs whmapi1 with JSON output (tests replace it).
var WHMAPI = func(ctx context.Context, args ...string) ([]byte, error) {
	bin := "/usr/local/cpanel/bin/whmapi1"
	if _, err := os.Stat(bin); err != nil {
		return nil, errors.New("not a cPanel server")
	}
	return exec.CommandContext(ctx, bin, append([]string{"--output=json"}, args...)...).Output()
}

type whmReply struct {
	Metadata struct {
		Result int    `json:"result"`
		Reason string `json:"reason"`
	} `json:"metadata"`
	Data struct {
		IPBlocks []struct {
			Low  string `json:"ip_low"`
			High string `json:"ip_high"`
		} `json:"ip_blocks"`
	} `json:"data"`
}

// cidrRange is the first and last address of a network.
func cidrRange(c string) (lo, hi netip.Addr, ok bool) {
	if !strings.Contains(c, "/") {
		a, err := netip.ParseAddr(c)
		return a, a, err == nil
	}
	p, err := netip.ParsePrefix(c)
	if err != nil {
		return lo, hi, false
	}
	p = p.Masked()
	lo, hi = p.Addr(), p.Addr()
	b := hi.AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 0x80 >> (i % 8)
	}
	hi, _ = netip.AddrFromSlice(b)
	return lo, hi, true
}

// SyncGreylistTrusted adds the networks of each relay (name → networks)
// to cPanel's greylisting Trusted Hosts when they are not there yet. It
// returns how many it added; it never removes an entry.
func SyncGreylistTrusted(ctx context.Context, relays map[string][]string) (int, error) {
	if len(relays) == 0 {
		return 0, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	out, err := WHMAPI(ctx, "read_cpgreylist_trusted_hosts")
	if err != nil {
		return 0, err
	}
	var r whmReply
	if err := json.Unmarshal(out, &r); err != nil || r.Metadata.Result != 1 {
		return 0, errors.New("greylisting trusted hosts unavailable: " + r.Metadata.Reason)
	}
	have := map[string]bool{}
	for _, b := range r.Data.IPBlocks {
		lo, err1 := netip.ParseAddr(b.Low)
		hi, err2 := netip.ParseAddr(b.High)
		if err1 == nil && err2 == nil {
			have[lo.String()+"-"+hi.String()] = true
		}
	}
	names := make([]string, 0, len(relays))
	for n := range relays {
		names = append(names, n)
	}
	sort.Strings(names)
	added := 0
	for _, name := range names {
		for _, c := range relays[name] {
			lo, hi, ok := cidrRange(c)
			if !ok || have[lo.String()+"-"+hi.String()] {
				continue
			}
			out, err := WHMAPI(ctx, "create_cpgreylist_trusted_host", "ip="+c, "comment="+name+" (xPGuard)")
			var cr whmReply
			if err != nil || json.Unmarshal(out, &cr) != nil || cr.Metadata.Result != 1 {
				continue // e.g. already covered by a wider entry
			}
			have[lo.String()+"-"+hi.String()] = true
			added++
		}
	}
	return added, nil
}

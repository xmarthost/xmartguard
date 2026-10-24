package firewall

import (
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

// A solved CAPTCHA lets the address past the IPDB only. Before 0.23.15 it
// was a temporary whitelist: every port open, no DoS limit and no new ban
// for hours, which an attacker on a shared server could buy with one solved
// check.
func TestCaptchaPassRendersIPDBOnly(t *testing.T) {
	rs := Ruleset{
		TempBan: map[string]time.Duration{"198.51.100.9": time.Hour}, TempAllow: map[string]time.Duration{},
		CaptchaPass: map[string]time.Duration{"203.0.113.50": time.Hour, "2001:db8::50": time.Hour},
		IPDB:        []string{"203.0.113.0/24", "2001:db8::/48"}, DoS: true, DoSPerMinute: 150,
		Ports:   &PortFilter{TCPIn: []string{"22", "80", "443"}},
		Captcha: &CaptchaRedirect{HTTPPort: 7780, HTTPSPort: 7743, TempBan: true, IPDB: true},
	}
	script := rs.Render()
	for _, want := range []string{"set cpass4", "203.0.113.50 timeout 3600s", "set cpass6",
		"ip saddr != @cpass4 ip saddr @ipdb4 counter jump drop_ipdb", "ip6 saddr != @cpass6 ip6 saddr @ipdb6 counter jump drop_ipdb"} {
		if !strings.Contains(script, want) {
			t.Errorf("nft script missing %q", want)
		}
	}
	if strings.Contains(script, "@cpass4 accept") || strings.Contains(script, "@cpass6 accept") {
		t.Error("a CAPTCHA pass is accepted like a whitelist entry")
	}
	// The redirect: a ban still goes to the check, the IPDB does not.
	ban := strings.Index(script, "ip saddr @tempban4 redirect to :7780")
	ret := strings.Index(script, "ip saddr @cpass4 return")
	ipdb := strings.Index(script, "ip saddr @ipdb4 redirect to :7780")
	if ban < 0 || ret < 0 || ipdb < 0 || !(ban < ret && ret < ipdb) {
		t.Errorf("redirect order: ban %d, pass %d, ipdb %d", ban, ret, ipdb)
	}
	if nft := FindNFT(); nft.Bin != "" && os.Geteuid() == 0 {
		cmd := exec.Command(nft.Bin, "-c", "-f", "-")
		cmd.Stdin = strings.NewReader(script)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("nft rejected ruleset: %v\n%s", err, out)
		}
	}

	for _, v6 := range []bool{false, true} {
		sfx := "4"
		if v6 {
			sfx = "6"
		}
		rules := renderRules(rs, v6)
		if !strings.Contains(rules, "-m set ! --match-set xg_cpass"+sfx+" src -m set --match-set xg_ipdb"+sfx+" src") {
			t.Errorf("iptables %s: IPDB drop does not skip passes:\n%s", sfx, rules)
		}
		if strings.Contains(rules, "xg_cpass"+sfx+" src -j RETURN") || strings.Contains(rules, "xg_cpass"+sfx+" src -j ACCEPT") {
			t.Errorf("iptables %s: a CAPTCHA pass is let through like a whitelist entry", sfx)
		}
		nat := renderNAT(rs, v6)
		ban := strings.Index(nat, "--match-set xg_tban"+sfx+" src -j REDIRECT")
		ret := strings.Index(nat, "--match-set xg_cpass"+sfx+" src -j RETURN")
		ipdb := strings.Index(nat, "--match-set xg_ipdb"+sfx+" src -j REDIRECT")
		if ban < 0 || ret < 0 || ipdb < 0 || !(ban < ret && ret < ipdb) {
			t.Errorf("iptables %s redirect order: ban %d, pass %d, ipdb %d\n%s", sfx, ban, ret, ipdb, nat)
		}
	}
	if !strings.Contains(renderIPSet(rs), "add xg_cpass4_n 203.0.113.50 timeout 3600 -exist") {
		t.Errorf("ipset script misses the pass:\n%s", renderIPSet(rs))
	}
}

// After the solve the address is out of the ban for at most a day; a new
// attack bans it again, ends the pass, and solving again does not lift
// that ban.
func TestCaptchaPassEndsOnNewBan(t *testing.T) {
	providers(t, func(t *testing.T, provider string) {
		m := newManager(t, provider)
		if _, err := m.Settings.Patch([]byte(`{"firewall":{"enabled":true}}`)); err != nil {
			t.Fatal(err)
		}
		if err := m.Apply(); err != nil {
			t.Fatal(err)
		}
		ip := "203.0.113.77"
		m.AutoBan(ip, "5 failed SSH logins in 10 min", "bruteforce")
		if err := m.CaptchaSolved(ip, 7*24*time.Hour); err != nil {
			t.Fatal(err)
		}
		rs, _ := m.List(KindCaptchaPass)
		if len(rs) != 1 || rs[0].ExpiresAt-time.Now().Unix() > int64(MaxCaptchaPass.Seconds())+5 {
			t.Fatalf("pass: %+v", rs)
		}
		if ta, _ := m.List(KindTempAllow); len(ta) != 0 {
			t.Fatalf("a solved CAPTCHA made a temporary allow: %+v", ta)
		}
		if !strings.Contains(kernelDump(m), ip) {
			t.Fatal("pass not in the kernel")
		}
		// It attacks again: banned, the pass ends, a new solve is refused.
		m.AutoBan(ip, "5 failed SSH logins in 10 min", "bruteforce")
		if rs, _ := m.List(KindCaptchaPass); len(rs) != 0 {
			t.Fatalf("pass kept after a new ban: %+v", rs)
		}
		bans, _ := m.List(KindTempBan)
		if len(bans) != 1 || !strings.HasSuffix(bans[0].Comment, afterCaptcha) {
			t.Fatalf("ban: %+v", bans)
		}
		if els, _ := m.Backend().TempBanned(); !contains(els, ip) {
			t.Fatalf("not banned in the kernel: %v", els)
		}
		dump := kernelDump(m)
		for _, l := range strings.Split(dump, "\n") {
			if strings.Contains(l, "cpass") && strings.Contains(l, ip) {
				t.Fatalf("pass left in the kernel: %s", l)
			}
		}
		if err := m.CaptchaSolved(ip, time.Hour); err == nil || !strings.Contains(err.Error(), "attacked after solving") {
			t.Fatalf("second solve: %v", err)
		}
		if err := m.PassRefused(ip); err == nil {
			t.Fatal("PassRefused: nil")
		}
		if c, _ := m.Check(ip); c.Status != "temp-blocked" {
			t.Fatalf("check: %+v", c)
		}
		// Another address with an ordinary ban still passes.
		m.AutoBan("203.0.113.78", "test", "bruteforce")
		if err := m.CaptchaSolved("203.0.113.78", time.Hour); err != nil {
			t.Fatal(err)
		}
	})
}

// Temporary allows that solved CAPTCHAs made before 0.23.15 become passes
// of at most a day; an admin's own temporary allow stays.
func TestOldCaptchaTempAllowsBecomePasses(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XG_STATE_DIR", filepath.Join(dir, "state"))
	t.Setenv("XG_CONFIG_DIR", filepath.Join(dir, "conf"))
	db, err := store.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	st, _ := settings.Load()
	m := &Manager{DB: db, Settings: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	now := time.Now().Unix()
	m.DB.Exec(`INSERT INTO fw_rules (kind, cidr, comment, created_at, expires_at) VALUES ('tempallow','203.0.113.60','solved CAPTCHA',?,?)`, now, now+7*86400)
	m.DB.Exec(`INSERT INTO fw_rules (kind, cidr, comment, created_at, expires_at) VALUES ('tempallow','203.0.113.61','office',?,?)`, now, now+7*86400)
	m.passesFromTempAllows()
	rs, _ := m.List(KindCaptchaPass)
	if len(rs) != 1 || rs[0].CIDR != "203.0.113.60" || rs[0].ExpiresAt > now+int64(MaxCaptchaPass.Seconds())+5 {
		t.Fatalf("passes: %+v", rs)
	}
	ta, _ := m.List(KindTempAllow)
	if len(ta) != 1 || ta[0].CIDR != "203.0.113.61" {
		t.Fatalf("temporary allows: %+v", ta)
	}
}

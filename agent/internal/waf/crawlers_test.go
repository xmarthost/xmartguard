package waf

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xmarthost/xmartguard/agent/internal/settings"
	"github.com/xmarthost/xmartguard/agent/internal/store"
)

// The bot rules test tx.xg_trusted (LiteSpeed ignores ctl:ruleRemoveById),
// never apply to robots.txt and trust Cloudflare's CF-Connecting-IP only.
func TestBotRulesRender(t *testing.T) {
	c := settings.Defaults().WAF
	c.AIBots, c.BotBlocker, c.BotList = true, true, []string{"SemrushBot"}
	out := Render(c, Options{Dir: "/r", Trusted: true})
	for _, id := range []int{IDAIBots, IDCustomBots} {
		i := strings.Index(out, fmt.Sprintf("id:%d,", id))
		if i < 0 {
			t.Fatalf("rule %d not rendered", id)
		}
		if !strings.Contains(out[i:i+600], `SecRule &TX:xg_trusted "@eq 0"`) || !strings.Contains(out[i:i+600], `"!@streq /robots.txt"`) {
			t.Errorf("rule %d does not skip trusted services and robots.txt", id)
		}
	}
	if !strings.Contains(out, fmt.Sprintf("id:%d,phase:1,t:none,pass,nolog,setvar:tx.xg_trusted=1,", IDTrusted)) {
		t.Error("trusted addresses are not marked")
	}
	i := strings.Index(out, fmt.Sprintf("id:%d,", IDTrustedCF))
	if i < 0 || strings.Contains(out[i-200:i], "127.0.0.1") || !strings.Contains(out[i:i+300], "REQUEST_HEADERS:CF-Connecting-IP") || strings.Contains(out[i:i+300], "X-Forwarded-For") {
		t.Error("trust behind Cloudflare must come from CF-Connecting-IP of Cloudflare's own addresses")
	}
}

// On a real Apache: real crawlers (trusted addresses, directly or behind
// Cloudflare) pass, fakes with the same User-Agent are refused, and
// robots.txt is open to all.
func TestRealAndFakeCrawlersOnApache(t *testing.T) {
	if os.Getenv("XG_DESTRUCTIVE_TESTS") != "1" || os.Geteuid() != 0 {
		t.Skip("set XG_DESTRUCTIVE_TESTS=1 (as root) to run")
	}
	tg := Detect()
	if tg.Name != "debian" || !tg.ModSec || exists(tg.IncludeFile) {
		t.Skipf("needs Debian Apache with mod_security2 and no include, detected %+v", tg)
	}
	// A Cloudflare address on the loopback, to connect from.
	const cfAddr = "104.16.0.77"
	if err := exec.Command("ip", "addr", "add", cfAddr+"/32", "dev", "lo").Run(); err != nil {
		t.Skip("can not add a Cloudflare address to the loopback")
	}
	defer exec.Command("ip", "addr", "del", cfAddr+"/32", "dev", "lo").Run()
	dir := t.TempDir()
	os.Chmod(dir, 0o755)
	os.Chmod(filepath.Dir(dir), 0o755)
	t.Setenv("XG_STATE_DIR", filepath.Join(dir, "state"))
	t.Setenv("XG_CONFIG_DIR", filepath.Join(dir, "conf"))
	db, _ := store.Open()
	defer db.Close()
	st, _ := settings.Load()
	st.Patch([]byte(`{"waf":{"upload_scan":false,"ai_bots":true,"bot_blocker":true,"bot_list":["AhrefsBot","SemrushBot"]}}`))
	trusted := []string{"198.51.100.0/24"}
	m := &Manager{DB: db, Settings: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), RulesDir: filepath.Join(dir, "waf"), NoSelfTest: true,
		TrustedIPs: func() []string { return trusted }}
	// The shop filter rule as on the servers (approved there).
	m.Intel = func() *Intel { return &Intel{Enforce: []int{IDShopScrape}} }
	exec.Command("apache2ctl", "start").Run()
	defer exec.Command("apache2ctl", "stop").Run()
	defer func() {
		st.Patch([]byte(`{"waf":{"enabled":false}}`))
		m.Apply()
		exec.Command("a2disconf", "xpguard-waf").Run()
	}()
	apply := func() {
		if err := m.Apply(); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Second)
	}
	send := func(from, uri, ua string, hdr ...string) int {
		d := net.Dialer{Timeout: 3 * time.Second}
		if from != "" {
			d.LocalAddr = &net.TCPAddr{IP: net.ParseIP(from)}
		}
		c, err := d.Dial("tcp", "127.0.0.1:80")
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		req := "GET " + uri + " HTTP/1.1\r\nHost: shop.example.com\r\nUser-Agent: " + ua + "\r\n"
		for _, h := range hdr {
			req += h + "\r\n"
		}
		io.WriteString(c, req+"Connection: close\r\n\r\n")
		line, _ := bufio.NewReader(c).ReadString('\n')
		var code int
		fmt.Sscanf(line, "HTTP/1.1 %d", &code)
		return code
	}
	gpt := "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.3; +https://openai.com/gptbot"
	claude := "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ClaudeBot/1.0; +claudebot@anthropic.com)"
	semrush := "Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)"
	chromeGPT := browserUA + " GPTBot"
	// want 0: served (not refused).
	check := func(name string, got, want int) {
		t.Helper()
		if (want == 0 && (got == 403 || got == 0)) || (want != 0 && got != want) {
			t.Errorf("%s: %d, want %d", name, got, want)
		}
	}

	// Not from a trusted address: fakes.
	apply()
	for _, ua := range []string{gpt, claude, semrush, chromeGPT} {
		check("fake "+ua+" on a page", send("", "/", ua), 403)
		check("fake "+ua+" on robots.txt", send("", "/robots.txt", ua), 0)
	}
	check("plain browser", send("", "/", browserUA), 0)
	// Behind Cloudflare: the crawler's real address decides.
	check("real GPTBot behind Cloudflare", send(cfAddr, "/", gpt, "CF-Connecting-IP: 198.51.100.7"), 0)
	check("real Semrush behind Cloudflare", send(cfAddr, "/", semrush, "CF-Connecting-IP: 198.51.100.8"), 0)
	check("fake GPTBot behind Cloudflare", send(cfAddr, "/", gpt, "CF-Connecting-IP: 203.0.113.9"), 403)
	check("forged X-Forwarded-For behind Cloudflare", send(cfAddr, "/", gpt, "CF-Connecting-IP: 203.0.113.9", "X-Forwarded-For: 198.51.100.7"), 403)
	check("CF-Connecting-IP not from Cloudflare", send("", "/", gpt, "CF-Connecting-IP: 198.51.100.7"), 403)
	// Shop filters (batquitraders.com, 2026-11-03): Google's shopping
	// crawler names no "Googlebot"; from elsewhere it is a scraper.
	storebot := "Mozilla/5.0 (X11; Linux x86_64; Storebot-Google/1.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
	check("fake Storebot-Google on many filter values", send("", "/shop/?filter_product_brand=202,119,197", storebot), 403)
	check("fake Storebot-Google on a sort URL", send("", "/shop/?orderby=date", storebot), 403)
	check("fake GoogleOther on many filter values", send("", "/shop/?filter_product_brand=202,119,197", "Mozilla/5.0 (compatible; GoogleOther)"), 403)

	// From a trusted address: the real crawlers.
	trusted = []string{"127.0.0.0/8"}
	apply()
	for _, ua := range []string{gpt, claude, semrush} {
		check("real "+ua, send("", "/", ua), 0)
	}
	check("real Storebot-Google on many filter values", send("", "/shop/?filter_product_brand=202,119,197", storebot), 0)
	check("real Storebot-Google on many filters", send("", "/shop/?filter_a=1&filter_b=2&filter_c=3", storebot), 0)
	check("real Storebot-Google on a sort URL", send("", "/shop/?orderby=date&per_page=24", storebot), 0)
	check("real GoogleOther on many filter values", send("", "/shop/?filter_product_brand=202,119,197", "Mozilla/5.0 (compatible; GoogleOther)"), 0)
	check("AI crawler from its own network on many filter values", send("", "/shop/?filter_product_brand=202,119,197", gpt), 403)
	check("AI crawler from its own network on a sort URL", send("", "/shop/?orderby=date&per_page=24", gpt), 403)
}

// batquitraders.com (business200, 2026-11-03): Google's crawlers from
// Google's own addresses (66.249.79.x) were refused on brand filter URLs by
// 7700510: Storebot-Google and GoogleOther do not say "Googlebot". The
// shop filter rules now let search engines from their published
// addresses through; the same User-Agent from anywhere else and AI
// crawlers from their own networks are still refused.
func TestShopFilterRulesLetVerifiedSearchEnginesThrough(t *testing.T) {
	c := settings.Defaults().WAF
	c.BadBots = true
	out := Render(c, Options{Dir: "/r", Trusted: true})
	i := strings.Index(out, fmt.Sprintf("id:%d,", IDShopScrape+3000))
	if i < 0 || !strings.Contains(out[i-60:i], `SecRule &TX:xg_trusted "@eq 1"`) || !strings.Contains(out[i:i+400], "setvar:tx.xg_search=1") {
		t.Fatal("verified search engines are not marked")
	}
	for _, id := range []int{IDCrawlerFacets, IDShopScrape, IDShopScrape + 1000} {
		j := strings.Index(out, fmt.Sprintf("id:%d,", id))
		if j < i || !strings.Contains(out[j:j+700], `SecRule &TX:xg_search "@eq 0"`) {
			t.Errorf("rule %d does not skip verified search engines (or runs before the marker)", id)
		}
	}
	if strings.Contains(Render(c, Options{Dir: "/r"}), "xg_search") {
		t.Error("marker rendered without a trusted list")
	}
}

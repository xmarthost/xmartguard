package waf

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Soft blocking (like a graylist): most false positives of the OWASP CRS
// are one weak signal (one critical rule, score 5) in a page view of a real
// visitor, for example a cookie of a shop plugin that looks like SQL. So a
// GET request that only reaches the threshold (below twice it) from a
// visitor with a clean reputation is sent to the portal's CAPTCHA page
// instead of being refused: a person solves it once and goes on, a scanner
// does not. POST requests, real attacks (several rules) and visitors on the
// IPDB, Tor or ban lists are refused as before; visitors who solved the
// CAPTCHA only need to stay below twice the threshold.

const (
	IDSoftVerified = 7700030 // +1 behind a proxy
	IDSoftStrict   = 7700032 // +1 behind a proxy
	IDSoftFlag     = 7700034
	IDSoftDeny     = 7700036
	// IDSoftTrusted: search engine crawlers and other trusted services
	// (official address lists) are never sent to the CAPTCHA page.
	IDSoftTrusted = 7700038
	// IDSoftCaptcha is in the CAPTCHA range: sending a visitor to the
	// CAPTCHA page is not counted as an attack.
	IDSoftCaptcha = 7700905
	// FileStrictIPs lists the addresses with a bad reputation.
	FileStrictIPs = "crs-strict-ips.txt"
)

type softBlockRules struct {
	setup, post string
	files       map[string]string
}

// softBlock renders the soft blocking for the CRS settings and inbound
// threshold in; ok is false when it is off or the CAPTCHA page is not set up.
func (m *Manager) softBlock(crs CRSConfig, in int) (softBlockRules, bool) {
	if crs.SoftBlock == "off" || m.Central == nil {
		return softBlockRules{}, false
	}
	c := m.Central()
	if c == nil || !reCentralURL.MatchString(c.URL) || !reServerID.MatchString(c.ServerID) {
		return softBlockRules{}, false
	}
	score := "TX:BLOCKING_INBOUND_ANOMALY_SCORE" // CRS 4
	if strings.HasPrefix(crs.Version, "3.") {
		score = "TX:ANOMALY_SCORE"
	}
	relaxed := in * 2
	if relaxed < 10 {
		relaxed = 10
	}
	strict := filepath.Join(m.RulesDir, FileStrictIPs)
	pass := filepath.Join(m.RulesDir, FileCaptchaPass)
	proxies := filepath.Join(m.RulesDir, FileProxyRanges)
	trusted := m.trustedList()
	files := map[string]string{
		strict:  AddrFile(m.strictList()),
		pass:    CentralFiles(c)[FileCaptchaPass],
		proxies: strings.Join(ProxyRanges, "\n") + "\n",
	}
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }
	// byAddr runs setvars for an address list, directly and behind a proxy.
	byAddr := func(id int, file, setvars string) {
		w(`SecRule REMOTE_ADDR "@ipMatchFromFile %s" "id:%d,phase:1,pass,t:none,nolog,%s"`, file, id, setvars)
		w(`SecRule REMOTE_ADDR "@ipMatchFromFile %s" "id:%d,phase:1,pass,t:none,nolog,chain"`, proxies, id+1)
		w(`  SecRule REQUEST_HEADERS:CF-Connecting-IP|REQUEST_HEADERS:X-Forwarded-For|REQUEST_HEADERS:X-Real-IP "@rx ^\s*([0-9A-Fa-f:.]{3,45})" "capture,chain"`)
		w(`    SecRule TX:1 "@ipMatchFromFile %s" "t:none,%s"`, file, setvars)
	}
	w("# Soft blocking: weak signals from clean visitors get the CAPTCHA page (xPGuard).")
	byAddr(IDSoftVerified, pass, fmt.Sprintf("setvar:tx.xg_verified=1,setvar:tx.inbound_anomaly_score_threshold=%d", relaxed))
	if len(trusted) > 0 {
		// Same list (and file) as the bot rules use.
		tf := filepath.Join(m.RulesDir, FileTrustedIPs)
		files[tf] = strings.Join(trusted, "\n") + "\n"
		w(`SecRule REMOTE_ADDR "@ipMatchFromFile %s" "id:%d,phase:1,pass,t:none,nolog,setvar:tx.xg_verified=1,setvar:tx.inbound_anomaly_score_threshold=%d"`, tf, IDSoftTrusted, relaxed)
	}
	byAddr(IDSoftStrict, strict, fmt.Sprintf("setvar:tx.xg_strict=1,setvar:tx.inbound_anomaly_score_threshold=%d", in))
	w(`SecRule &TX:xg_strict "@eq 0" "id:%d,phase:1,pass,t:none,nolog,chain"`, IDSoftFlag)
	w(`  SecRule &TX:xg_verified "@eq 0" "t:none,setvar:tx.xg_soft=1,setvar:tx.inbound_anomaly_score_threshold=%d"`, relaxed)

	var p strings.Builder
	pw := func(f string, a ...any) { fmt.Fprintf(&p, f+"\n", a...) }
	pw("# Soft blocking, after the OWASP CRS: requests that reached the strict threshold %d", in)
	pw("# but not %d, from visitors with a clean reputation (xPGuard).", relaxed)
	pw(`SecRule TX:xg_soft "@eq 1" "id:%d,phase:2,t:none,redirect:%s?s=%s&ip=%%{REMOTE_ADDR}&h=%%{REQUEST_HEADERS.Host}&u=%%{REQUEST_URI},log,msg:'xPGuard - weak attack signal: visitor sent to the CAPTCHA (Total Score: %%{%s})',tag:'xpguard/captcha',chain"`,
		IDSoftCaptcha, c.URL, c.ServerID, strings.ToLower(score))
	pw(`  SecRule %s "@ge %d" "t:none,chain"`, score, in)
	pw(`  SecRule REQUEST_METHOD "@rx ^(?:GET|HEAD)$" "t:none"`)
	pw(`SecRule TX:xg_soft "@eq 1" "id:%d,phase:2,t:none,deny,status:403,log,msg:'xPGuard - Inbound Anomaly Score Exceeded (Total Score: %%{%s})',tag:'xpguard/crs',chain"`,
		IDSoftDeny, strings.ToLower(score))
	pw(`  SecRule %s "@ge %d" "t:none"`, score, in)
	return softBlockRules{setup: b.String(), post: p.String(), files: files}, true
}

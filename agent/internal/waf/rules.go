// Package waf manages xPGuard's ModSecurity rule set on Apache (and
// LiteSpeed, which reads the same rules), reads ModSecurity events from the
// web server error log, and bans IPs with repeated failed CMS logins.
//
// All rule ids are in 7700000-7709999. The rules are deliberately
// conservative hardening rules: they protect files and folders that should
// never be served, scan uploads with the agent's malware engine and block
// known abusive tools, so they are safe to enable on shared hosting.
package waf

import (
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"

	"github.com/xmarthost/xmartguard/agent/internal/settings"
)

// Rule id ranges by category.
const (
	IDWhitelist     = 7700001
	IDWhiteDomains  = 7700002
	IDDisable       = 7700003
	IDTrusted       = 7700004
	IDUploadMalware = 7700101
	IDUploadPHP     = 7700102
	IDSensitive     = 7700201
	IDUploadsPHP    = 7700301
	IDXMLRPCMulti   = 7700302
	IDUserEnum      = 7700303
	IDRestUsers     = 7700304
	IDPHPInAssets   = 7700305
	IDHiddenPHP     = 7700306
	IDXMLRPCGet     = 7700307
	IDEmptyUAWP     = 7700308
	IDLoginWP       = 7700401
	IDLoginXMLRPC   = 7700402
	IDLoginJoomla   = 7700403
	IDLoginOpenCart = 7700404
	IDLoginCustom   = 7700405
	IDBadBots       = 7700501
	IDSEOBots       = 7700502
	IDAIBots        = 7700503
	IDCustomBots    = 7700504
	IDWebshell      = 7700601
	IDWebshellDir   = 7700602
	IDExploitProbe  = 7700603
	IDProxyBlocked  = 7700701
	IDGateNoCookie  = 7700902
	IDGateBadCookie = 7700903
)

// RuleInfo describes one of our rules for the settings page.
type RuleInfo struct {
	ID       int    `json:"id"`
	Category string `json:"category"`
	Title    string `json:"title"`
	Action   string `json:"action"`
}

// Catalog lists every rule xPGuard can load.
var Catalog = []RuleInfo{
	{IDUploadMalware, "upload_scan", "Scan uploaded files with the xPGuard malware engine", "block"},
	{IDUploadPHP, "block_php_upload", "Block uploads of PHP files through web forms", "block"},
	{IDSensitive, "sensitive_files", "Block access to .env, .git, config backups, logs and SQL dumps", "block"},
	{IDUploadsPHP, "wordpress", "Block running PHP files inside wp-content/uploads", "block"},
	{IDXMLRPCMulti, "wordpress", "Block XML-RPC system.multicall (password guessing amplification)", "block"},
	{IDUserEnum, "wordpress", "Block WordPress user enumeration (?author=N) for visitors who are not logged in", "block"},
	{IDRestUsers, "wordpress", "Block the REST API user list (/wp-json/wp/v2/users) for visitors who are not logged in", "block"},
	{IDPHPInAssets, "wordpress", "Block running PHP files inside images, fonts, css and js folders of wp-content and wp-includes", "block"},
	{IDHiddenPHP, "wordpress", "Block running hidden PHP files (/.name.php), a common backdoor trick", "block"},
	{IDXMLRPCGet, "wordpress", "Allow only POST requests to xmlrpc.php (GET is used by scanners)", "block"},
	{IDEmptyUAWP, "wordpress", "Block requests without a User-Agent to WordPress PHP files (bots and exploit tools)", "block"},
	{IDLoginWP, "bruteforce", "Count failed WordPress logins", "count"},
	{IDLoginXMLRPC, "bruteforce", "Count WordPress XML-RPC login calls", "count"},
	{IDLoginJoomla, "bruteforce", "Count Joomla administrator logins", "count"},
	{IDLoginOpenCart, "bruteforce", "Count OpenCart administrator logins", "count"},
	{IDLoginCustom, "bruteforce", "Count logins on the other protected login URLs", "count"},
	{IDWebshell, "webshell", "Block requests to well-known web shell files", "block"},
	{IDWebshellDir, "webshell", "Block requests into web shell working folders", "block"},
	{IDExploitProbe, "webshell", "Block probes for well-known exploits (PHPUnit eval-stdin RCE, Laravel Ignition RCE, leaked cloud credentials)", "block"},
	{IDBadBots, "bad_bots", "Block vulnerability scanners and abusive tools", "block"},
	{IDSEOBots, "seo_bots", "Block aggressive SEO crawlers", "block"},
	{IDAIBots, "ai_bots", "Block AI training crawlers", "block"},
	{IDCustomBots, "bot_blocker", "Bad Bot blocker: block the User-Agents in the list", "block"},
	{IDProxyBlocked, "proxy_ip_check", "Block blacklisted visitors behind Cloudflare or a local proxy (real IP from CF-Connecting-IP / X-Forwarded-For)", "block"},
}

// Bot lists (matched case-insensitively as substrings of the User-Agent).
var (
	BadBots = []string{"sqlmap", "nikto", "nmap scripting engine", "masscan", "zgrab", "nuclei", "wpscan", "acunetix",
		"netsparker", "dirbuster", "gobuster", "feroxbuster", "fuzz faster u fool", "whatweb", "jorgee", "zmeu",
		"morfeus", "havij", "w3af", "openvas", "arachni", "skipfish", "commix", "wfuzz"}
	SEOBots = settings.SEOCrawlers
	AIBots  = []string{"gptbot", "ccbot", "bytespider", "amazonbot", "perplexitybot", "claudebot", "anthropic-ai",
		"imagesiftbot", "diffbot", "omgili", "cohere-ai", "meta-externalagent"}
)

// WebshellNames are file names of widely distributed PHP web shells; a
// request for one of them is an attacker looking for a planted backdoor.
var WebshellNames = []string{"c99.php", "c99shell.php", "r57.php", "r57shell.php", "wso.php", "wso2.php", "wso25.php",
	"b374k.php", "alfa.php", "alfav4.php", "alfashell.php", "indoxploit.php", "leafmailer.php", "leaf.php",
	"priv8.php", "marijuana.php", "0byte.php", "bypass.php", "symlink.php", "sym.php", "k2ll33d.php", "gecko.php"}

// knownLogin are login paths with dedicated rules.
var knownLogin = map[string]bool{"/wp-login.php": true, "/xmlrpc.php": true, "/administrator/index.php": true, "/admin/index.php": true}

// Files the rules reference, relative to the rules directory.
const (
	FileBadBots    = "bad-bots.txt"
	FileSEOBots    = "seo-bots.txt"
	FileAIBots     = "ai-bots.txt"
	FileCustomBots = "custom-bots.txt"
	// Proxy IP check: the proxies whose forwarded-for header is trusted,
	// and the addresses to block (the firewall's deny list, bans and IPDB).
	FileProxyRanges = "proxy-ranges.txt"
	FileBlockedIPs  = "blocked-ips.txt"
	FileTrustedIPs  = "trusted-ips.txt"
)

// ProxyRanges are Cloudflare's published networks plus local reverse
// proxies (nginx or LiteSpeed in front of Apache).
var ProxyRanges = []string{"127.0.0.1", "::1",
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
	"190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
	"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
	"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32"}

// placeholderIP keeps an empty list loadable (@ipMatchFromFile refuses an
// empty file); it is a documentation address no visitor has.
const placeholderIP = "192.0.2.255"

// Options tune rendering for what the local ModSecurity supports.
type Options struct {
	Dir         string // where the rules and bot lists live
	InspectPath string // upload approver script
	UploadScan  bool   // false when @inspectFile is unusable
	// Trusted: trusted-ips.txt lists search engine crawlers, uptime monitors
	// and other trusted services; bot rules never apply to them.
	Trusted bool
	// Gate sends visitors of the protected login URLs to the CAPTCHA page
	// until they carry a valid pass cookie (nil = off).
	Gate *Gate
}

// Gate is the login-page CAPTCHA: the cookie values accepted now and the
// CAPTCHA server's ports.
type Gate struct {
	Tokens    []string
	HTTPPort  int
	HTTPSPort int
}

// GateCookie is the cookie a solved login-page CAPTCHA sets.
const GateCookie = "xg_gate"

var reGateToken = regexp.MustCompile(`^[a-f0-9]{16,64}$`)

// isGateRule reports the login-page CAPTCHA redirects, which are not attacks.
func isGateRule(id int) bool { return id >= 7700900 && id <= 7700909 }

// Render builds the rules file for the given settings.
func Render(c settings.WAF, o Options) string {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }
	w("# xPGuard WAF rules. Managed by the xPGuard agent: changes here are overwritten.")
	w("# Configure them in the xPGuard portal (Settings » WAF & Bruteforce).")
	w("")
	if len(c.WhitelistIPs) > 0 {
		ips := make([]string, len(c.WhitelistIPs))
		for i, a := range c.WhitelistIPs {
			ips[i] = modsecAddr(a)
		}
		w(`SecRule REMOTE_ADDR "@ipMatch %s" "id:%d,phase:1,pass,nolog,ctl:ruleRemoveById=7700002-7709999"`, strings.Join(ips, ","), IDWhitelist)
	}
	if len(c.WhitelistDomains) > 0 {
		var alt []string
		for _, d := range c.WhitelistDomains {
			alt = append(alt, strings.ReplaceAll(regexp.QuoteMeta(d), `\*`, `[^.]+`))
		}
		w(`SecRule SERVER_NAME "@rx ^(?:%s)$" "id:%d,phase:1,t:none,t:lowercase,pass,nolog,ctl:ruleRemoveById=7700003-7709999"`, strings.Join(alt, "|"), IDWhiteDomains)
	}
	if o.Trusted {
		// Crawlers and monitors keep their User-Agent: the bot rules, the
		// empty User-Agent rule and the XML-RPC GET rule skip them, and a
		// blacklisted address behind a trusted proxy is still checked.
		w(`SecRule REMOTE_ADDR "@ipMatchFromFile %s/%s" "id:%d,phase:1,t:none,pass,nolog,ctl:ruleRemoveById=%d-%d,ctl:ruleRemoveById=%d,ctl:ruleRemoveById=%d,ctl:ruleRemoveById=%d"`,
			o.Dir, FileTrustedIPs, IDTrusted, IDBadBots, IDCustomBots, IDEmptyUAWP, IDEmptyUAWP+1000, IDXMLRPCGet)
	}
	off := map[int]bool{}
	for _, id := range c.DisabledRules {
		off[id] = true
	}
	// rule writes one of our rules unless it was switched off.
	rule := func(id int, format string, a ...any) {
		if !off[id] {
			w(format, a...)
		}
	}
	ids := append([]int(nil), c.DisabledRules...)
	sort.Ints(ids)
	if len(ids) > 0 {
		// ctl works at run time, so it also disables vendor rules loaded after this file.
		var ctl []string
		for _, id := range ids {
			ctl = append(ctl, fmt.Sprintf("ctl:ruleRemoveById=%d", id))
		}
		w(`SecAction "id:%d,phase:1,pass,nolog,%s"`, IDDisable, strings.Join(ctl, ","))
	}
	if c.UploadScan && o.UploadScan && o.InspectPath != "" {
		w(`SecTmpSaveUploadedFiles On`)
		w(`SecRule FILES_TMPNAMES "@inspectFile %s" "id:%d,phase:2,t:none,deny,status:403,log,msg:'xPGuard - Malware upload blocked',tag:'xpguard/upload'"`, o.InspectPath, IDUploadMalware)
	}
	if c.BlockPHPUpload {
		rule(IDUploadPHP, `SecRule FILES "@rx \.(?:php[0-9]?|phtml|phar|pht|phps)$" "id:%d,phase:2,t:none,t:lowercase,deny,status:403,log,msg:'xPGuard - PHP file upload blocked',tag:'xpguard/upload'"`, IDUploadPHP)
	}
	if c.SensitiveFiles {
		rule(IDSensitive, `SecRule REQUEST_FILENAME "@rx /(?:\.env$|\.git/|\.svn/|\.hg/|\.htpasswd$|\.DS_Store$|\.env\.[a-z0-9_-]+$|[^/]+\.php[0-9]?(?:\.bak|\.old|\.orig|\.save|\.swp|\.txt|\.zip|~)$|debug\.log$|error_log$|[^/]+\.sql(?:\.gz|\.zip)?$)" "id:%d,phase:1,t:none,t:urlDecodeUni,t:lowercase,deny,status:403,log,msg:'xPGuard - Access to sensitive file blocked',tag:'xpguard/files'"`, IDSensitive)
	}
	if c.WordPress {
		rule(IDUploadsPHP, `SecRule REQUEST_FILENAME "@rx /wp-content/uploads/.*\.(?:php[0-9]?|phtml|phar|pht)$" "id:%d,phase:1,t:none,t:urlDecodeUni,t:lowercase,deny,status:403,log,msg:'xPGuard - PHP execution in uploads blocked',tag:'xpguard/wordpress'"`, IDUploadsPHP)
		rule(IDPHPInAssets, `SecRule REQUEST_FILENAME "@rx /(?:wp-content|wp-includes)/(?:[^?]*/)?(?:images?|img|fonts?|css|js)/[^/]*\.(?:php[0-9]?|phtml|phar|pht)$" "id:%d,phase:1,t:none,t:urlDecodeUni,t:lowercase,deny,status:403,log,msg:'xPGuard - PHP execution in an assets folder blocked',tag:'xpguard/wordpress',chain"`, IDPHPInAssets)
		if !off[IDPHPInAssets] {
			// WordPress core's own TinyMCE loader lives in wp-includes/js.
			w(`  SecRule REQUEST_FILENAME "!@endsWith /wp-includes/js/tinymce/wp-tinymce.php" "t:none,t:lowercase"`)
		}
		rule(IDHiddenPHP, `SecRule REQUEST_FILENAME "@rx /\.[^/]+\.(?:php[0-9]?|phtml|phar)$" "id:%d,phase:1,t:none,t:urlDecodeUni,t:lowercase,deny,status:403,log,msg:'xPGuard - Hidden PHP file request blocked',tag:'xpguard/wordpress'"`, IDHiddenPHP)
		if !off[IDXMLRPCGet] {
			w(`SecRule REQUEST_FILENAME "@endsWith /xmlrpc.php" "id:%d,phase:1,t:none,t:lowercase,deny,status:403,log,msg:'xPGuard - XML-RPC accepts only POST',tag:'xpguard/wordpress',chain"`, IDXMLRPCGet)
			w(`  SecRule REQUEST_METHOD "!@streq POST" "t:none"`)
		}
		if !off[IDEmptyUAWP] {
			w(`SecRule REQUEST_FILENAME "@rx /(?:wp-[a-z0-9_-]+\.php|wp-(?:admin|content|includes)/.*\.php)$" "id:%d,phase:1,t:none,t:urlDecodeUni,t:lowercase,deny,status:403,log,msg:'xPGuard - Request without User-Agent to a WordPress file blocked',tag:'xpguard/wordpress',chain"`, IDEmptyUAWP)
			w(`  SecRule &REQUEST_HEADERS:User-Agent "@eq 0" "t:none"`)
			w(`SecRule REQUEST_FILENAME "@rx /(?:wp-[a-z0-9_-]+\.php|wp-(?:admin|content|includes)/.*\.php)$" "id:%d,phase:1,t:none,t:urlDecodeUni,t:lowercase,deny,status:403,log,msg:'xPGuard - Request without User-Agent to a WordPress file blocked',tag:'xpguard/wordpress',chain"`, IDEmptyUAWP+1000)
			w(`  SecRule REQUEST_HEADERS:User-Agent "@rx ^\s*$" "t:none"`)
		}
		if !off[IDXMLRPCMulti] {
			w(`SecRule REQUEST_FILENAME "@endsWith /xmlrpc.php" "id:%d,phase:2,t:none,t:lowercase,deny,status:403,log,msg:'xPGuard - XML-RPC multicall blocked',tag:'xpguard/wordpress',chain"`, IDXMLRPCMulti)
			w(`  SecRule REQUEST_BODY "@contains system.multicall" "t:none,t:lowercase"`)
		}
		// User enumeration: /?author=1 redirects to /author/<login>/ and the
		// REST API lists users; attackers use both to find login names.
		if !off[IDUserEnum] {
			w(`SecRule ARGS_GET:author "@rx ^\s*\d" "id:%d,phase:1,t:none,t:urlDecodeUni,deny,status:403,log,msg:'xPGuard - WordPress user enumeration blocked',tag:'xpguard/wordpress',chain"`, IDUserEnum)
			w(`  SecRule &REQUEST_COOKIES_NAMES:/^wordpress_logged_in_/ "@eq 0" "t:none"`)
		}
		if !off[IDRestUsers] {
			w(`SecRule REQUEST_URI "@rx (?:/wp-json/wp/v2/users|[?&]rest_route=/wp/v2/users)" "id:%d,phase:1,t:none,t:urlDecodeUni,t:lowercase,deny,status:403,log,msg:'xPGuard - WordPress REST user list blocked',tag:'xpguard/wordpress',chain"`, IDRestUsers)
			w(`  SecRule &REQUEST_COOKIES_NAMES:/^wordpress_logged_in_/ "@eq 0" "t:none"`)
		}
	}
	if c.BruteForce {
		// Successful WordPress logins redirect (302); a failed one shows the form again (200).
		if !off[IDLoginWP] {
			w(`SecRule REQUEST_METHOD "@streq POST" "id:%d,phase:3,pass,log,msg:'xPGuard - Failed login: WordPress',tag:'xpguard/login',chain"`, IDLoginWP)
			w(`  SecRule REQUEST_FILENAME "@endsWith /wp-login.php" "t:none,t:lowercase,chain"`)
			w(`  SecRule RESPONSE_STATUS "@streq 200" "t:none"`)
		}
		if !off[IDLoginXMLRPC] {
			w(`SecRule REQUEST_METHOD "@streq POST" "id:%d,phase:2,pass,log,msg:'xPGuard - Login attempt: XML-RPC',tag:'xpguard/login',chain"`, IDLoginXMLRPC)
			w(`  SecRule REQUEST_FILENAME "@endsWith /xmlrpc.php" "t:none,t:lowercase"`)
		}
		if !off[IDLoginJoomla] {
			w(`SecRule REQUEST_METHOD "@streq POST" "id:%d,phase:2,pass,log,msg:'xPGuard - Login attempt: Joomla',tag:'xpguard/login',chain"`, IDLoginJoomla)
			w(`  SecRule REQUEST_FILENAME "@endsWith /administrator/index.php" "t:none,t:lowercase,chain"`)
			w(`  SecRule ARGS:task "@streq login" "t:none,t:lowercase"`)
		}
		if !off[IDLoginOpenCart] {
			w(`SecRule REQUEST_METHOD "@streq POST" "id:%d,phase:2,pass,log,msg:'xPGuard - Login attempt: OpenCart',tag:'xpguard/login',chain"`, IDLoginOpenCart)
			w(`  SecRule REQUEST_FILENAME "@endsWith /admin/index.php" "t:none,t:lowercase,chain"`)
			w(`  SecRule ARGS:route "@rx ^common/login" "t:none,t:lowercase"`)
		}
		var custom []string
		for _, u := range c.LoginURLs {
			if !knownLogin[strings.ToLower(u)] {
				custom = append(custom, regexp.QuoteMeta(strings.ToLower(u)))
			}
		}
		if len(custom) > 0 && !off[IDLoginCustom] {
			w(`SecRule REQUEST_METHOD "@streq POST" "id:%d,phase:2,pass,log,msg:'xPGuard - Login attempt: protected URL',tag:'xpguard/login',chain"`, IDLoginCustom)
			w(`  SecRule REQUEST_FILENAME "@rx (?:%s)$" "t:none,t:urlDecodeUni,t:lowercase"`, strings.Join(custom, "|"))
		}
	}
	if g := o.Gate; g != nil && len(g.Tokens) > 0 && len(c.LoginURLs) > 0 {
		var urls []string
		for _, u := range c.LoginURLs {
			urls = append(urls, regexp.QuoteMeta(strings.ToLower(u)))
		}
		var toks []string
		for _, t := range g.Tokens {
			if reGateToken.MatchString(t) {
				toks = append(toks, t)
			}
		}
		if len(toks) > 0 {
			// Written with what LiteSpeed's own ModSecurity engine also runs
			// (no TX counters or SERVER_PORT): one rule for a missing cookie,
			// one for a wrong or expired one. Always sent to the HTTPS port.
			// Logged so it can be checked; the agent does not count these
			// as attacks (see isGateRule).
			pass := fmt.Sprintf(`(?:^|;)\s*%s=(?:%s)\s*(?:;|$)`, GateCookie, strings.Join(toks, "|"))
			gate := func(id int, cond string) {
				w(`SecRule REQUEST_FILENAME "@rx (?:%s)$" "id:%d,phase:1,t:none,t:urlDecodeUni,t:lowercase,redirect:https://%%{REQUEST_HEADERS.Host}:%d/.xpguard/gate?back=%%{REQUEST_URI},log,msg:'xPGuard - CAPTCHA required for a login page',tag:'xpguard/captcha',chain"`,
					strings.Join(urls, "|"), id, g.HTTPSPort)
				w(`  %s`, cond)
			}
			gate(IDGateNoCookie, `SecRule &REQUEST_HEADERS:Cookie "@eq 0" "t:none"`)
			gate(IDGateBadCookie, fmt.Sprintf(`SecRule REQUEST_HEADERS:Cookie "!@rx %s" "t:none"`, pass))
		}
	}
	if c.Webshell {
		rule(IDWebshell, `SecRule REQUEST_FILENAME "@rx /(?:%s)$" "id:%d,phase:1,t:none,t:urlDecodeUni,t:lowercase,deny,status:403,log,msg:'xPGuard - Web shell request blocked',tag:'xpguard/webshell'"`, strings.Join(quoteAll(WebshellNames), "|"), IDWebshell)
		rule(IDWebshellDir, `SecRule REQUEST_FILENAME "@rx /(?:alfa_data|alfacgiapi|wso_data)/" "id:%d,phase:1,t:none,t:urlDecodeUni,t:lowercase,deny,status:403,log,msg:'xPGuard - Web shell folder request blocked',tag:'xpguard/webshell'"`, IDWebshellDir)
		// Paths only exploit scanners request: PHPUnit's eval-stdin.php
		// (CVE-2017-9841), Laravel Ignition (CVE-2021-3129), leaked credentials.
		rule(IDExploitProbe, `SecRule REQUEST_FILENAME "@rx /(?:vendor/phpunit/phpunit/src/util/php/eval-stdin\.php|_ignition/execute-solution|\.aws/credentials|\.vscode/sftp\.json|sftp-config\.json|\.git-credentials)$" "id:%d,phase:1,t:none,t:urlDecodeUni,t:lowercase,deny,status:403,log,msg:'xPGuard - Exploit probe blocked',tag:'xpguard/webshell'"`, IDExploitProbe)
	}
	bot := func(on bool, file string, id int, what string) {
		if on && !off[id] {
			w(`SecRule REQUEST_HEADERS:User-Agent "@pmFromFile %s/%s" "id:%d,phase:1,t:none,deny,status:403,log,msg:'xPGuard - %s blocked',tag:'xpguard/bot'"`, o.Dir, file, id, what)
		}
	}
	bot(c.BadBots, FileBadBots, IDBadBots, "Bad bot")
	bot(c.SEOBots, FileSEOBots, IDSEOBots, "SEO crawler")
	bot(c.AIBots, FileAIBots, IDAIBots, "AI crawler")
	bot(c.BotBlocker && len(c.BotList) > 0, FileCustomBots, IDCustomBots, "Bad bot")
	if c.ProxyIPCheck && !off[IDProxyBlocked] {
		// Disruptive action and metadata sit on the chain's first rule
		// (ModSecurity 2); the client address is the first one in the header.
		w(`SecRule REMOTE_ADDR "@ipMatchFromFile %s/%s" "id:%d,phase:1,t:none,deny,status:403,log,msg:'xPGuard - Blacklisted IP behind proxy',tag:'xpguard/proxy',chain"`, o.Dir, FileProxyRanges, IDProxyBlocked)
		w(`  SecRule REQUEST_HEADERS:CF-Connecting-IP|REQUEST_HEADERS:X-Forwarded-For|REQUEST_HEADERS:X-Real-IP "@rx ^\s*([0-9A-Fa-f:.]{3,45})" "capture,chain"`)
		w(`    SecRule TX:1 "@ipMatchFromFile %s/%s" "t:none"`, o.Dir, FileBlockedIPs)
	}
	return b.String()
}

// RenderLoginWatch is what stays of xPGuard's rules where another rule set
// (Malware.Expert) replaces them: only the failed-login detectors, which
// pass every request and let the agent ban brute-force attackers.
func RenderLoginWatch(c settings.WAF, replacedBy string) string {
	var b strings.Builder
	b.WriteString("# xPGuard's own blocking rules are off on this server: " + replacedBy + "'s rules are used instead.\n")
	b.WriteString("# Kept: failed-login detection (pass, log only) for the brute-force bans.\n\n")
	if !c.BruteForce {
		return b.String()
	}
	full := Render(settings.WAF{BruteForce: true, LoginURLs: c.LoginURLs, DisabledRules: c.DisabledRules}, Options{})
	keep := false
	for _, l := range strings.Split(full, "\n") {
		if strings.HasPrefix(l, "SecRule ") {
			keep = strings.Contains(l, "tag:'xpguard/login'")
		} else if !strings.HasPrefix(l, "  ") {
			keep = false
		}
		if keep {
			b.WriteString(l + "\n")
		}
	}
	return b.String()
}

// BotFiles returns the bot list files to write next to the rules.
func BotFiles(c settings.WAF) map[string]string {
	join := func(l []string) string { return strings.Join(l, "\n") + "\n" }
	return map[string]string{
		FileBadBots:    join(BadBots),
		FileSEOBots:    join(SEOBots),
		FileAIBots:     join(AIBots),
		FileCustomBots: join(c.BotList),
	}
}

// ProxyFiles returns the proxy IP check lists (blocked: the firewall's
// blocked addresses).
func ProxyFiles(blocked []string) map[string]string {
	var ok []string
	seen := map[string]bool{}
	for _, a := range blocked {
		if a = modsecAddr(a); validAddr(a) && !seen[a] {
			seen[a] = true
			ok = append(ok, a)
		}
	}
	if len(ok) == 0 {
		ok = []string{placeholderIP}
	}
	sort.Strings(ok)
	return map[string]string{
		FileProxyRanges: strings.Join(ProxyRanges, "\n") + "\n", // no host masks
		FileBlockedIPs:  strings.Join(ok, "\n") + "\n",
	}
}

// modsecAddr writes an address the way @ipMatchFromFile accepts it:
// ModSecurity 2 refuses "/32" (IPv4) and "/128" (IPv6) host masks.
func modsecAddr(a string) string {
	if strings.Contains(a, ":") {
		return strings.TrimSuffix(a, "/128")
	}
	return strings.TrimSuffix(a, "/32")
}

func validAddr(a string) bool {
	if net.ParseIP(a) != nil {
		return true
	}
	_, _, err := net.ParseCIDR(a)
	return err == nil
}

func quoteAll(l []string) []string {
	out := make([]string, len(l))
	for i, v := range l {
		out[i] = regexp.QuoteMeta(v)
	}
	return out
}

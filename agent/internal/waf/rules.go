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
	IDWhitelist    = 7700001
	IDWhiteDomains = 7700002
	IDDisable      = 7700003
	IDTrusted      = 7700004
	// IDExempt: the server's own addresses, its fleet, the portal and the
	// firewall whitelist are never inspected (ctl:ruleEngine=Off).
	IDExempt        = 7700006
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
	IDWPCoreDirect  = 7700309
	IDWPAdminFake   = 7700310
	IDWPLookalike   = 7700311
	IDWPUploadsList = 7700312
	IDWPCachePHP    = 7700313
	IDStaticPHP     = 7700321
	IDRepeatDirPHP  = 7700322
	IDHiddenDirPHP  = 7700323
	IDDoubleEncode  = 7700324
	IDLoginWP       = 7700401
	IDLoginXMLRPC   = 7700402
	IDLoginJoomla   = 7700403
	IDLoginOpenCart = 7700404
	IDLoginCustom   = 7700405
	IDBadBots       = 7700501
	IDSEOBots       = 7700502
	IDAIBots        = 7700503
	IDCustomBots    = 7700504
	IDRootProbe     = 7700505
	IDBareMozilla   = 7700506
	IDFakeSearchBot = 7700507
	IDWebshell      = 7700601
	IDWebshellDir   = 7700602
	IDExploitProbe  = 7700603
	IDMalwareExt    = 7700604
	IDProxyBlocked  = 7700701
	// IPDB and Tor: id+1000 checks the real address behind Cloudflare or a
	// local proxy, id+2000 Cloudflare's Tor marker.
	IDIPDBPost = 7700711
	IDTorPost  = 7700712
	IDTorBlock = 7700713
	// Virtual patches: known plugin vulnerabilities blocked at the WAF.
	IDVPGravitySMTP = 7701001
	IDVPFileManager = 7701002
	IDVPRevSlider   = 7701003
	IDVPDuplicator  = 7701004
	IDVPLiteSpeed   = 7701005
	IDGateNoCookie  = 7700902
	IDGateBadCookie = 7700903
	IDCentralGate   = 7700904
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
	{IDWPAdminExcl, "exclusions", "Allow code and HTML in WordPress admin screens of logged-in users (WPCode, theme options, page builders): injection rules skip them", "allow"},
	{IDWPAjaxExcl, "exclusions", "Allow code and HTML in admin-ajax.php / admin-post.php requests of logged-in users sent from the admin screens (editor saves)", "allow"},
	{IDWPRestExcl, "exclusions", "Allow code and HTML in writes to WordPress core REST routes (posts, pages, blocks, templates, media…; WordPress checks the user's rights)", "allow"},
	{IDWPRestMethods, "exclusions", "Allow the HTTP methods (PUT, PATCH, DELETE) and method override headers of the WordPress REST API (Elementor, WooCommerce block checkout)", "allow"},
	{IDWCStoreExcl, "exclusions", "WooCommerce block cart and checkout (Store API): PHP-injection rules skip it (addresses and order notes are stored, never run)", "allow"},
	{IDHostingBase, "exclusions", "Hosting defaults: comments and reviews in Urdu, Arabic or with emoji (941310), crawlers' Accept charset (920600) and JSON in cookies (942550) are not attacks", "allow"},
	{IDCPanelPaths, "exclusions", "cPanel pages reached by the server address (mail autodiscover/autoconfig, suspended page, AutoSSL): numeric Host allowed", "allow"},
	{IDStaticCookies, "exclusions", "Images, styles and scripts: the cookies sent with them are not checked for injections", "allow"},
	{IDWPCommentText, "exclusions", "WordPress comments and WooCommerce reviews: the text, name and website are not checked for SQL injection (WordPress stores them safely; XSS is still checked)", "allow"},
	{IDAdminPanel, "exclusions", "Admin areas of other web apps (SMM panels, Laravel, CodeIgniter): saves from the same admin area with a session skip injection rules", "allow"},
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
	{IDWPCoreDirect, "wordpress", "Block direct requests to PHP files in wp-includes and wp-admin/includes, css, js and images (WordPress hardening guide)", "block"},
	{IDWPAdminFake, "wordpress", "Block PHP files in wp-admin/network and wp-admin/user that are not part of WordPress", "block"},
	{IDWPLookalike, "wordpress", "Block wp-*.php files that imitate WordPress core names (wp-l0gin.php, wp-configs.php, wp-2019.php)", "block"},
	{IDWPUploadsList, "wordpress", "Block folder listings of wp-content/uploads and its year/month folders", "block"},
	{IDWPCachePHP, "wordpress", "Block running PHP files inside wp-content/cache", "block"},
	{IDLoginWP, "bruteforce", "Count failed WordPress logins", "count"},
	{IDLoginXMLRPC, "bruteforce", "Count WordPress XML-RPC login calls", "count"},
	{IDLoginJoomla, "bruteforce", "Count Joomla administrator logins", "count"},
	{IDLoginOpenCart, "bruteforce", "Count OpenCart administrator logins", "count"},
	{IDLoginCustom, "bruteforce", "Count logins on the other protected login URLs", "count"},
	{IDWebshell, "webshell", "Block requests to well-known web shell files", "block"},
	{IDWebshellDir, "webshell", "Block requests into web shell working folders", "block"},
	{IDExploitProbe, "webshell", "Block probes for well-known exploits (PHPUnit eval-stdin RCE, Laravel Ignition RCE, leaked cloud credentials)", "block"},
	{IDFleetNames, "webshell", "Block web shell file names the scanners of your servers found (learned by the portal)", "block"},
	{IDMalwareExt, "webshell", "Block requests into plugin and theme folders that only malware creates (fake plugins, seotheme)", "block"},
	{IDStaticPHP, "generic", "Block running PHP files inside images, img, fonts and css folders of any website", "block"},
	{IDRepeatDirPHP, "generic", "Block PHP requests through repeated folders (/images/images/cache.php), a backdoor search pattern", "block"},
	{IDHiddenDirPHP, "generic", "Block running PHP files inside hidden folders (/.tmb/, /.trash/), except .well-known", "block"},
	{IDDoubleEncode, "generic", "Block double-encoded path traversal (%252e%252e) in the address", "block"},
	{IDBadBots, "bad_bots", "Block vulnerability scanners and abusive tools", "block"},
	{IDRootProbe, "bad_bots", "Block PHP probes on a website's top folder that send neither a User-Agent nor a Referer", "block"},
	{IDBareMozilla, "bad_bots", "Block the fake User-Agent \"Mozilla/5.0\" with nothing after it (scripts pretending to be a browser)", "block"},
	{IDFakeSearchBot, "bot_blocker", "Block fake Googlebot and Bingbot: the User-Agent says so but the address is not on Google's or Microsoft's published list", "block"},
	{IDSEOBots, "seo_bots", "Block aggressive SEO crawlers", "block"},
	{IDAIBots, "ai_bots", "Block AI training crawlers", "block"},
	{IDCustomBots, "bot_blocker", "Bad Bot blocker: block the User-Agents in the list", "block"},
	{IDProxyBlocked, "proxy_ip_check", "Block blacklisted visitors behind Cloudflare or a local proxy (real IP from CF-Connecting-IP / X-Forwarded-For)", "block"},
	{IDIPDBPost, "ipdb_post", "Block POST requests (logins, forms, uploads) from IPDB-listed addresses, also behind Cloudflare", "block"},
	{IDTorPost, "tor", "Tor exit nodes: block POST requests (Tor action \"post\")", "block"},
	{IDTorBlock, "tor", "Tor exit nodes: block every request (Tor action \"block\")", "block"},
	{IDVPGravitySMTP, "virtual_patches", "Gravity SMTP: block its REST API for visitors who are not logged in (unauthenticated system report exposure)", "block"},
	{IDVPFileManager, "virtual_patches", "WP File Manager: block direct requests to the elFinder connector (CVE-2020-25213, unauthenticated upload)", "block"},
	{IDVPRevSlider, "virtual_patches", "Slider Revolution: block the revslider_show_image file download with ../ (arbitrary file read)", "block"},
	{IDVPDuplicator, "virtual_patches", "Duplicator: block duplicator_download with ../ (CVE-2020-11738, arbitrary file read)", "block"},
	{IDVPLiteSpeed, "virtual_patches", "LiteSpeed Cache: block its debug logs in wp-content/litespeed/debug (CVE-2024-44000, session cookie leak)", "block"},
}

// Package is a group of rule categories shown as one card in the portal.
// The portal switches it on by turning on the On categories and off by
// turning off all of them.
type Package struct {
	ID         string   `json:"id"`
	Title      string   `json:"title"`
	Desc       string   `json:"desc"`
	Categories []string `json:"categories"`
	On         []string `json:"on"`
}

// Packages lists xPGuard's rule packages.
var Packages = []Package{
	{"generic", "Generic", "PHP in static, hidden and repeated folders, double-encoded traversal, sensitive files (.env, .git, backups, wp-config.php)",
		[]string{"generic", "sensitive_files"}, []string{"generic", "sensitive_files"}},
	{"wordpress", "WordPress", "PHP in uploads, cache and core folders, fake core files, user enumeration, XML-RPC abuse, folder listings",
		[]string{"wordpress"}, []string{"wordpress"}},
	{"webshell", "Web shells", "Well-known web shell names and folders, names learned from the scanners of all servers, malware plugin folders, exploit probes",
		[]string{"webshell"}, []string{"webshell"}},
	{"scanner", "Scanners", "Vulnerability scanners and attack tools, PHP probes without User-Agent and Referer, fake browser User-Agents",
		[]string{"bad_bots"}, []string{"bad_bots"}},
	{"crawler", "Crawlers", "Fake Googlebot and Bingbot, the Bad Bot blocker list and AI crawlers",
		[]string{"bot_blocker", "ai_bots", "seo_bots"}, []string{"bot_blocker"}},
	{"virtual_patches", "Virtual patches", "Known vulnerabilities of popular WordPress plugins blocked before they reach the plugin",
		[]string{"virtual_patches"}, []string{"virtual_patches"}},
	{"rbl", "IPDB & Tor", "POST requests from addresses on the xPGuard IPDB and visitors from Tor exit nodes (Tor Project list), also behind Cloudflare",
		[]string{"ipdb_post", "tor"}, []string{"ipdb_post"}},
	{"upload", "Uploads", "Uploaded files are scanned for malware; PHP uploads can be refused",
		[]string{"upload_scan", "block_php_upload"}, []string{"upload_scan"}},
	{"proxy", "Proxy IP check", "Blacklisted visitors behind Cloudflare or a local proxy (real address from CF-Connecting-IP / X-Forwarded-For)",
		[]string{"proxy_ip_check"}, []string{"proxy_ip_check"}},
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
	"priv8.php", "marijuana.php", "0byte.php", "bypass.php", "symlink.php", "sym.php", "k2ll33d.php", "gecko.php",
	"shell.php", "alfa-rex.php", "xmrlpc.php", "wp_filemanager.php"}

// MalwareExtDirs are plugin and theme folders that only malware creates
// (fake plugins that hide a backdoor or create administrators).
var MalwareExtDirs = []string{"plugins/hellopress", "plugins/apikey", "plugins/wordpresscore", "themes/seotheme"}

// Files WordPress keeps in wp-admin/network and wp-admin/user; anything else
// there is not WordPress.
var wpAdminNetwork = []string{"about", "admin", "contribute", "credits", "edit", "freedoms", "index", "menu", "plugin-editor",
	"plugin-install", "plugins", "privacy", "profile", "settings", "setup", "site-info", "site-new", "site-settings",
	"site-themes", "site-users", "sites", "theme-editor", "theme-install", "themes", "update-core", "update", "upgrade",
	"user-edit", "user-new", "users"}

// wp-*.php files of WordPress (and of old versions, still linked to).
var wpRootFiles = []string{"activate", "blog-header", "comments-post", "config", "config-sample", "cron", "links-opml", "load",
	"login", "mail", "settings", "signup", "trackback", "app", "atom", "commentsrss2", "feed", "pass", "rdf", "register",
	"rss", "rss2"}

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
	FileExemptIPs   = "exempt-ips.txt"
	// IPDB POST block and Tor rules: the addresses, and those never
	// blocked by them (allowed, temporarily allowed, CAPTCHA solved).
	FileIPDBIPs   = "ipdb-ips.txt"
	FileTorIPs    = "tor-exits.txt"
	FileRBLExempt = "rbl-exempt.txt"
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
	// Central sends suspicious visitors of the protected login URLs to the
	// portal's CAPTCHA page (captcha.xpguard.org) until they solve it (nil =
	// off; not used together with Gate, which already asks everyone).
	Central *Central
	// VerifiedBots are the search crawlers (User-Agent words, e.g.
	// "googlebot") whose official address lists are in trusted-ips.txt:
	// others claiming to be them are fake.
	VerifiedBots []string
	// Intel is the portal's fleet intelligence (learned web shell names,
	// virtual patches); nil = none.
	Intel *Intel
	// Dynamic: learned exclusions and cPanel's per-website switches.
	Dynamic Dynamic
}

// TorMode is the Tor rule rendered for a setting: "captcha" needs the
// portal's CAPTCHA page (suspects), otherwise POST requests are blocked.
func TorMode(action string, centralOn bool) string {
	switch action {
	case "post", "block":
		return action
	case "captcha":
		if centralOn {
			return "captcha"
		}
		return "post"
	}
	return "off"
}

// Central is the portal's CAPTCHA page for suspicious visitors: the
// addresses it applies to (suspects) and those that solved it (pass).
type Central struct {
	URL      string // e.g. https://captcha.xpguard.org/v
	ServerID string
	// All sends every visitor of the login pages, not only suspects (the
	// login-page CAPTCHA for everyone).
	All      bool
	Suspects []string
	Pass     []string
}

// Files the central CAPTCHA rule reads.
const (
	FileCaptchaSuspects = "captcha-suspects.txt"
	FileCaptchaPass     = "captcha-pass.txt"
)

// CentralFiles are the address lists of the central CAPTCHA rule.
func CentralFiles(c *Central) map[string]string {
	list := func(l []string) string {
		var ok []string
		for _, a := range l {
			if strings.TrimSpace(a) != "" {
				ok = append(ok, modsecAddr(a))
			}
		}
		if len(ok) == 0 {
			ok = []string{placeholderIP}
		}
		return strings.Join(ok, "\n") + "\n"
	}
	return map[string]string{FileCaptchaSuspects: list(c.Suspects), FileCaptchaPass: list(c.Pass)}
}

var reCentralURL = regexp.MustCompile(`^https://[a-z0-9.-]+(?::[0-9]+)?/[a-z0-9/_-]*$`)
var reServerID = regexp.MustCompile(`^[a-f0-9-]{8,64}$`)

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

// renderExempt turns the WAF off for the addresses that are never
// inspected: this server itself (its cron jobs and scripts calling its own
// websites), the account's other xPGuard servers, the portal and the
// firewall whitelist. Proxy networks (Cloudflare, a local reverse proxy)
// are never on the list, so visitors behind them stay checked.
func renderExempt(w func(string, ...any), d Dynamic) {
	if d.ExemptFile == "" {
		return
	}
	w(`SecRule REMOTE_ADDR "@ipMatchFromFile %s" "id:%d,phase:1,t:none,pass,nolog,ctl:ruleEngine=Off"`, d.ExemptFile, IDExempt)
}

// Render builds the rules file for the given settings.
func Render(c settings.WAF, o Options) string {
	if c.Level == "low" {
		// Low: no blocks by reputation alone.
		c.IPDBPost, c.TorAction = false, "off"
	}
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }
	w("# xPGuard WAF rules. Managed by the xPGuard agent: changes here are overwritten.")
	w("# Configure them in the xPGuard portal (Settings » WAF & Bruteforce).")
	w("")
	off := map[int]bool{}
	for _, id := range c.DisabledRules {
		off[id] = true
	}
	renderExempt(w, o.Dynamic)
	renderCPanelOff(w, o.Dynamic)
	renderExclusions(w, c, off, o.Dynamic)
	if len(c.WhitelistIPs) > 0 {
		ips := make([]string, len(c.WhitelistIPs))
		for i, a := range c.WhitelistIPs {
			ips[i] = modsecAddr(a)
		}
		// Whitelisted: no rule at all (the OWASP CRS included) checks them.
		w(`SecRule REMOTE_ADDR "@ipMatch %s" "id:%d,phase:1,pass,nolog,ctl:ruleEngine=Off"`, strings.Join(ips, ","), IDWhitelist)
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
		// They are never sent to a CAPTCHA either (a link-preview or search
		// bot cannot solve one, and the preview or the crawl breaks): the
		// login gate, the central CAPTCHA and soft blocking skip them. A
		// strong OWASP CRS signal still blocks them.
		w(`SecRule REMOTE_ADDR "@ipMatchFromFile %s/%s" "id:%d,phase:1,t:none,pass,nolog,ctl:ruleRemoveById=%d-%d,ctl:ruleRemoveById=%d,ctl:ruleRemoveById=%d,ctl:ruleRemoveById=%d,ctl:ruleRemoveById=%d,ctl:ruleRemoveById=%d-%d,ctl:ruleRemoveById=%d,ctl:ruleRemoveById=%d"`,
			o.Dir, FileTrustedIPs, IDTrusted, IDBadBots, IDFakeSearchBot, IDRootProbe+1000, IDEmptyUAWP, IDEmptyUAWP+1000, IDXMLRPCGet,
			IDGateNoCookie, IDCentralGate, IDSoftCaptcha, IDSoftDeny)
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
		rule(IDSensitive, `SecRule REQUEST_FILENAME "@rx /(?:\.env$|[a-z0-9_.-]+\.env$|env\.(?:txt|bak|old|orig|save)$|\.aws/|wp-config(?:-sample)?\.php$|[^/]+\.php[0-9]?\.suspected$|\.git/|\.svn/|\.hg/|\.htpasswd$|\.DS_Store$|\.env\.[a-z0-9_-]+$|[^/]+\.php[0-9]?(?:\.bak|\.old|\.orig|\.save|\.swp|\.txt|\.zip|~)$|debug\.log$|error_log$|[^/]+\.sql(?:\.gz|\.zip)?$)" "id:%d,phase:1,t:none,t:urlDecodeUni,t:lowercase,deny,status:403,log,msg:'xPGuard - Access to sensitive file blocked',tag:'xpguard/files'"`, IDSensitive)
	}
	if c.WordPress {
		rule(IDUploadsPHP, `SecRule REQUEST_FILENAME "@rx /wp-content/(?:uploads|blogs\.dir)/.*\.(?:php[0-9]?|phtml|phar|pht)$" "id:%d,phase:1,t:none,t:urlDecodeUni,t:lowercase,deny,status:403,log,msg:'xPGuard - PHP execution in uploads blocked',tag:'xpguard/wordpress'"`, IDUploadsPHP)
		rule(IDPHPInAssets, `SecRule REQUEST_FILENAME "@rx /(?:wp-content|wp-includes)/(?:[^?]*/)?(?:images?|img|fonts?|css|js)/[^/]*\.(?:php[0-9]?|phtml|phar|pht)$" "id:%d,phase:1,t:none,t:urlDecodeUni,t:lowercase,deny,status:403,log,msg:'xPGuard - PHP execution in an assets folder blocked',tag:'xpguard/wordpress',chain"`, IDPHPInAssets)
		if !off[IDPHPInAssets] {
			// WordPress core's own TinyMCE loader lives in wp-includes/js;
			// Autoptimize's old non-static mode serves .php files from its cache.
			w(`  SecRule REQUEST_FILENAME "!@rx (?:/wp-includes/js/tinymce/wp-tinymce\.php$|/cache/+autoptimize/)" "t:none,t:lowercase"`)
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
		// WordPress never runs the PHP files of wp-includes and of
		// wp-admin/includes, css, js and images directly (the hardening guide
		// denies them), except its TinyMCE loader and old multisite files.
		// Paths keep empty segments (//): not every engine normalises them.
		if !off[IDWPCoreDirect] {
			w(`SecRule REQUEST_FILENAME "@rx /wp-(?:includes|admin/(?:includes|css|js|images))/(?:[^/]*/)*[^/]+\.(?:php[0-9]?|phtml|phar|pht)$" "id:%d,phase:1,t:none,t:urlDecodeUni,t:lowercase,deny,status:403,log,msg:'xPGuard - Direct request to a WordPress core PHP file blocked',tag:'xpguard/wordpress',chain"`, IDWPCoreDirect)
			w(`  SecRule REQUEST_FILENAME "!@rx /wp-includes/+(?:js/+tinymce/+wp-tinymce|ms-files)\.php$" "t:none,t:urlDecodeUni,t:lowercase"`)
		}
		if !off[IDWPAdminFake] {
			w(`SecRule REQUEST_FILENAME "@rx /wp-admin/+(?:network|user)/+[^/]+\.(?:php[0-9]?|phtml|phar|pht)$" "id:%d,phase:1,t:none,t:urlDecodeUni,t:lowercase,deny,status:403,log,msg:'xPGuard - PHP file that is not part of WordPress in wp-admin blocked',tag:'xpguard/wordpress',chain"`, IDWPAdminFake)
			w(`  SecRule REQUEST_FILENAME "!@rx /wp-admin/+(?:network|user)/+(?:%s)\.php$" "t:none,t:urlDecodeUni,t:lowercase"`, strings.Join(quoteAll(wpAdminNetwork), "|"))
		}
		if !off[IDWPLookalike] {
			w(`SecRule REQUEST_FILENAME "@rx /wp-[^/]*\.php[0-9]?$" "id:%d,phase:1,t:none,t:urlDecodeUni,t:lowercase,deny,status:403,log,msg:'xPGuard - Fake WordPress core file blocked',tag:'xpguard/wordpress',chain"`, IDWPLookalike)
			w(`  SecRule REQUEST_FILENAME "!@rx /wp-(?:admin|includes|content)/" "t:none,t:urlDecodeUni,t:lowercase,chain"`)
			w(`  SecRule REQUEST_FILENAME "!@rx /wp-(?:%s)\.php$" "t:none,t:urlDecodeUni,t:lowercase"`, strings.Join(quoteAll(wpRootFiles), "|"))
		}
		rule(IDWPUploadsList, `SecRule REQUEST_FILENAME "@rx /wp-content/+uploads/+(?:\d{4}/+(?:\d{2}/+)?)?$" "id:%d,phase:1,t:none,t:urlDecodeUni,t:lowercase,deny,status:403,log,msg:'xPGuard - Uploads folder listing blocked',tag:'xpguard/wordpress'"`, IDWPUploadsList)
		if !off[IDWPCachePHP] {
			// Autoptimize's old non-static mode serves .php files from its cache.
			w(`SecRule REQUEST_FILENAME "@rx /wp-content/+cache/.*\.(?:php[0-9]?|phtml|phar|pht)$" "id:%d,phase:1,t:none,t:urlDecodeUni,t:lowercase,deny,status:403,log,msg:'xPGuard - PHP execution in the cache folder blocked',tag:'xpguard/wordpress',chain"`, IDWPCachePHP)
			w(`  SecRule REQUEST_FILENAME "!@rx /cache/+autoptimize/" "t:none,t:urlDecodeUni,t:lowercase"`)
		}
	}
	if c.Generic {
		// Any website: static folders hold no PHP; repeated folders
		// (/images/images/cache.php) and hidden folders are backdoor hunts.
		if !off[IDStaticPHP] {
			w(`SecRule REQUEST_FILENAME "@rx /(?:images?|img|fonts?|css)/+[^/]*\.(?:php[0-9]?|phtml|phar|pht)$" "id:%d,phase:1,t:none,t:urlDecodeUni,t:lowercase,deny,status:403,log,msg:'xPGuard - PHP execution in a static folder blocked',tag:'xpguard/generic',chain"`, IDStaticPHP)
			// Also the colour stylesheets of ViserLab scripts (HYIPLAB, PTC…).
			w(`  SecRule REQUEST_FILENAME "!@rx (?:/cache/+autoptimize/|/assets/+templates/+[^/]+/+css/+color\.php$)" "t:none,t:urlDecodeUni,t:lowercase"`)
		}
		rule(IDRepeatDirPHP, `SecRule REQUEST_FILENAME "@rx /([^/]+)/+\1/(?:[^/]*/)*[^/]*\.(?:php[0-9]?|phtml|phar|pht)$" "id:%d,phase:1,t:none,t:urlDecodeUni,t:lowercase,deny,status:403,log,msg:'xPGuard - PHP request through repeated folders blocked',tag:'xpguard/generic'"`, IDRepeatDirPHP)
		if !off[IDHiddenDirPHP] {
			w(`SecRule REQUEST_FILENAME "@rx /\.[^/]+/(?:[^/]*/)*[^/]*\.(?:php[0-9]?|phtml|phar|pht)$" "id:%d,phase:1,t:none,t:urlDecodeUni,t:lowercase,deny,status:403,log,msg:'xPGuard - PHP execution in a hidden folder blocked',tag:'xpguard/generic',chain"`, IDHiddenDirPHP)
			w(`  SecRule REQUEST_FILENAME "!@contains /.well-known/" "t:none,t:urlDecodeUni,t:lowercase"`)
		}
		// REQUEST_URI is not decoded: %252e%252e is ".." encoded twice.
		rule(IDDoubleEncode, `SecRule REQUEST_URI "@rx %%25(?:25)*2e%%25(?:25)*2e" "id:%d,phase:1,t:none,t:lowercase,deny,status:403,log,msg:'xPGuard - Double-encoded path traversal blocked',tag:'xpguard/generic'"`, IDDoubleEncode)
	}
	if c.VirtualPatches {
		if !off[IDVPGravitySMTP] {
			w(`SecRule REQUEST_URI "@rx (?:/wp-json/+gravitysmtp/|[?&]rest_route=/?gravitysmtp/)" "id:%d,phase:1,t:none,t:urlDecodeUni,t:lowercase,deny,status:403,log,msg:'xPGuard - Virtual patch: Gravity SMTP REST API without login',tag:'xpguard/vpatch',chain"`, IDVPGravitySMTP)
			w(`  SecRule &REQUEST_COOKIES_NAMES:/^wordpress_logged_in_/ "@eq 0" "t:none"`)
		}
		rule(IDVPFileManager, `SecRule REQUEST_FILENAME "@rx /wp-content/+plugins/+wp-file-manager/+lib/+php/+connector\.minimal\.php$" "id:%d,phase:1,t:none,t:urlDecodeUni,t:lowercase,deny,status:403,log,msg:'xPGuard - Virtual patch: WP File Manager connector (CVE-2020-25213)',tag:'xpguard/vpatch'"`, IDVPFileManager)
		if !off[IDVPRevSlider] {
			w(`SecRule ARGS:action "@streq revslider_show_image" "id:%d,phase:2,t:none,t:lowercase,deny,status:403,log,msg:'xPGuard - Virtual patch: Slider Revolution file download',tag:'xpguard/vpatch',chain"`, IDVPRevSlider)
			w(`  SecRule ARGS:img "@contains .." "t:none,t:urlDecodeUni"`)
		}
		if !off[IDVPDuplicator] {
			w(`SecRule ARGS:action "@streq duplicator_download" "id:%d,phase:2,t:none,t:lowercase,deny,status:403,log,msg:'xPGuard - Virtual patch: Duplicator file download (CVE-2020-11738)',tag:'xpguard/vpatch',chain"`, IDVPDuplicator)
			w(`  SecRule ARGS:file "@contains .." "t:none,t:urlDecodeUni"`)
		}
		if o.Intel != nil {
			for _, p := range o.Intel.Patches {
				if !off[p.ID] && p.Valid() == nil {
					renderPatch(w, p)
				}
			}
		}
		rule(IDVPLiteSpeed, `SecRule REQUEST_FILENAME "@rx /wp-content/+litespeed/+debug/" "id:%d,phase:1,t:none,t:urlDecodeUni,t:lowercase,deny,status:403,log,msg:'xPGuard - Virtual patch: LiteSpeed Cache debug log (CVE-2024-44000)',tag:'xpguard/vpatch'"`, IDVPLiteSpeed)
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
	if ct := o.Central; ct != nil && o.Gate == nil && len(c.LoginURLs) > 0 && reCentralURL.MatchString(ct.URL) && reServerID.MatchString(ct.ServerID) {
		var urls []string
		for _, u := range c.LoginURLs {
			urls = append(urls, regexp.QuoteMeta(strings.ToLower(u)))
		}
		// A suspicious address (IPDB, recent bans, repeated WAF blocks) that
		// has not solved the CAPTCHA yet is sent to the portal's page with
		// this server, its address, the site and the page it asked for (the
		// page last: it may hold "&"). Logged, not counted as an attack.
		w(`SecRule REQUEST_FILENAME "@rx (?:%s)$" "id:%d,phase:1,t:none,t:urlDecodeUni,t:lowercase,redirect:%s?s=%s&ip=%%{REMOTE_ADDR}&h=%%{REQUEST_HEADERS.Host}&u=%%{REQUEST_URI},log,msg:'xPGuard - suspicious visitor sent to the CAPTCHA',tag:'xpguard/captcha',chain"`,
			strings.Join(urls, "|"), IDCentralGate, ct.URL, ct.ServerID)
		if !ct.All {
			w(`  SecRule REMOTE_ADDR "@ipMatchFromFile %s/%s" "t:none,chain"`, o.Dir, FileCaptchaSuspects)
		}
		w(`  SecRule REMOTE_ADDR "!@ipMatchFromFile %s/%s" "t:none"`, o.Dir, FileCaptchaPass)
	}
	if c.Webshell {
		rule(IDWebshell, `SecRule REQUEST_FILENAME "@rx /(?:%s)[0-9]?$" "id:%d,phase:1,t:none,t:urlDecodeUni,t:lowercase,deny,status:403,log,msg:'xPGuard - Web shell request blocked',tag:'xpguard/webshell'"`, strings.Join(quoteAll(WebshellNames), "|"), IDWebshell)
		rule(IDWebshellDir, `SecRule REQUEST_FILENAME "@rx /(?:alfa_data|alfacgiapi|wso_data)/" "id:%d,phase:1,t:none,t:urlDecodeUni,t:lowercase,deny,status:403,log,msg:'xPGuard - Web shell folder request blocked',tag:'xpguard/webshell'"`, IDWebshellDir)
		// Paths only exploit scanners request: PHPUnit's eval-stdin.php
		// (CVE-2017-9841), Laravel Ignition (CVE-2021-3129), leaked credentials.
		if in := o.Intel; in != nil && len(in.Names) > 0 && !off[IDFleetNames] {
			rule(IDFleetNames, `SecRule REQUEST_FILENAME "@rx /(?:%s)$" "id:%d,phase:1,t:none,t:urlDecodeUni,t:lowercase,deny,status:403,log,msg:'xPGuard - Web shell name learned by the fleet blocked',tag:'xpguard/webshell'"`, strings.Join(quoteAll(in.Names), "|"), IDFleetNames)
		}
		rule(IDMalwareExt, `SecRule REQUEST_FILENAME "@rx /wp-content/+(?:%s)(?:/|$)" "id:%d,phase:1,t:none,t:urlDecodeUni,t:lowercase,deny,status:403,log,msg:'xPGuard - Malware plugin or theme folder blocked',tag:'xpguard/webshell'"`, strings.Join(quoteAll(MalwareExtDirs), "|"), IDMalwareExt)
		rule(IDExploitProbe, `SecRule REQUEST_FILENAME "@rx /(?:vendor/phpunit/phpunit/src/util/php/eval-stdin\.php|_ignition/execute-solution|\.aws/credentials|\.vscode/sftp\.json|sftp-config\.json|\.git-credentials)$" "id:%d,phase:1,t:none,t:urlDecodeUni,t:lowercase,deny,status:403,log,msg:'xPGuard - Exploit probe blocked',tag:'xpguard/webshell'"`, IDExploitProbe)
	}
	bot := func(on bool, file string, id int, what string) {
		if on && !off[id] {
			w(`SecRule REQUEST_HEADERS:User-Agent "@pmFromFile %s/%s" "id:%d,phase:1,t:none,deny,status:403,log,msg:'xPGuard - %s blocked',tag:'xpguard/bot'"`, o.Dir, file, id, what)
		}
	}
	bot(c.BadBots, FileBadBots, IDBadBots, "Bad bot")
	if c.BadBots {
		// PHP probes on the top folder with neither a User-Agent nor a
		// Referer: tools hunting for planted backdoors (/w.php, /alfa.php).
		probe := func(id int, ua string) {
			w(`SecRule REQUEST_FILENAME "@rx ^/+[^/]+\.(?:php[0-9]?|phtml|phar)$" "id:%d,phase:1,t:none,t:urlDecodeUni,t:lowercase,deny,status:403,log,msg:'xPGuard - PHP probe without User-Agent and Referer blocked',tag:'xpguard/bot',chain"`, id)
			w(`  SecRule REQUEST_FILENAME "!@rx ^/+(?:index|wp-cron|xmlrpc)\.php$" "t:none,t:urlDecodeUni,t:lowercase,chain"`)
			w(`  SecRule &REQUEST_HEADERS:Referer "@eq 0" "t:none,chain"`)
			w(`  %s`, ua)
		}
		if !off[IDRootProbe] {
			probe(IDRootProbe, `SecRule &REQUEST_HEADERS:User-Agent "@eq 0" "t:none"`)
			probe(IDRootProbe+1000, `SecRule REQUEST_HEADERS:User-Agent "@rx ^\s*$" "t:none"`)
		}
		if !off[IDBareMozilla] {
			// Not for logged-in users and API clients (some site tools send it).
			w(`SecRule REQUEST_HEADERS:User-Agent "@rx ^\s*mozilla/5\.0\s*$" "id:%d,phase:1,t:none,t:lowercase,deny,status:403,log,msg:'xPGuard - Fake browser User-Agent blocked',tag:'xpguard/bot',chain"`, IDBareMozilla)
			w(`  SecRule &REQUEST_HEADERS:Authorization "@eq 0" "t:none,chain"`)
			w(`  SecRule &REQUEST_COOKIES_NAMES:/^wordpress_logged_in_/ "@eq 0" "t:none"`)
		}
	}
	bot(c.SEOBots, FileSEOBots, IDSEOBots, "SEO crawler")
	bot(c.AIBots, FileAIBots, IDAIBots, "AI crawler")
	bot(c.BotBlocker && len(c.BotList) > 0, FileCustomBots, IDCustomBots, "Bad bot")
	if len(o.VerifiedBots) > 0 && o.Trusted && c.BotBlocker && !off[IDFakeSearchBot] {
		// Only direct visitors: behind a CDN or proxy the address is the
		// proxy's, so a real crawler could look fake.
		w(`SecRule REQUEST_HEADERS:User-Agent "@rx \b(?:%s)\b" "id:%d,phase:1,t:none,t:lowercase,deny,status:403,log,msg:'xPGuard - Fake search engine crawler blocked',tag:'xpguard/bot',chain"`, strings.Join(quoteAll(o.VerifiedBots), "|"), IDFakeSearchBot)
		w(`  SecRule REMOTE_ADDR "!@ipMatchFromFile %s/%s" "t:none,chain"`, o.Dir, FileTrustedIPs)
		w(`  SecRule &REQUEST_HEADERS:X-Forwarded-For "@eq 0" "t:none,chain"`)
		w(`  SecRule &REQUEST_HEADERS:CF-Connecting-IP "@eq 0" "t:none"`)
	}
	// rblRule blocks addresses on a list, directly and behind a proxy (real
	// address from the forwarded-for headers; id+1000), except exempt
	// addresses. viaCF also blocks visitors Cloudflare marks with that
	// country code (id+2000; T1 is Tor).
	rblRule := func(id int, post bool, list, msg string, viaCF string) {
		head := func(id int, what, first string) {
			if post {
				w(`SecRule REQUEST_METHOD "@streq POST" "id:%d,phase:1,t:none,deny,status:403,log,msg:'xPGuard - %s%s',tag:'xpguard/rbl',chain"`, id, msg, what)
				w(`  SecRule REMOTE_ADDR "@ipMatchFromFile %s/%s" "t:none,chain"`, o.Dir, first)
			} else {
				w(`SecRule REMOTE_ADDR "@ipMatchFromFile %s/%s" "id:%d,phase:1,t:none,deny,status:403,log,msg:'xPGuard - %s%s',tag:'xpguard/rbl',chain"`, o.Dir, first, id, msg, what)
			}
		}
		head(id, "", list)
		w(`  SecRule REMOTE_ADDR "!@ipMatchFromFile %s/%s" "t:none"`, o.Dir, FileRBLExempt)
		head(id+1000, " (behind a proxy)", FileProxyRanges)
		w(`  SecRule REQUEST_HEADERS:CF-Connecting-IP|REQUEST_HEADERS:X-Forwarded-For|REQUEST_HEADERS:X-Real-IP "@rx ^\s*([0-9A-Fa-f:.]{3,45})" "capture,chain"`)
		w(`    SecRule TX:1 "@ipMatchFromFile %s/%s" "t:none,chain"`, o.Dir, list)
		w(`    SecRule TX:1 "!@ipMatchFromFile %s/%s" "t:none"`, o.Dir, FileRBLExempt)
		if viaCF != "" {
			head(id+2000, " (Cloudflare)", FileProxyRanges)
			w(`  SecRule REQUEST_HEADERS:CF-IPCountry "@streq %s" "t:none"`, viaCF)
		}
	}
	if c.IPDBPost && !off[IDIPDBPost] {
		rblRule(IDIPDBPost, true, FileIPDBIPs, "POST from an IPDB-listed address blocked", "")
	}
	switch TorMode(c.TorAction, o.Central != nil && o.Gate == nil) {
	case "post":
		if !off[IDTorPost] {
			rblRule(IDTorPost, true, FileTorIPs, "POST from a Tor exit node blocked", "T1")
		}
	case "block":
		if !off[IDTorBlock] {
			rblRule(IDTorBlock, false, FileTorIPs, "Tor exit node blocked", "T1")
		}
	}
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
func RenderLoginWatch(c settings.WAF, replacedBy string, dyn Dynamic) string {
	var b strings.Builder
	b.WriteString("# xPGuard's own blocking rules are off on this server: " + replacedBy + "'s rules are used instead.\n")
	b.WriteString("# Kept: the portal's whitelists and switched-off rules (applied to " + replacedBy + "'s rules),\n")
	b.WriteString("# and failed-login detection (pass, log only) for the brute-force bans.\n\n")
	off := map[int]bool{}
	for _, id := range c.DisabledRules {
		off[id] = true
	}
	lw := func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }
	renderExempt(lw, dyn)
	renderCPanelOff(lw, dyn)
	renderExclusions(lw, c, off, dyn)
	// Whitelisted addresses and domains skip the vendor's rules too.
	if len(c.WhitelistIPs) > 0 {
		ips := make([]string, len(c.WhitelistIPs))
		for i, a := range c.WhitelistIPs {
			ips[i] = modsecAddr(a)
		}
		fmt.Fprintf(&b, "SecRule REMOTE_ADDR \"@ipMatch %s\" \"id:%d,phase:1,pass,nolog,ctl:ruleEngine=Off\"\n", strings.Join(ips, ","), IDWhitelist)
	}
	if len(c.WhitelistDomains) > 0 {
		var alt []string
		for _, d := range c.WhitelistDomains {
			alt = append(alt, strings.ReplaceAll(regexp.QuoteMeta(d), `\*`, `[^.]+`))
		}
		fmt.Fprintf(&b, "SecRule SERVER_NAME \"@rx ^(?:%s)$\" \"id:%d,phase:1,t:none,t:lowercase,pass,nolog,ctl:ruleEngine=Off\"\n", strings.Join(alt, "|"), IDWhiteDomains)
	}
	// Rules switched off in the portal (a vendor rule causing false positives).
	if ids := append([]int(nil), c.DisabledRules...); len(ids) > 0 {
		sort.Ints(ids)
		var ctl []string
		for _, id := range ids {
			ctl = append(ctl, fmt.Sprintf("ctl:ruleRemoveById=%d", id))
		}
		fmt.Fprintf(&b, "SecAction \"id:%d,phase:1,pass,nolog,%s\"\n", IDDisable, strings.Join(ctl, ","))
	}
	b.WriteString("\n")
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

// AddrFile writes addresses the way @ipMatchFromFile reads them: valid,
// unique, sorted, never empty.
func AddrFile(list []string) string {
	var ok []string
	seen := map[string]bool{}
	for _, a := range list {
		if a = modsecAddr(strings.TrimSpace(a)); validAddr(a) && !seen[a] {
			seen[a] = true
			ok = append(ok, a)
		}
	}
	if len(ok) == 0 {
		ok = []string{placeholderIP}
	}
	sort.Strings(ok)
	return strings.Join(ok, "\n") + "\n"
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

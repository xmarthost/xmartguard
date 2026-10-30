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
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/xmarthost/xmartguard/agent/internal/settings"
)

// Rule id ranges by category.
const (
	IDWhitelist    = 7700001
	IDWhiteDomains = 7700002
	IDDisable      = 7700003
	IDTrusted      = 7700004
	// IDTrustedCF marks trusted services behind Cloudflare (CF-Connecting-IP).
	IDTrustedCF = 7700056
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
	// IDWPPackagePHP: a PHP file sent to WordPress's plugin, theme or media
	// uploader, which only take zips and media. CRS 933110 scores it only
	// 5 (threshold 10): a malicious plugin upload with a stolen admin
	// session passed on business200 (2026-10-20).
	IDWPPackagePHP = 7700315
	// 7700314 (XML-RPC "fake Jetpack") is retired: the Jetpack mobile app
	// sends that name from its users' own connections.
	IDStaticPHP    = 7700321
	IDRepeatDirPHP = 7700322
	IDHiddenDirPHP = 7700323
	IDDoubleEncode = 7700324
	// IDNoUAPost: POSTs to a PHP file with no User-Agent, Referer or cookie
	// (web shell and exploit tools). Not shared with the IPDB: a
	// server-to-server call may look the same.
	IDNoUAPost = 7700330
	// Comment spam on WordPress (wp-comments-post.php, also WooCommerce
	// reviews). Real visitors' browsers always send Origin (or at least a
	// Referer) when they post the comment form, type plain text into a
	// plain textarea and rarely paste many links. IDCommentScript: posted
	// without Origin and Referer (a script, not a browser).
	// IDCommentLinks: a link written as HTML (<a href=…>) while the
	// website field is filled too (an SEO backlink), or BBCode [url=…]
	// that WordPress never shows (+1000). IDCommentManyLinks: 4 or more
	// links in one comment.
	IDCommentScript    = 7700331
	IDCommentLinks     = 7700332
	IDCommentManyLinks = 7700333
	IDLoginWP          = 7700401
	IDLoginXMLRPC      = 7700402
	IDLoginJoomla      = 7700403
	IDLoginOpenCart    = 7700404
	IDLoginCustom      = 7700405
	IDBadBots          = 7700501
	IDSEOBots          = 7700502
	IDAIBots           = 7700503
	IDCustomBots       = 7700504
	IDRootProbe        = 7700505
	IDBareMozilla      = 7700506
	IDFakeSearchBot    = 7700507
	// IDCrawlerCart: crawlers adding to cart or wishlist (every such URL
	// writes a session and runs the shop uncached).
	IDCrawlerCart = 7700508
	// IDCrawlerFacets: crawlers other than the search engines walking a
	// shop's filter, sort and page-size combinations (millions of uncached
	// pages: SEO backlink crawlers overloaded a server this way).
	IDCrawlerFacets = 7700509
	// IDShopScrape: clients without cookies (no visitor has none) walking
	// shop filter combinations: three or more values of a filter, or three
	// filters at once. Scrapers send a browser User-Agent from residential
	// proxies and AI crawlers from their own networks, and every such URL
	// runs the shop's heaviest query uncached.
	IDShopScrape = 7700510
	// IDCartSpam: cart links no visitor clicks (remove_item together with
	// add-to-cart) and cart changes without a session cookie.
	IDCartSpam     = 7700511
	IDWebshell     = 7700601
	IDWebshellDir  = 7700602
	IDExploitProbe = 7700603
	IDMalwareExt   = 7700604
	// IDCookieShell: a cookie whose value is a base64 PHP command (shells
	// that read their commands from cookies get past parameter rules).
	IDCookieShell = 7700606
	// IDStaticPost: a POST to an image, icon or stylesheet address
	// (polyglot shells run when a handler maps those extensions to PHP).
	IDStaticPost   = 7700607
	IDProxyBlocked = 7700701
	// IPDB and Tor: id+1000 checks the real address behind Cloudflare or a
	// local proxy, id+2000 Cloudflare's Tor marker.
	IDIPDBPost = 7700711
	IDTorPost  = 7700712
	IDTorBlock = 7700713
	// IDIPDBPostAPI: API calls (an Authorization, API key or signature
	// header) skip the IPDB POST rule: integrations call from data-center
	// addresses that share IPDB-listed networks.
	IDIPDBPostAPI = 7700714
	// Virtual patches: known plugin vulnerabilities blocked at the WAF.
	IDVPGravitySMTP = 7701001
	IDVPFileManager = 7701002
	IDVPRevSlider   = 7701003
	IDVPDuplicator  = 7701004
	IDVPLiteSpeed   = 7701005
	// IDVPPHPFormName: PHP2Shell (CVE-2026-109618): a form field name of
	// megabytes exhausts PHP's memory while it parses the request, before
	// any script runs.
	IDVPPHPFormName = 7701006
	IDGateNoCookie  = 7700902
	IDGateBadCookie = 7700903
	IDCentralGate   = 7700904
	// IDCentralNoBrowser: a suspicious address that is not a browser opening
	// a page (xmlrpc.php posts, scripts) gets a 403, not the CAPTCHA page.
	IDCentralNoBrowser = 7700906
	// On the website's own address (Central.Site) the pass is a cookie:
	// IDCentralGate and IDCentralNoBrowser then test a missing cookie,
	// these two a wrong or expired one.
	IDCentralGateBadCookie      = 7700907
	IDCentralNoBrowserBadCookie = 7700908
	// IDCentralPassUsed+N logs a suspect sending pass-cookie value N (slot N
	// of Central.Slots), so the agent sees a value used by an address it was
	// not given to. Up to 10 slots.
	IDCentralPassUsed = 7700910
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
	{IDWCStoreExcl, "exclusions", "WooCommerce cart and checkout (Store API and ?wc-ajax=): PHP-injection rules skip it (addresses and order notes are stored, never run)", "allow"},
	{IDHostingBase, "exclusions", "Hosting defaults: comments and reviews in Urdu, Arabic or with emoji (941310), crawlers' Accept charset (920600) and JSON sent by shop, tracking and consent plugins (942550) are not attacks", "allow"},
	{IDCPanelPaths, "exclusions", "cPanel pages reached by the server address (mail autodiscover/autoconfig, suspended page, AutoSSL): numeric Host allowed", "allow"},
	{IDCPanelServices, "exclusions", "cPanel service subdomains (cpanel., webmail., whm., webdisk., cpcalendars., cpcontacts.): not inspected, cPanel checks their logins", "allow"},
	{IDCPanelMailCfg, "exclusions", "Mail client setup requests answered by cPanel (cgi-sys/autodiscover.cgi, autoconfig.cgi)", "allow"},
	{IDDeviceIclock, "exclusions", "Attendance and access-control devices posting to /iclock/ (ZKTeco push protocol)", "allow"},
	{IDStaticCookies, "exclusions", "Images, styles and scripts: the cookies sent with them are not checked for injections", "allow"},
	{IDWPCommentText, "exclusions", "WordPress comments and WooCommerce reviews: the text, name and website are not checked for SQL injection (WordPress stores them safely; XSS is still checked)", "allow"},
	{IDPasswordArgs, "exclusions", "Password fields of login and sign-up forms are not checked for PHP injection (passwords are hashed, never run; SQL and XSS rules still check them)", "allow"},
	{IDWPCustomizer, "exclusions", "WordPress customizer preview of a logged-in user (unsaved CSS and HTML widgets): injection rules skip it", "allow"},
	{IDThemeColorCSS, "exclusions", "Theme colour stylesheets built by PHP (css/color.php?primary_color=F7931A) are allowed in css folders", "allow"},
	{IDSiteBeacons, "exclusions", "Meta Conversions API bridge (?ob=open-bridge/events) and Optimization Detective page measurements", "allow"},
	{IDWHMCSAdmin, "exclusions", "WHMCS admin area (any admin folder name): saves from the same site with the WHMCS session skip injection rules", "allow"},
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
	{IDWPPackagePHP, "wordpress", "Block PHP files sent to the WordPress plugin, theme and media uploaders (they only take zip files and media)", "block"},
	{IDLoginWP, "bruteforce", "Count failed WordPress logins", "count"},
	{IDLoginXMLRPC, "bruteforce", "Count WordPress XML-RPC login calls", "count"},
	{IDLoginJoomla, "bruteforce", "Count Joomla administrator logins", "count"},
	{IDLoginOpenCart, "bruteforce", "Count OpenCart administrator logins", "count"},
	{IDLoginCustom, "bruteforce", "Count logins on the other protected login URLs", "count"},
	{IDWebshell, "webshell", "Block requests to well-known web shell files", "block"},
	{IDWebshellDir, "webshell", "Block requests into web shell working folders", "block"},
	{IDStaticPost, "webshell", "Block POST requests to image, icon and stylesheet addresses (polyglot web shells)", "block"},
	{IDCookieShell, "webshell", "Block cookies carrying a base64-encoded PHP command (web shells that read their commands from cookies)", "block"},
	{IDExploitProbe, "webshell", "Block probes for well-known exploits (PHPUnit eval-stdin RCE, Laravel Ignition RCE, leaked cloud credentials)", "block"},
	{IDFleetNames, "webshell", "Block web shell file names the scanners of your servers found (learned by the portal)", "block"},
	{IDMalwareExt, "webshell", "Block requests into plugin and theme folders that only malware creates (fake plugins, seotheme)", "block"},
	{IDStaticPHP, "generic", "Block running PHP files inside images, img, fonts and css folders of any website", "block"},
	{IDRepeatDirPHP, "generic", "Block PHP requests through repeated folders (/images/images/cache.php), a backdoor search pattern", "block"},
	{IDHiddenDirPHP, "generic", "Block running PHP files inside hidden folders (/.tmb/, /.trash/), except .well-known", "block"},
	{IDCommentScript, "wordpress", "Block comments and reviews posted by scripts: no Origin and no Referer header (every browser sends one when the comment form is posted)", "block"},
	{IDCommentLinks, "wordpress", "Block SEO spam comments: a link written as HTML (<a href=…>) together with a filled website field, or forum BBCode [url=…] that WordPress never shows", "block"},
	{IDCommentManyLinks, "wordpress", "Block comments and reviews with 4 or more links", "block"},
	{IDNoUAPost, "bad_bots", "Block POSTs to PHP files with no User-Agent, Referer or cookie (web shell tools), except API, webhook and payment callback paths and trusted services", "block"},
	{IDDoubleEncode, "generic", "Block double-encoded path traversal (%252e%252e) in the address", "block"},
	{IDBadBots, "bad_bots", "Block vulnerability scanners and abusive tools", "block"},
	{IDCrawlerCart, "bad_bots", "Block crawlers following add-to-cart and wishlist links (each one writes a session and runs the shop uncached)", "block"},
	{IDShopScrape, "bad_bots", "Block clients without cookies walking shop filter combinations (3+ values or 3+ filters) unless the browser says the click came from the same site: scrapers and botnets with a browser User-Agent, AI crawlers", "block"},
	{IDCartSpam, "bad_bots", "Block cart spam: remove_item with add-to-cart in one link, and removing cart items without a session cookie", "block"},
	{IDCrawlerFacets, "bad_bots", "Block crawlers other than search engines on shop filter, sort and page-size URLs (endless uncached combinations)", "block"},
	{IDRootProbe, "bad_bots", "Block PHP probes on a website's top folder that send neither a User-Agent nor a Referer", "block"},
	{IDBareMozilla, "bad_bots", "Block the fake User-Agent \"Mozilla/5.0\" with nothing after it (scripts pretending to be a browser)", "block"},
	{IDFakeSearchBot, "bot_blocker", "Block fake Googlebot and Bingbot: the User-Agent says so but the address is not on Google's or Microsoft's published list", "block"},
	{IDSEOBots, "seo_bots", "Block aggressive SEO crawlers", "block"},
	{IDAIBots, "ai_bots", "Block fake AI crawlers (GPTBot, ClaudeBot, PerplexityBot… from outside their official networks; the real ones are allowed)", "block"},
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
	{IDVPPHPFormName, "virtual_patches", "PHP2Shell: block form posts with a field name longer than 16 KB (CVE-2026-109618, PHP remote code execution while PHP reads the form; update PHP too)", "block"},
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

// LoginPages drops the WordPress admin folder from the protected login
// URLs: no login happens there (wp-login.php has its own rule), and every
// POST of a logged-in admin's screens (admin-ajax.php: heartbeat, autosave,
// carts, forms) answers 200 like a failed login form. Listed as a protected
// URL (business200) it counted those as failed logins: website owners on
// iCloud Private Relay were banned after 10 of them and then could not
// pass the CAPTCHA ("attacked after solving"), and the site's login attack
// mode was set off by its own admin.
func LoginPages(urls []string) []string {
	var out []string
	for _, u := range urls {
		l := strings.TrimSuffix(strings.ToLower(u), "/")
		if l == "/wp-admin" || strings.HasPrefix(l, "/wp-admin/") {
			continue
		}
		out = append(out, u)
	}
	return out
}

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
	// Cloudflare's networks and the local reverse proxies apart: behind
	// Cloudflare only CF-Connecting-IP names the visitor (Cloudflare sets
	// it; X-Real-IP and X-Forwarded-For pass through from the client).
	FileCFRanges    = "cloudflare-ranges.txt"
	FileLocalProxys = "local-proxies.txt"
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

// cloudflareRanges are ProxyRanges without the local proxies.
func cloudflareRanges() []string {
	var out []string
	for _, r := range ProxyRanges {
		if r != "127.0.0.1" && r != "::1" {
			out = append(out, r)
		}
	}
	return out
}

// proxyRead is one way to learn the visitor behind a proxy: the proxies'
// address file, the header they set, and the rule id.
type proxyRead struct {
	id            int
	file, headers string
}

// viaProxies are the two proxy kinds: Cloudflare (CF-Connecting-IP only)
// under id, local reverse proxies (nginx, Varnish, often behind Cloudflare
// themselves: the header they or Cloudflare set) under id+5000.
func viaProxies(id int) []proxyRead {
	return []proxyRead{
		{id, FileCFRanges, "REQUEST_HEADERS:CF-Connecting-IP"},
		{id + 5000, FileLocalProxys, "REQUEST_HEADERS:CF-Connecting-IP|REQUEST_HEADERS:X-Forwarded-For|REQUEST_HEADERS:X-Real-IP"},
	}
}

// The IPDB list holds a quarter of a million networks, and every rule
// that reads a list file keeps its own copy in every web server process:
// about 35 MB each (measured on Apache with ModSecurity 2). The IPDB POST
// block, the CAPTCHA suspects and soft blocking read it up to 18 times
// (LiteSpeed used 235 MB a process on cloud2). It is now read once per
// address source, and those rules test the result.
const (
	// IDMarkIPDB marks the visitor's own address; viaProxies(IDMarkIPDB+1)
	// the address behind Cloudflare (7700061) and a local proxy (7705061).
	IDMarkIPDB = 7700060
	// IDMarkSuspect and IDMarkSuspect+1 mark the CAPTCHA suspects.
	IDMarkSuspect = 7700062
	// IDSoftStrictIPDB.. +2: soft blocking's bad reputation from the marks.
	IDSoftStrictIPDB = 7700064
	// IDMarkSiteAttack marks every visitor of the login page of a website
	// under a password-guessing attack from many addresses (Central.Sites):
	// each one must solve the CAPTCHA, whatever its address.
	IDMarkSiteAttack = 7700067
	// IDHostPage: the CAPTCHA page on this server's hostname (hostname
	// mode) is not inspected (a static page; its link holds the page the
	// visitor wanted, which may look like an attack).
	IDHostPage = 7700068
	// IDMarkHosting marks visitors of the login pages from hosting, cloud
	// and VPS networks (Central.Hosting): stolen passwords are used from
	// rented servers.
	IDMarkHosting = 7700069
)

// ipdbMarkVars are the variables of renderIPDBMarks: the visitor's own
// address, then the address behind each proxy kind (viaProxies order).
var ipdbMarkVars = []string{"xg_ipdb", "xg_ipdb_cf", "xg_ipdb_lp"}

// renderIPDBMarks looks the IPDB list up once for each address source.
func renderIPDBMarks(w func(string, ...any), dir string) {
	w(`SecRule REMOTE_ADDR "@ipMatchFromFile %s/%s" "id:%d,phase:1,t:none,pass,nolog,setvar:tx.%s=1"`, dir, FileIPDBIPs, IDMarkIPDB, ipdbMarkVars[0])
	for i, v := range viaProxies(IDMarkIPDB + 1) {
		w(`SecRule REMOTE_ADDR "@ipMatchFromFile %s/%s" "id:%d,phase:1,t:none,pass,nolog,chain"`, dir, v.file, v.id)
		w(`  SecRule %s "@rx ^\s*([0-9A-Fa-f:.]{3,45})" "capture,chain"`, v.headers)
		w(`    SecRule TX:1 "@ipMatchFromFile %s/%s" "t:none,setvar:tx.%s=1"`, dir, FileIPDBIPs, ipdbMarkVars[i+1])
	}
}

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
	// IPDBMarks: the IPDB list is looked up once per address source and
	// the IPDB POST, CAPTCHA suspect and soft blocking rules read the
	// result (see renderIPDBMarks).
	IPDBMarks bool
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
	// Site shows the check on the website's own address: suspects go to
	// this server's CAPTCHA port (HTTPSPort) and pass with a cookie that
	// holds one of the values of Slots (no web server reload for a pass).
	// Each slot lists its values (today's, yesterday's).
	Site      bool
	Slots     [][]string
	HTTPSPort int
	// Sites are websites under a password-guessing attack spread over many
	// addresses (one per few attempts, as botnets and VPNs rotate): every
	// visitor of their WordPress or protected login page gets the CAPTCHA,
	// not only suspects. Lowercase, without "www." and port.
	Sites []string
	// SiteLoginURLs are the login pages gated on those websites (not
	// xmlrpc.php or admin panels: apps and logged-in admins use them).
	SiteLoginURLs []string
	// HostPage is the check's page on this server's hostname
	// (https://<hostname>/xpguard-check/, hostname mode): suspects are sent
	// there instead of URL, and pass through the pass list.
	HostPage string
	// Hosting: visitors of SiteLoginURLs from hosting, cloud and VPS
	// networks (HostingNets, hostnets) are suspects, except HostingExempt
	// (the server's allowed addresses, the fleet) and trusted services.
	Hosting       bool
	HostingNets   []string
	HostingExempt []string
}

// reHostPage is a hostname page address the rules may hold.
var reHostPage = regexp.MustCompile(`^https://[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+/xpguard-check/$`)

// Files the central CAPTCHA rule reads.
const (
	FileCaptchaSuspects = "captcha-suspects.txt"
	// FileCaptchaNotSuspects: IPDB entries the agent does not send to the
	// CAPTCHA (allowed, protected); read with the IPDB marks.
	FileCaptchaNotSuspects = "captcha-not-suspects.txt"
	FileCaptchaPass        = "captcha-pass.txt"
	// FileCaptchaSites lists Central.Sites (the rule holds them; the file
	// tells a change, see CentralChanged and CentralSitesAdded).
	FileCaptchaSites = "captcha-sites.txt"
	// FileCaptchaHosting and FileCaptchaHostingExempt: Central.HostingNets
	// and Central.HostingExempt.
	FileCaptchaHosting       = "captcha-hosting.txt"
	FileCaptchaHostingExempt = "captcha-hosting-exempt.txt"
)

// CentralFiles are the address lists of the central CAPTCHA rule. With
// ipdb (the IPDB list the marks read; nil without them) the suspects file
// holds only the suspects that are not on it, and FileCaptchaNotSuspects
// the IPDB entries that are no suspects (allowed, protected).
func CentralFiles(c *Central, ipdb []string) map[string]string {
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
	suspects, not := c.Suspects, []string(nil)
	if ipdb != nil {
		in := make(map[string]bool, len(ipdb))
		for _, a := range ipdb {
			in[a] = true
		}
		sus := make(map[string]bool, len(c.Suspects))
		suspects = nil
		for _, a := range c.Suspects {
			sus[a] = true
			if !in[a] {
				suspects = append(suspects, a)
			}
		}
		for _, a := range ipdb {
			if !sus[a] {
				not = append(not, a)
			}
		}
	}
	return map[string]string{FileCaptchaSuspects: list(suspects), FileCaptchaNotSuspects: list(not), FileCaptchaPass: list(c.Pass), FileCaptchaSites: siteList(c.Sites),
		FileCaptchaHosting: list(c.HostingNets), FileCaptchaHostingExempt: list(c.HostingExempt)}
}

// reSiteHost is a website name the site attack rule may hold.
var reSiteHost = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)

// MaxAttackSites caps the websites in the site attack rule.
const MaxAttackSites = 300

// AttackSites are the valid, distinct, sorted names of sites (at most
// MaxAttackSites).
func AttackSites(sites []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, h := range sites {
		h = strings.TrimPrefix(strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), "."), "www.")
		if reSiteHost.MatchString(h) && !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	sort.Strings(out)
	if len(out) > MaxAttackSites {
		out = out[:MaxAttackSites]
	}
	return out
}

func siteList(sites []string) string {
	l := AttackSites(sites)
	if len(l) == 0 {
		return "\n"
	}
	return strings.Join(l, "\n") + "\n"
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
func isGateRule(id int) bool { return id >= 7700900 && id <= 7700919 }

// CentralPassSlot is the pass-cookie slot an IDCentralPassUsed event names (-1: none).
func CentralPassSlot(id int) int {
	if id >= IDCentralPassUsed && id < IDCentralPassUsed+10 {
		return id - IDCentralPassUsed
	}
	return -1
}

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
	// Settings are checked when saved; a bad value from elsewhere is
	// dropped here so it can neither break the file nor add actions.
	c.WhitelistIPs = filter(c.WhitelistIPs, validAddr)
	c.WhitelistDomains = filter(c.WhitelistDomains, settings.ValidDomain)
	c.LoginURLs = filter(c.LoginURLs, settings.ValidLoginURL)
	c.LoginURLs = LoginPages(c.LoginURLs)
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
	if o.IPDBMarks {
		renderIPDBMarks(w, o.Dir)
	}
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
		// strong OWASP CRS signal still blocks them. Real AI crawlers come
		// from their official networks too, so the AI crawler rule only
		// stops fakes and crawlers that can not be verified.
		w(`SecRule REMOTE_ADDR "@ipMatchFromFile %s/%s" "id:%d,phase:1,t:none,pass,nolog,setvar:tx.xg_trusted=1,ctl:ruleRemoveById=%d-%d,ctl:ruleRemoveById=%d-%d,ctl:ruleRemoveById=%d,ctl:ruleRemoveById=%d,ctl:ruleRemoveById=%d,ctl:ruleRemoveById=%d,ctl:ruleRemoveById=%d-%d,ctl:ruleRemoveById=%d,ctl:ruleRemoveById=%d,ctl:ruleRemoveById=%d"`,
			o.Dir, FileTrustedIPs, IDTrusted, IDBadBots, IDSEOBots, IDCustomBots, IDFakeSearchBot, IDRootProbe+1000, IDEmptyUAWP, IDEmptyUAWP+1000, IDXMLRPCGet,
			IDGateNoCookie, IDCentralGate, IDSoftCaptcha, IDSoftDeny, IDNoUAPost)
		// The same for the second rule of the CAPTCHA on the website's own address.
		w(`SecRule REMOTE_ADDR "@ipMatchFromFile %s/%s" "id:%d,phase:1,t:none,pass,nolog,ctl:ruleRemoveById=%d,ctl:ruleRemoveById=%d,ctl:ruleRemoveById=%d"`,
			o.Dir, FileTrustedIPs, IDTrusted+2000, IDGateBadCookie, IDCentralGateBadCookie, IDCentralNoBrowserBadCookie)
		// LiteSpeed ignores ctl:ruleRemoveById, so the bot rules also test
		// tx.xg_trusted. Behind Cloudflare the visitor is CF-Connecting-IP,
		// which Cloudflare sets itself (X-Forwarded-For can be forged).
		w(`SecRule REMOTE_ADDR "@ipMatch %s" "id:%d,phase:1,t:none,pass,nolog,chain"`, strings.Join(cloudflareRanges(), ","), IDTrustedCF)
		w(`  SecRule REQUEST_HEADERS:CF-Connecting-IP "@ipMatchFromFile %s/%s" "t:none,setvar:tx.xg_trusted=1"`, o.Dir, FileTrustedIPs)
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
	if c.UploadScan && o.UploadScan && o.InspectPath != "" && !off[IDUploadMalware] {
		// Switched off means not rendered: LiteSpeed ignores IDDisable's ctl.
		w(`SecTmpSaveUploadedFiles On`)
		w(`SecRule FILES_TMPNAMES "@inspectFile %s" "id:%d,phase:2,t:none,deny,status:403,log,msg:'xPGuard - Malware upload blocked',tag:'xpguard/upload'"`, o.InspectPath, IDUploadMalware)
	}
	if c.BlockPHPUpload {
		rule(IDUploadPHP, `SecRule FILES "@rx \.(?:php[0-9]?|phtml|phar|pht|phps)$" "id:%d,phase:2,t:none,t:lowercase,deny,status:403,log,msg:'xPGuard - PHP file upload blocked',tag:'xpguard/upload'"`, IDUploadPHP)
	}
	if c.SensitiveFiles {
		rule(IDSensitive, `SecRule REQUEST_FILENAME "@rx /(?:\.env$|[a-z0-9_.-]+\.env$|env\.(?:txt|bak|old|orig|save)$|\.aws/|wp-config(?:-sample)?\.php(?:/|$)|[^/]+\.php[0-9]?\.suspected$|\.git/|\.svn/|\.(?:claude|cursor|crush|windsurf|codex|gemini|aider)/|\.hg/|\.htpasswd$|\.DS_Store$|\.env\.[a-z0-9_-]+$|[^/]+\.php[0-9]?(?:\.bak|\.old|\.orig|\.save|\.swp|\.txt|\.zip|~)$|debug\.log$|error_log$|[^/]+\.sql(?:\.gz|\.zip)?$|(?:wp[_-]options|woocommerce_[a-z0-9_]*settings)(?:\.(?:sql|zip|tar|gz|tgz|bz2|7z|rar|txt|log|bak|json|csv|xml))+$)" "id:%d,phase:1,t:none,t:urlDecodeUni,t:normalizePath,t:lowercase,deny,status:403,log,msg:'xPGuard - Access to sensitive file blocked',tag:'xpguard/files'"`, IDSensitive)
	}
	if c.WordPress {
		rule(IDUploadsPHP, `SecRule REQUEST_FILENAME "@rx /wp-content/+(?:uploads|blogs\.dir)/.*\.(?:php[0-9]?|phtml|phar|pht)(?:/|$)" "id:%d,phase:1,t:none,t:urlDecodeUni,t:normalizePath,t:lowercase,deny,status:403,log,msg:'xPGuard - PHP execution in uploads blocked',tag:'xpguard/wordpress'"`, IDUploadsPHP)
		rule(IDPHPInAssets, `SecRule REQUEST_FILENAME "@rx /(?:wp-content|wp-includes)/(?:[^?]*/)?(?:images?|img|fonts?|css|js)/+[^/]*\.(?:php[0-9]?|phtml|phar|pht)(?:/|$)" "id:%d,phase:1,t:none,t:urlDecodeUni,t:normalizePath,t:lowercase,deny,status:403,log,msg:'xPGuard - PHP execution in an assets folder blocked',tag:'xpguard/wordpress',chain"`, IDPHPInAssets)
		if !off[IDPHPInAssets] {
			// WordPress core's own TinyMCE loader lives in wp-includes/js;
			// Autoptimize's old non-static mode serves .php files from its cache.
			w(`  SecRule REQUEST_FILENAME "!@rx (?:/wp-includes/+js/+tinymce/+wp-tinymce\.php$|/cache/+autoptimize/)" "t:none,t:urlDecodeUni,t:normalizePath,t:lowercase"`)
		}
		rule(IDHiddenPHP, `SecRule REQUEST_FILENAME "@rx /\.[^/]+\.(?:php[0-9]?|phtml|phar)(?:/|$)" "id:%d,phase:1,t:none,t:urlDecodeUni,t:normalizePath,t:lowercase,deny,status:403,log,msg:'xPGuard - Hidden PHP file request blocked',tag:'xpguard/wordpress'"`, IDHiddenPHP)
		if !off[IDXMLRPCGet] {
			w(`SecRule REQUEST_FILENAME "@rx /xmlrpc\.php(?:/|$)" "id:%d,phase:1,t:none,t:urlDecodeUni,t:normalizePath,t:lowercase,deny,status:403,log,msg:'xPGuard - XML-RPC accepts only POST',tag:'xpguard/wordpress',chain"`, IDXMLRPCGet)
			w(`  SecRule REQUEST_METHOD "!@streq POST" "t:none"`)
		}
		if !off[IDEmptyUAWP] {
			w(`SecRule REQUEST_FILENAME "@rx /(?:wp-[a-z0-9_-]+\.php|wp-(?:admin|content|includes)/.*\.php)(?:/|$)" "id:%d,phase:1,t:none,t:urlDecodeUni,t:normalizePath,t:lowercase,deny,status:403,log,msg:'xPGuard - Request without User-Agent to a WordPress file blocked',tag:'xpguard/wordpress',chain"`, IDEmptyUAWP)
			w(`  SecRule &REQUEST_HEADERS:User-Agent "@eq 0" "t:none"`)
			w(`SecRule REQUEST_FILENAME "@rx /(?:wp-[a-z0-9_-]+\.php|wp-(?:admin|content|includes)/.*\.php)(?:/|$)" "id:%d,phase:1,t:none,t:urlDecodeUni,t:normalizePath,t:lowercase,deny,status:403,log,msg:'xPGuard - Request without User-Agent to a WordPress file blocked',tag:'xpguard/wordpress',chain"`, IDEmptyUAWP+1000)
			w(`  SecRule REQUEST_HEADERS:User-Agent "@rx ^\s*$" "t:none"`)
		}
		// Comment spam. The comment text goes to the log (logdata) so the
		// watch report shows what would have been refused.
		comment := `SecRule REQUEST_FILENAME "@rx /wp-comments-post\.php(?:/|$)" "id:%d,phase:2,t:none,t:urlDecodeUni,t:normalizePath,t:lowercase,deny,status:403,log,msg:'xPGuard - %s',tag:'xpguard/comment-spam',logdata:'%%{MATCHED_VAR}',chain"`
		if !off[IDCommentScript] {
			w(comment, IDCommentScript, "Comment posted by a script (no Origin or Referer) blocked")
			w(`  SecRule REQUEST_METHOD "@streq POST" "t:none,chain"`)
			w(`  SecRule &REQUEST_HEADERS:Origin "@eq 0" "t:none,chain"`)
			w(`  SecRule &REQUEST_HEADERS:Referer "@eq 0" "t:none"`)
		}
		if !off[IDCommentLinks] {
			w(comment, IDCommentLinks, "SEO spam comment (HTML link and website) blocked")
			w(`  SecRule ARGS_POST:url "@rx [a-z0-9]\.[a-z]" "t:none,t:lowercase,chain"`)
			w(`  SecRule ARGS_POST:comment "@rx <a\s[^>]*href\s*=" "t:none,t:htmlEntityDecode,t:lowercase"`)
			w(comment, IDCommentLinks+1000, "Spam comment with BBCode links blocked")
			w(`  SecRule ARGS_POST:comment "@rx \[(?:url|link)\s*=" "t:none,t:lowercase"`)
		}
		if !off[IDCommentManyLinks] {
			w(comment, IDCommentManyLinks, "Comment with 4 or more links blocked")
			// Four "://" (http, https, ftp …): each step stops right before the
			// next "://", so the match never backtracks far (no lookahead, which
			// not every ModSecurity engine supports).
			w(`  SecRule ARGS_POST:comment "@rx ^(?:(?:[^:]|:[^/]|:/[^/])*://){4}" "t:none,t:htmlEntityDecode"`)
		}
		if !off[IDXMLRPCMulti] {
			w(`SecRule REQUEST_FILENAME "@rx /xmlrpc\.php(?:/|$)" "id:%d,phase:2,t:none,t:urlDecodeUni,t:normalizePath,t:lowercase,deny,status:403,log,msg:'xPGuard - XML-RPC multicall blocked',tag:'xpguard/wordpress',chain"`, IDXMLRPCMulti)
			w(`  SecRule REQUEST_BODY "@contains system.multicall" "t:none,t:lowercase"`)
		}
		// User enumeration: /?author=1 redirects to /author/<login>/ and the
		// REST API lists users; attackers use both to find login names.
		if !off[IDUserEnum] {
			w(`SecRule ARGS_GET:author "@rx ^\s*\d" "id:%d,phase:1,t:none,t:urlDecodeUni,deny,status:403,log,msg:'xPGuard - WordPress user enumeration blocked',tag:'xpguard/wordpress',chain"`, IDUserEnum)
			w(`  SecRule &TX:xg_wp_user "@eq 0" "t:none"`)
		}
		if !off[IDRestUsers] {
			// Not /users/me: the block editor asks who is logged in (WordPress
			// answers 401 to visitors). RE2-safe: no lookahead (Coraza).
			w(`SecRule REQUEST_URI "@rx (?:/wp-json/+wp/v2/+users|[?&]rest_route=/*wp/v2/+users)(?:$|[^/]|/+(?:$|[^m]|m(?:$|[^e])|me[^/?&#]))" "id:%d,phase:1,t:none,t:urlDecodeUni,t:lowercase,deny,status:403,log,msg:'xPGuard - WordPress REST user list blocked',tag:'xpguard/wordpress',chain"`, IDRestUsers)
			w(`  SecRule &TX:xg_wp_user "@eq 0" "t:none"`)
		}
		// WordPress never runs the PHP files of wp-includes and of
		// wp-admin/includes, css, js and images directly (the hardening guide
		// denies them), except its TinyMCE loader and old multisite files.
		// Paths keep empty segments (//): not every engine normalises them.
		if !off[IDWPCoreDirect] {
			w(`SecRule REQUEST_FILENAME "@rx /wp-(?:includes|admin/+(?:includes|css|js|images))/(?:[^/]*/)*[^/]+\.(?:php[0-9]?|phtml|phar|pht)(?:/|$)" "id:%d,phase:1,t:none,t:urlDecodeUni,t:normalizePath,t:lowercase,deny,status:403,log,msg:'xPGuard - Direct request to a WordPress core PHP file blocked',tag:'xpguard/wordpress',chain"`, IDWPCoreDirect)
			w(`  SecRule REQUEST_FILENAME "!@rx /wp-includes/+(?:js/+tinymce/+wp-tinymce|ms-files)\.php$" "t:none,t:urlDecodeUni,t:normalizePath,t:lowercase"`)
		}
		if !off[IDWPAdminFake] {
			w(`SecRule REQUEST_FILENAME "@rx /wp-admin/+(?:network|user)/+[^/]+\.(?:php[0-9]?|phtml|phar|pht)(?:/|$)" "id:%d,phase:1,t:none,t:urlDecodeUni,t:normalizePath,t:lowercase,deny,status:403,log,msg:'xPGuard - PHP file that is not part of WordPress in wp-admin blocked',tag:'xpguard/wordpress',chain"`, IDWPAdminFake)
			w(`  SecRule REQUEST_FILENAME "!@rx /wp-admin/+(?:network|user)/+(?:%s)\.php$" "t:none,t:urlDecodeUni,t:normalizePath,t:lowercase"`, strings.Join(quoteAll(wpAdminNetwork), "|"))
		}
		if !off[IDWPLookalike] {
			w(`SecRule REQUEST_FILENAME "@rx /wp-[^/]*\.php[0-9]?(?:/|$)" "id:%d,phase:1,t:none,t:urlDecodeUni,t:normalizePath,t:lowercase,deny,status:403,log,msg:'xPGuard - Fake WordPress core file blocked',tag:'xpguard/wordpress',chain"`, IDWPLookalike)
			w(`  SecRule REQUEST_FILENAME "!@rx /wp-(?:admin|includes|content)/" "t:none,t:urlDecodeUni,t:normalizePath,t:lowercase,chain"`)
			w(`  SecRule REQUEST_FILENAME "!@rx /wp-(?:%s)\.php(?:/|$)" "t:none,t:urlDecodeUni,t:normalizePath,t:lowercase"`, strings.Join(quoteAll(wpRootFiles), "|"))
		}
		rule(IDWPUploadsList, `SecRule REQUEST_FILENAME "@rx /wp-content/+uploads/+(?:\d{4}/+(?:\d{2}/+)?)?$" "id:%d,phase:1,t:none,t:urlDecodeUni,t:normalizePath,t:lowercase,deny,status:403,log,msg:'xPGuard - Uploads folder listing blocked',tag:'xpguard/wordpress'"`, IDWPUploadsList)
		if !off[IDWPPackagePHP] {
			w(`SecRule REQUEST_FILENAME "@rx /wp-admin/+(?:update|async-upload|media-new|upload|theme-install|plugin-install)\.php$" "id:%d,phase:2,t:none,t:urlDecodeUni,t:normalizePath,t:lowercase,deny,status:403,log,msg:'xPGuard - PHP file sent to the WordPress plugin, theme or media uploader blocked',logdata:'%%{MATCHED_VAR}',tag:'xpguard/wordpress',chain"`, IDWPPackagePHP)
			w(`  SecRule FILES "@rx \.(?:php[0-9]?|phtml|phar|pht|phps)$" "t:none,t:lowercase"`)
		}
		if !off[IDWPCachePHP] {
			// Autoptimize's old non-static mode serves .php files from its cache.
			w(`SecRule REQUEST_FILENAME "@rx /wp-content/+cache/.*\.(?:php[0-9]?|phtml|phar|pht)(?:/|$)" "id:%d,phase:1,t:none,t:urlDecodeUni,t:normalizePath,t:lowercase,deny,status:403,log,msg:'xPGuard - PHP execution in the cache folder blocked',tag:'xpguard/wordpress',chain"`, IDWPCachePHP)
			w(`  SecRule REQUEST_FILENAME "!@rx /cache/+autoptimize/" "t:none,t:urlDecodeUni,t:normalizePath,t:lowercase"`)
		}
	}
	if c.Generic {
		// Any website: static folders hold no PHP; repeated folders
		// (/images/images/cache.php) and hidden folders are backdoor hunts.
		if !off[IDStaticPHP] {
			w(`SecRule REQUEST_FILENAME "@rx /(?:images?|img|fonts?|css)/+[^/]*\.(?:php[0-9]?|phtml|phar|pht)(?:/|$)" "id:%d,phase:1,t:none,t:urlDecodeUni,t:normalizePath,t:lowercase,deny,status:403,log,msg:'xPGuard - PHP execution in a static folder blocked',tag:'xpguard/generic',chain"`, IDStaticPHP)
			// Also the colour stylesheets of ViserLab scripts (HYIPLAB, PTC…).
			w(`  SecRule REQUEST_FILENAME "!@rx (?:/cache/+autoptimize/|/assets/+templates/+[^/]+/+css/+color\.php$)" "t:none,t:urlDecodeUni,t:normalizePath,t:lowercase"`)
		}
		rule(IDRepeatDirPHP, `SecRule REQUEST_FILENAME "@rx /([^/]+)/+\1/(?:[^/]*/)*[^/]*\.(?:php[0-9]?|phtml|phar|pht)(?:/|$)" "id:%d,phase:1,t:none,t:urlDecodeUni,t:normalizePath,t:lowercase,deny,status:403,log,msg:'xPGuard - PHP request through repeated folders blocked',tag:'xpguard/generic'"`, IDRepeatDirPHP)
		if !off[IDHiddenDirPHP] {
			w(`SecRule REQUEST_FILENAME "@rx /\.[^/]+/(?:[^/]*/)*[^/]*\.(?:php[0-9]?|phtml|phar|pht)(?:/|$)" "id:%d,phase:1,t:none,t:urlDecodeUni,t:normalizePath,t:lowercase,deny,status:403,log,msg:'xPGuard - PHP execution in a hidden folder blocked',tag:'xpguard/generic',chain"`, IDHiddenDirPHP)
			w(`  SecRule REQUEST_FILENAME "!@contains /.well-known/" "t:none,t:urlDecodeUni,t:normalizePath,t:lowercase"`)
		}
		// REQUEST_URI is not decoded: %252e%252e is ".." encoded twice.
		rule(IDDoubleEncode, `SecRule REQUEST_URI "@rx %%25(?:25)*2e%%25(?:25)*2e" "id:%d,phase:1,t:none,t:lowercase,deny,status:403,log,msg:'xPGuard - Double-encoded path traversal blocked',tag:'xpguard/generic'"`, IDDoubleEncode)
	}
	if c.VirtualPatches {
		if !off[IDVPGravitySMTP] {
			w(`SecRule REQUEST_URI "@rx (?:/wp-json/+gravitysmtp/|[?&]rest_route=/?gravitysmtp/)" "id:%d,phase:1,t:none,t:urlDecodeUni,t:lowercase,deny,status:403,log,msg:'xPGuard - Virtual patch: Gravity SMTP REST API without login',tag:'xpguard/vpatch',chain"`, IDVPGravitySMTP)
			w(`  SecRule &TX:xg_wp_user "@eq 0" "t:none"`)
		}
		rule(IDVPFileManager, `SecRule REQUEST_FILENAME "@rx /wp-content/+plugins/+wp-file-manager/+lib/+php/+connector\.minimal\.php(?:/|$)" "id:%d,phase:1,t:none,t:urlDecodeUni,t:normalizePath,t:lowercase,deny,status:403,log,msg:'xPGuard - Virtual patch: WP File Manager connector (CVE-2020-25213)',tag:'xpguard/vpatch'"`, IDVPFileManager)
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
		rule(IDVPLiteSpeed, `SecRule REQUEST_FILENAME "@rx /wp-content/+litespeed/+debug/" "id:%d,phase:1,t:none,t:urlDecodeUni,t:normalizePath,t:lowercase,deny,status:403,log,msg:'xPGuard - Virtual patch: LiteSpeed Cache debug log (CVE-2024-44000)',tag:'xpguard/vpatch'"`, IDVPLiteSpeed)
		// No form has field names of 16 KB; the exploit needs one larger
		// than PHP's memory limit (or a body cut at the request body limit
		// still shows more than 16 KB of it).
		rule(IDVPPHPFormName, `SecRule ARGS_POST_NAMES "@rx (?s)^.{16385}" "id:%d,phase:2,t:none,deny,status:403,log,msg:'xPGuard - Virtual patch: PHP form field name of more than 16 KB (PHP2Shell, CVE-2026-109618)',tag:'xpguard/vpatch'"`, IDVPPHPFormName)
	}
	if c.BruteForce {
		// Successful WordPress logins redirect (302); a failed one shows the form again (200).
		if !off[IDLoginWP] {
			w(`SecRule REQUEST_METHOD "@streq POST" "id:%d,phase:3,pass,log,msg:'xPGuard - Failed login: WordPress',tag:'xpguard/login',chain"`, IDLoginWP)
			w(`  SecRule REQUEST_FILENAME "@rx /wp-login\.php(?:/|$)" "t:none,t:urlDecodeUni,t:normalizePath,t:lowercase,chain"`)
			w(`  SecRule RESPONSE_STATUS "@streq 200" "t:none"`)
		}
		if !off[IDLoginXMLRPC] {
			// Only calls that log in (wp.*, blogger.*, metaWeblog.*, mt.*,
			// multicall): not pingbacks, Jetpack's own jetpack.* calls or
			// system.listMethods.
			w(`SecRule REQUEST_METHOD "@streq POST" "id:%d,phase:2,pass,log,msg:'xPGuard - Login attempt: XML-RPC',tag:'xpguard/login',chain"`, IDLoginXMLRPC)
			w(`  SecRule REQUEST_FILENAME "@rx /xmlrpc\.php(?:/|$)" "t:none,t:urlDecodeUni,t:normalizePath,t:lowercase,chain"`)
			w(`  SecRule REQUEST_BODY "@rx <methodname>\s*(?:wp\.|blogger\.|metaweblog\.|mt\.|system\.multicall)" "t:none,t:lowercase"`)
		}
		if !off[IDLoginJoomla] {
			w(`SecRule REQUEST_METHOD "@streq POST" "id:%d,phase:2,pass,log,msg:'xPGuard - Login attempt: Joomla',tag:'xpguard/login',chain"`, IDLoginJoomla)
			w(`  SecRule REQUEST_FILENAME "@rx /administrator/index\.php(?:/|$)" "t:none,t:urlDecodeUni,t:normalizePath,t:lowercase,chain"`)
			w(`  SecRule ARGS:task "@streq login" "t:none,t:lowercase"`)
		}
		if !off[IDLoginOpenCart] {
			// A successful login redirects (302); a failed one shows the form (200).
			w(`SecRule REQUEST_METHOD "@streq POST" "id:%d,phase:3,pass,log,msg:'xPGuard - Login attempt: OpenCart',tag:'xpguard/login',chain"`, IDLoginOpenCart)
			w(`  SecRule REQUEST_FILENAME "@rx /admin/index\.php(?:/|$)" "t:none,t:urlDecodeUni,t:normalizePath,t:lowercase,chain"`)
			w(`  SecRule ARGS:route "@rx ^common/login" "t:none,t:lowercase,chain"`)
			w(`  SecRule RESPONSE_STATUS "@streq 200" "t:none"`)
		}
		var custom []string
		for _, u := range c.LoginURLs {
			if !knownLogin[strings.ToLower(u)] {
				custom = append(custom, regexp.QuoteMeta(strings.ToLower(u)))
			}
		}
		if len(custom) > 0 && !off[IDLoginCustom] {
			// Like WordPress: a failed login shows the form again (200), a
			// successful one redirects.
			w(`SecRule REQUEST_METHOD "@streq POST" "id:%d,phase:3,pass,log,msg:'xPGuard - Login attempt: protected URL',tag:'xpguard/login',chain"`, IDLoginCustom)
			w(`  SecRule REQUEST_FILENAME "@rx (?:%s)(?:/|$)" "t:none,t:urlDecodeUni,t:normalizePath,t:lowercase,chain"`, strings.Join(custom, "|"))
			w(`  SecRule RESPONSE_STATUS "@streq 200" "t:none"`)
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
				w(`SecRule REQUEST_FILENAME "@rx (?:%s)(?:/|$)" "id:%d,phase:1,t:none,t:urlDecodeUni,t:normalizePath,t:lowercase,redirect:https://%%{REQUEST_HEADERS.Host}:%d/.xpguard/gate?back=%%{REQUEST_URI},log,msg:'xPGuard - CAPTCHA required for a login page',tag:'xpguard/captcha',chain"`,
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
		// Only a browser opening a page (it accepts HTML) is sent to the
		// CAPTCHA page; bots and scripts (xmlrpc.php posts) get a 403.
		// The visitor has not passed yet: not on the pass list, or (on the
		// website's own address) without a valid pass cookie, missing or
		// wrong (two rules: what LiteSpeed's engine runs too).
		type notPassed struct {
			gate, deny int
			cond       string
		}
		var pending []notPassed
		var toks []string
		var slots [][]string
		for i, sl := range ct.Slots {
			if i >= 10 {
				break
			}
			var ok []string
			for _, t := range sl {
				if reGateToken.MatchString(t) {
					ok = append(ok, t)
				}
			}
			slots = append(slots, ok)
			toks = append(toks, ok...)
		}
		site := ct.Site && len(toks) > 0 && ct.HTTPSPort > 0 && ct.HTTPSPort < 65536
		if site {
			// Not passed: no pass cookie, and not on the pass list either (a
			// visitor that cannot reach the CAPTCHA port solves on the portal,
			// which lets the address in like portal mode).
			pass := fmt.Sprintf(`(?:^|;)\s*%s=(?:%s)\s*(?:;|$)`, GateCookie, strings.Join(toks, "|"))
			listed := fmt.Sprintf(`SecRule REMOTE_ADDR "!@ipMatchFromFile %s/%s" "t:none`, o.Dir, FileCaptchaPass)
			pending = []notPassed{
				{IDCentralGate, IDCentralNoBrowser, `SecRule &REQUEST_HEADERS:Cookie "@eq 0" "t:none,chain"` + "\n  " + listed},
				{IDCentralGateBadCookie, IDCentralNoBrowserBadCookie, fmt.Sprintf(`SecRule REQUEST_HEADERS:Cookie "!@rx %s" "t:none,chain"`, pass) + "\n  " + listed},
			}
		} else {
			pending = []notPassed{{IDCentralGate, IDCentralNoBrowser, fmt.Sprintf(`SecRule REMOTE_ADDR "!@ipMatchFromFile %s/%s" "t:none`, o.Dir, FileCaptchaPass)}}
		}
		if !ct.All {
			// The suspects, once: IPDB-listed (the marks) except the few the
			// agent left out, and the others from their own short list (see
			// CentralFiles). Every gate rule reading the full list kept a copy
			// of it in each web server process.
			if o.IPDBMarks {
				w(`SecRule TX:%s "@eq 1" "id:%d,phase:1,t:none,pass,nolog,chain"`, ipdbMarkVars[0], IDMarkSuspect)
				w(`  SecRule REMOTE_ADDR "!@ipMatchFromFile %s/%s" "t:none,setvar:tx.xg_suspect=1"`, o.Dir, FileCaptchaNotSuspects)
			}
			w(`SecRule REMOTE_ADDR "@ipMatchFromFile %s/%s" "id:%d,phase:1,t:none,pass,nolog,setvar:tx.xg_suspect=1"`, o.Dir, FileCaptchaSuspects, IDMarkSuspect+1)
			// A website under a password-guessing attack from many
			// addresses: every visitor of its login page is a suspect.
			var gated []string
			for _, u := range ct.SiteLoginURLs {
				gated = append(gated, regexp.QuoteMeta(strings.ToLower(u)))
			}
			if sites := AttackSites(ct.Sites); len(sites) > 0 && len(gated) > 0 {
				w(`SecRule SERVER_NAME "@rx ^(?:www\.)?(?:%s)\.?$" "id:%d,phase:1,t:none,t:lowercase,pass,nolog,chain"`, strings.Join(quoteAll(sites), "|"), IDMarkSiteAttack)
				w(`  SecRule REQUEST_FILENAME "@rx (?:%s)(?:/|$)" "t:none,t:urlDecodeUni,t:normalizePath,t:lowercase,setvar:tx.xg_suspect=1"`, strings.Join(gated, "|"))
			}
			// A login page opened from a hosting network (not xmlrpc.php:
			// apps and services call it from servers).
			if ct.Hosting && len(gated) > 0 {
				w(`SecRule REMOTE_ADDR "@ipMatchFromFile %s/%s" "id:%d,phase:1,t:none,pass,nolog,chain"`, o.Dir, FileCaptchaHosting, IDMarkHosting)
				w(`  SecRule REMOTE_ADDR "!@ipMatchFromFile %s/%s" "t:none,chain"`, o.Dir, FileCaptchaHostingExempt)
				if o.Trusted {
					w(`  SecRule REMOTE_ADDR "!@ipMatchFromFile %s/%s" "t:none,chain"`, o.Dir, FileTrustedIPs)
				}
				w(`  SecRule REQUEST_FILENAME "@rx (?:%s)(?:/|$)" "t:none,t:urlDecodeUni,t:normalizePath,t:lowercase,setvar:tx.xg_suspect=1"`, strings.Join(gated, "|"))
			}
		}
		gateRule := func(id int, cond, action, msg, browser string) {
			w(`SecRule REQUEST_FILENAME "@rx (?:%s)(?:/|$)" "id:%d,phase:1,t:none,t:urlDecodeUni,t:normalizePath,t:lowercase,%s,log,msg:'%s',tag:'xpguard/captcha',chain"`,
				strings.Join(urls, "|"), id, action, msg)
			if !ct.All {
				w(`  SecRule TX:xg_suspect "@eq 1" "t:none,chain"`)
			}
			if browser == "" {
				w(`  %s"`, cond)
				return
			}
			w(`  %s,chain"`, cond)
			w(`  SecRule REQUEST_HEADERS:Accept "%s" "t:none,t:lowercase"`, browser)
		}
		redirect := fmt.Sprintf("redirect:%s?s=%s&ip=%%{REMOTE_ADDR}&h=%%{REQUEST_HEADERS.Host}&u=%%{REQUEST_URI}", ct.URL, ct.ServerID)
		if !site && reHostPage.MatchString(ct.HostPage) {
			// On this server's hostname: port 443, no website in between.
			redirect = fmt.Sprintf("redirect:%s?s=%s&ip=%%{REMOTE_ADDR}&h=%%{REQUEST_HEADERS.Host}&u=%%{REQUEST_URI}", ct.HostPage, ct.ServerID)
			host := strings.TrimSuffix(strings.TrimPrefix(ct.HostPage, "https://"), "/xpguard-check/")
			w(`SecRule REQUEST_FILENAME "@beginsWith /xpguard-check/" "id:%d,phase:1,t:none,t:lowercase,pass,nolog,ctl:ruleEngine=Off,chain"`, IDHostPage)
			w(`  SecRule SERVER_NAME "@streq %s" "t:none,t:lowercase"`, host)
		}
		if site {
			// Through the portal's page, which sends the visitor on to this
			// server's CAPTCHA port on the website's address (the page there
			// sets the pass cookie) when the browser reaches that port, and
			// otherwise shows the check itself: a website behind Cloudflare
			// and agents' cloud browsers only reach 80 and 443
			// (roxannebradley.online: "refused to connect" on :7743).
			redirect = fmt.Sprintf("redirect:%s?s=%s&ip=%%{REMOTE_ADDR}&h=%%{REQUEST_HEADERS.Host}&g=%d&u=%%{REQUEST_URI}", ct.URL, ct.ServerID, ct.HTTPSPort)
		}
		for _, p := range pending {
			gateRule(p.gate, p.cond, redirect, "xPGuard - suspicious visitor sent to the CAPTCHA", "@contains text/html")
		}
		// After the redirect: whatever it did not send away (also requests
		// without an Accept header) is not a browser.
		for _, p := range pending {
			gateRule(p.deny, p.cond, "deny,status:403", "xPGuard - suspicious visitor blocked (not a browser)", "")
		}
		// Which pass-cookie value a suspect sends: a value sent from an address
		// it was not given to is withdrawn by the agent (one solve shared
		// with a botnet).
		if site {
			for i, sl := range slots {
				if len(sl) == 0 {
					continue
				}
				w(`SecRule REQUEST_FILENAME "@rx (?:%s)(?:/|$)" "id:%d,phase:1,t:none,t:urlDecodeUni,t:normalizePath,t:lowercase,pass,log,msg:'xPGuard - CAPTCHA pass cookie used',tag:'xpguard/captcha',chain"`,
					strings.Join(urls, "|"), IDCentralPassUsed+i)
				if !ct.All {
					w(`  SecRule TX:xg_suspect "@eq 1" "t:none,chain"`)
				}
				w(`  SecRule REQUEST_HEADERS:Cookie "@rx (?:^|;)\s*%s=(?:%s)\s*(?:;|$)" "t:none"`, GateCookie, strings.Join(sl, "|"))
			}
		}
	}
	if c.Webshell {
		rule(IDWebshell, `SecRule REQUEST_FILENAME "@rx /(?:%s)[0-9]?(?:/|$)" "id:%d,phase:1,t:none,t:urlDecodeUni,t:normalizePath,t:lowercase,deny,status:403,log,msg:'xPGuard - Web shell request blocked',tag:'xpguard/webshell'"`, strings.Join(quoteAll(WebshellNames), "|"), IDWebshell)
		rule(IDWebshellDir, `SecRule REQUEST_FILENAME "@rx /(?:alfa_data|alfacgiapi|wso_data)/" "id:%d,phase:1,t:none,t:urlDecodeUni,t:normalizePath,t:lowercase,deny,status:403,log,msg:'xPGuard - Web shell folder request blocked',tag:'xpguard/webshell'"`, IDWebshellDir)
		// (CRS reads plain PHP in cookies; this one the base64 form.)
		rule(IDStaticPost, `SecRule REQUEST_METHOD "@streq POST" "id:%d,phase:1,t:none,deny,status:403,log,msg:'xPGuard - POST to an image or stylesheet blocked',tag:'xpguard/webshell',chain"
  SecRule REQUEST_FILENAME "@rx \.(?:gif|jpe?g|png|ico|bmp|webp|css)$" "t:none,t:urlDecodeUni,t:normalizePath,t:lowercase"`, IDStaticPost)
		rule(IDCookieShell, `SecRule REQUEST_COOKIES "@rx (?i)\b(?:system|passthru|shell_exec|proc_open|popen|pcntl_exec|assert|eval|create_function|file_put_contents|move_uploaded_file)\s*\(" "id:%d,phase:1,t:none,t:urlDecodeUni,t:base64Decode,deny,status:403,log,msg:'xPGuard - Web shell command in a cookie blocked',logdata:'%%{MATCHED_VAR_NAME}',tag:'xpguard/webshell'"`, IDCookieShell)
		// Paths only exploit scanners request: PHPUnit's eval-stdin.php
		// (CVE-2017-9841), Laravel Ignition (CVE-2021-3129), leaked credentials.
		if in := o.Intel; in != nil && len(in.Names) > 0 && !off[IDFleetNames] {
			// Not in wp-admin and wp-includes: WordPress's own files live
			// there, and other rules refuse anything else in them.
			var names []string
			for _, n := range in.Names {
				if FleetNameOK(n) {
					names = append(names, n)
				}
			}
			if len(names) > 0 {
				w(`SecRule REQUEST_FILENAME "@rx /(?:%s)(?:/|$)" "id:%d,phase:1,t:none,t:urlDecodeUni,t:normalizePath,t:lowercase,deny,status:403,log,msg:'xPGuard - Web shell name learned by the fleet blocked',tag:'xpguard/webshell',chain"`, strings.Join(quoteAll(names), "|"), IDFleetNames)
				w(`  SecRule REQUEST_FILENAME "!@rx /wp-(?:admin|includes)/" "t:none,t:urlDecodeUni,t:normalizePath,t:lowercase"`)
			}
		}
		rule(IDMalwareExt, `SecRule REQUEST_FILENAME "@rx /wp-content/+(?:%s)(?:/|$)" "id:%d,phase:1,t:none,t:urlDecodeUni,t:normalizePath,t:lowercase,deny,status:403,log,msg:'xPGuard - Malware plugin or theme folder blocked',tag:'xpguard/webshell'"`, strings.Join(quoteAll(MalwareExtDirs), "|"), IDMalwareExt)
		rule(IDExploitProbe, `SecRule REQUEST_FILENAME "@rx /(?:vendor/+phpunit/+phpunit/+src/+util/+php/+eval-stdin\.php|_ignition/+execute-solution|\.aws/+credentials|\.vscode/+sftp\.json|sftp-config\.json|\.git-credentials)(?:/|$)" "id:%d,phase:1,t:none,t:urlDecodeUni,t:normalizePath,t:lowercase,deny,status:403,log,msg:'xPGuard - Exploit probe blocked',tag:'xpguard/webshell'"`, IDExploitProbe)
	}
	bot := func(on bool, file string, id int, what string) {
		if on && !off[id] {
			// Trusted services (official lists, verified crawlers) are the real
			// crawlers; anyone may read robots.txt.
			w(`SecRule REQUEST_HEADERS:User-Agent "@pmFromFile %s/%s" "id:%d,phase:1,t:none,deny,status:403,log,msg:'xPGuard - %s blocked',tag:'xpguard/bot',chain"`, o.Dir, file, id, what)
			w(`  SecRule &TX:xg_trusted "@eq 0" "t:none,chain"`)
			w(`  SecRule REQUEST_FILENAME "!@streq /robots.txt" "t:none"`)
		}
	}
	bot(c.BadBots, FileBadBots, IDBadBots, "Bad bot")
	if c.BadBots {
		// PHP probes on the top folder with neither a User-Agent nor a
		// Referer: tools hunting for planted backdoors (/w.php, /alfa.php).
		probe := func(id int, ua string) {
			w(`SecRule REQUEST_FILENAME "@rx ^/+[^/]+\.(?:php[0-9]?|phtml|phar)(?:/|$)" "id:%d,phase:1,t:none,t:urlDecodeUni,t:normalizePath,t:lowercase,deny,status:403,log,msg:'xPGuard - PHP probe without User-Agent and Referer blocked',tag:'xpguard/bot',chain"`, id)
			w(`  SecRule REQUEST_FILENAME "!@rx ^/+(?:index|wp-cron|xmlrpc)\.php(?:/|$)" "t:none,t:urlDecodeUni,t:normalizePath,t:lowercase,chain"`)
			w(`  SecRule &REQUEST_HEADERS:Referer "@eq 0" "t:none,chain"`)
			w(`  %s`, ua)
		}
		if !off[IDRootProbe] {
			probe(IDRootProbe, `SecRule &REQUEST_HEADERS:User-Agent "@eq 0" "t:none"`)
			probe(IDRootProbe+1000, `SecRule REQUEST_HEADERS:User-Agent "@rx ^\s*$" "t:none"`)
		}
		// POSTs to any PHP file from a tool that sends no User-Agent, no
		// Referer and no cookie. API, webhook and payment callback paths
		// are left alone: servers call them with bare HTTP clients.
		if !off[IDNoUAPost] {
			noUA := func(id int, ua string) {
				w(`SecRule REQUEST_METHOD "@streq POST" "id:%d,phase:1,t:none,deny,status:403,log,msg:'xPGuard - POST without User-Agent, Referer or cookie blocked',tag:'xpguard/bot',chain"`, id)
				w(`  SecRule REQUEST_FILENAME "@rx \.(?:php[0-9]?|phtml)(?:/|$)" "t:none,t:urlDecodeUni,t:normalizePath,t:lowercase,chain"`)
				w(`  SecRule REQUEST_FILENAME "!@rx (?:/(?:index|wp-cron|xmlrpc|admin-ajax|wp-login|cron|api)\.php(?:/|$)|/(?:api|apis|webhooks?|hooks?|callbacks?|ipn|notify|notifications?|gateways?|payments?|modules/gateways|oauth|cron|rest|v[0-9])/)" "t:none,t:urlDecodeUni,t:normalizePath,t:lowercase,chain"`)
				w(`  SecRule REQUEST_FILENAME "!@rx (?:callback|webhook|notify|ipn|hook|return|listener|response|status|verify|licen[cs]|activat|validat|heartbeat|register|session|check)[^/]*\.php(?:/|$)" "t:none,t:urlDecodeUni,t:normalizePath,t:lowercase,chain"`)
				w(`  SecRule &REQUEST_HEADERS:Referer "@eq 0" "t:none,chain"`)
				w(`  SecRule &REQUEST_COOKIES "@eq 0" "t:none,chain"`)
				w(`  %s`, ua)
			}
			noUA(IDNoUAPost, `SecRule &REQUEST_HEADERS:User-Agent "@eq 0" "t:none"`)
			noUA(IDNoUAPost+1000, `SecRule REQUEST_HEADERS:User-Agent "@rx ^\s*$" "t:none"`)
		}
		crawler := `SecRule REQUEST_HEADERS:User-Agent "@rx (?:bot|crawl|spider|slurp|fetcher|scraper)\b" "t:none,t:lowercase%s"`
		if !off[IDCrawlerCart] {
			w(`SecRule ARGS_NAMES "@rx ^(?:add[-_]to[-_](?:cart|wishlist|compare)|wishlist_add|yith_wcwl_add)" "id:%d,phase:1,t:none,t:lowercase,deny,status:403,log,msg:'xPGuard - Crawler adding to cart or wishlist blocked',tag:'xpguard/bot',chain"`, IDCrawlerCart)
			w(`  `+crawler, "")
		}
		if !off[IDCrawlerFacets] {
			w(`SecRule ARGS_GET_NAMES "@rx ^(?:filter_[a-z0-9_-]+|query_type_[a-z0-9_-]+|orderby|min_price|max_price|per_page|rating_filter|product_count|shop_view|pa_[a-z0-9_-]+)$" "id:%d,phase:1,t:none,t:lowercase,deny,status:403,log,msg:'xPGuard - Crawler on shop filter URLs blocked',tag:'xpguard/bot',chain"`, IDCrawlerFacets)
			w(`  `+crawler, ",chain")
			w(`  SecRule REQUEST_HEADERS:User-Agent "!@rx (?:googlebot|bingbot|applebot|yandex|duckduckbot|google-inspectiontool|adsbot-google|mediapartners-google)" "t:none,t:lowercase"`)
		}
		// Search engines are exempt (fake ones are blocked by their own rule).
		search := `SecRule REQUEST_HEADERS:User-Agent "!@rx (?:googlebot|bingbot|applebot|yandex|duckduckbot|google-inspectiontool|adsbot-google|mediapartners-google)" "t:none,t:lowercase"`
		if !off[IDShopScrape] {
			// A visitor clicking a filter on the site: the browser says the
			// request came from the same site (Sec-Fetch-Site, sent by every
			// current browser) and the Referer, when sent, is this site.
			// A Referer alone is not enough: the filter botnets send one
			// (blacksoulltd.com on business900, 2026-10-22: ~800 requests a
			// minute from 28,000 addresses with browser User-Agents, which
			// put LiteSpeed into a restart loop).
			w(`SecRule REQUEST_HEADERS:Sec-Fetch-Site "@streq same-origin" "id:%d,phase:1,t:none,t:lowercase,pass,nolog,chain"`, IDShopScrape+2000)
			w(`  SecRule &REQUEST_HEADERS:Referer "@eq 0" "t:none,setvar:tx.xg_same_origin=1"`)
			w(`SecRule REQUEST_HEADERS:Sec-Fetch-Site "@streq same-origin" "id:%d,phase:1,t:none,t:lowercase,pass,nolog,chain"`, IDShopScrape+5000)
			w(`  SecRule REQUEST_HEADERS:Referer "@rx ^https?://([^/?#]+)" "t:none,t:lowercase,capture,chain"`)
			w(`  SecRule TX:1 "@streq %%{REQUEST_HEADERS.Host}" "t:none,t:lowercase,setvar:tx.xg_same_origin=1"`)
			w(`SecRule ARGS_GET:/^filter_/|ARGS_GET:/^pa_/ "@rx ^[^,]*,[^,]*," "id:%d,phase:1,t:none,t:urlDecodeUni,deny,status:403,log,msg:'xPGuard - Shop filter scraping blocked (no cookies, many filter values)',tag:'xpguard/bot',chain"`, IDShopScrape)
			w(`  SecRule &REQUEST_COOKIES "@eq 0" "t:none,chain"`)
			w(`  %s`, search)
			w(`SecRule &ARGS_GET:/^filter_/ "@ge 3" "id:%d,phase:1,t:none,deny,status:403,log,msg:'xPGuard - Shop filter scraping blocked (no cookies, many filters)',tag:'xpguard/bot',chain"`, IDShopScrape+1000)
			w(`  SecRule &REQUEST_COOKIES "@eq 0" "t:none,chain"`)
			w(`  %s`, search)
		}
		if !off[IDCartSpam] {
			w(`SecRule &ARGS_GET:remove_item "@ge 1" "id:%d,phase:1,t:none,deny,status:403,log,msg:'xPGuard - Cart spam blocked (remove and add in one link)',tag:'xpguard/bot',chain"`, IDCartSpam)
			w(`  SecRule ARGS_GET_NAMES "@rx ^add[-_]to[-_]cart$" "t:none,t:lowercase"`)
			// Removing an item needs a cart, and a cart needs the session
			// cookie. (Not add-to-cart: a guest's first click has no cookie.)
			w(`SecRule ARGS_GET_NAMES "@rx ^(?:remove_item|undo_item)$" "id:%d,phase:1,t:none,t:lowercase,deny,status:403,log,msg:'xPGuard - Cart change without a session blocked',tag:'xpguard/bot',chain"`, IDCartSpam+1000)
			w(`  SecRule &ARGS_GET:_wpnonce "@ge 1" "t:none,chain"`)
			w(`  SecRule &REQUEST_COOKIES "@eq 0" "t:none"`)
		}
		if !off[IDBareMozilla] {
			// Not for logged-in users and API clients (some site tools send it).
			w(`SecRule REQUEST_HEADERS:User-Agent "@rx ^\s*mozilla/5\.0\s*$" "id:%d,phase:1,t:none,t:lowercase,deny,status:403,log,msg:'xPGuard - Fake browser User-Agent blocked',tag:'xpguard/bot',chain"`, IDBareMozilla)
			w(`  SecRule &REQUEST_HEADERS:Authorization "@eq 0" "t:none,chain"`)
			w(`  SecRule &TX:xg_wp_user "@eq 0" "t:none"`)
		}
	}
	bot(c.SEOBots, FileSEOBots, IDSEOBots, "SEO crawler")
	bot(c.AIBots, FileAIBots, IDAIBots, "Fake AI crawler")
	bot(c.BotBlocker && len(c.BotList) > 0, FileCustomBots, IDCustomBots, "Bad bot")
	if len(o.VerifiedBots) > 0 && o.Trusted && c.BotBlocker && !off[IDFakeSearchBot] {
		// A forwarded-for header any client can add does not skip the test
		// (audit A3 F4): direct visitors are tested by their address;
		// behind Cloudflare by CF-Connecting-IP (IDTrustedCF sets
		// tx.xg_trusted, which every one of these tests); behind a local
		// proxy only when it names no visitor (it may be a real crawler).
		head := func(id int) {
			w(`SecRule REQUEST_HEADERS:User-Agent "@rx \b(?:%s)\b" "id:%d,phase:1,t:none,t:lowercase,deny,status:403,log,msg:'xPGuard - Fake search engine crawler blocked',tag:'xpguard/bot',chain"`, strings.Join(quoteAll(o.VerifiedBots), "|"), id)
			w(`  SecRule REMOTE_ADDR "!@ipMatchFromFile %s/%s" "t:none,chain"`, o.Dir, FileTrustedIPs)
		}
		head(IDFakeSearchBot)
		w(`  SecRule REMOTE_ADDR "!@ipMatchFromFile %s/%s" "t:none"`, o.Dir, FileProxyRanges)
		head(IDFakeSearchBot + 1000)
		w(`  SecRule REMOTE_ADDR "@ipMatchFromFile %s/%s" "t:none,chain"`, o.Dir, FileLocalProxys)
		w(`  SecRule &REQUEST_HEADERS:X-Forwarded-For "@eq 0" "t:none,chain"`)
		w(`  SecRule &REQUEST_HEADERS:X-Real-IP "@eq 0" "t:none,chain"`)
		w(`  SecRule &REQUEST_HEADERS:CF-Connecting-IP "@eq 0" "t:none"`)
		head(IDFakeSearchBot + 2000)
		w(`  SecRule REMOTE_ADDR "@ipMatchFromFile %s/%s" "t:none"`, o.Dir, FileCFRanges)
	}
	// rblRule blocks addresses on a list, directly and behind a proxy (real
	// address from the forwarded-for headers; id+1000), except exempt
	// addresses. viaCF also blocks visitors Cloudflare marks with that
	// country code (id+2000; T1 is Tor).
	rblRule := func(id int, post bool, list, msg string, viaCF string) {
		if post && list == FileIPDBIPs && o.IPDBMarks {
			// The marks of renderIPDBMarks instead of the list itself.
			heads := []struct {
				id         int
				what, mark string
				headers    string
			}{{id, "", ipdbMarkVars[0], ""}}
			for i, v := range viaProxies(id + 1000) {
				heads = append(heads, struct {
					id         int
					what, mark string
					headers    string
				}{v.id, " (behind a proxy)", ipdbMarkVars[i+1], v.headers})
			}
			for _, h := range heads {
				w(`SecRule REQUEST_METHOD "@streq POST" "id:%d,phase:1,t:none,deny,status:403,log,msg:'xPGuard - %s%s',tag:'xpguard/rbl',chain"`, h.id, msg, h.what)
				w(`  SecRule &TX:xg_wp_editing "@eq 0" "t:none,chain"`)
				w(`  SecRule &TX:xg_api "@eq 0" "t:none,chain"`)
				if h.headers == "" {
					w(`  SecRule TX:%s "@eq 1" "t:none,chain"`, h.mark)
					w(`  SecRule REMOTE_ADDR "!@ipMatchFromFile %s/%s" "t:none"`, o.Dir, FileRBLExempt)
					continue
				}
				w(`  SecRule TX:%s "@eq 1" "t:none,chain"`, h.mark)
				w(`  SecRule %s "@rx ^\s*([0-9A-Fa-f:.]{3,45})" "capture,chain"`, h.headers)
				w(`    SecRule TX:1 "!@ipMatchFromFile %s/%s" "t:none"`, o.Dir, FileRBLExempt)
			}
			return
		}
		head := func(id int, what, first string) {
			if post {
				w(`SecRule REQUEST_METHOD "@streq POST" "id:%d,phase:1,t:none,deny,status:403,log,msg:'xPGuard - %s%s',tag:'xpguard/rbl',chain"`, id, msg, what)
				// A logged-in WordPress user is the site's own editor on a
				// shared or mobile address (WordPress checks the login;
				// logins themselves are still refused from listed addresses).
				// Only in the admin and REST API: anyone can send the cookie,
				// so forms and other pages stay refused (audit A3 F1).
				w(`  SecRule &TX:xg_wp_editing "@eq 0" "t:none,chain"`)
				if list == FileIPDBIPs {
					// API calls and webhooks (marked by IDIPDBPostAPI: LiteSpeed
					// ignores its ctl:ruleRemoveById, so the marker decides).
					w(`  SecRule &TX:xg_api "@eq 0" "t:none,chain"`)
				}
				w(`  SecRule REMOTE_ADDR "@ipMatchFromFile %s/%s" "t:none,chain"`, o.Dir, first)
			} else {
				w(`SecRule REMOTE_ADDR "@ipMatchFromFile %s/%s" "id:%d,phase:1,t:none,deny,status:403,log,msg:'xPGuard - %s%s',tag:'xpguard/rbl',chain"`, o.Dir, first, id, msg, what)
			}
		}
		head(id, "", list)
		w(`  SecRule REMOTE_ADDR "!@ipMatchFromFile %s/%s" "t:none"`, o.Dir, FileRBLExempt)
		for _, v := range viaProxies(id + 1000) {
			head(v.id, " (behind a proxy)", v.file)
			w(`  SecRule %s "@rx ^\s*([0-9A-Fa-f:.]{3,45})" "capture,chain"`, v.headers)
			w(`    SecRule TX:1 "@ipMatchFromFile %s/%s" "t:none,chain"`, o.Dir, list)
			w(`    SecRule TX:1 "!@ipMatchFromFile %s/%s" "t:none"`, o.Dir, FileRBLExempt)
		}
		if viaCF != "" {
			head(id+2000, " (Cloudflare)", FileProxyRanges)
			w(`  SecRule REQUEST_HEADERS:CF-IPCountry "@streq %s" "t:none"`, viaCF)
		}
	}
	if c.IPDBPost && !off[IDIPDBPost] {
		// Anyone can add an API header, so it only counts on what looks
		// like an API call (audit A3 F5): no cookie, no browser asking for
		// a page and not a login page. (A missing Accept header would not
		// match a negated test: a marker for the browser's one.)
		logins := []string{`/wp-login\.php`, `/xmlrpc\.php`}
		for _, u := range c.LoginURLs {
			logins = append(logins, regexp.QuoteMeta(strings.ToLower(u)))
		}
		w(`SecRule REQUEST_HEADERS:Accept "@contains text/html" "id:%d,phase:1,t:none,t:lowercase,pass,nolog,setvar:tx.xg_page=1"`, IDIPDBPostAPI+1000)
		w(`SecRule REQUEST_HEADERS_NAMES "@rx %s" "id:%d,phase:1,t:none,t:lowercase,pass,nolog,chain"`, reAPIHeader.String(), IDIPDBPostAPI)
		w(`  SecRule &REQUEST_COOKIES "@eq 0" "t:none,chain"`)
		w(`  SecRule &TX:xg_page "@eq 0" "t:none,chain"`)
		w(`  SecRule REQUEST_FILENAME "!@rx (?:%s)(?:/|$)" "t:none,t:urlDecodeUni,t:normalizePath,t:lowercase,setvar:tx.xg_api=1"`, strings.Join(logins, "|"))
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
		for _, v := range viaProxies(IDProxyBlocked) {
			w(`SecRule REMOTE_ADDR "@ipMatchFromFile %s/%s" "id:%d,phase:1,t:none,deny,status:403,log,msg:'xPGuard - Blacklisted IP behind proxy',tag:'xpguard/proxy',chain"`, o.Dir, v.file, v.id)
			w(`  SecRule %s "@rx ^\s*([0-9A-Fa-f:.]{3,45})" "capture,chain"`, v.headers)
			w(`    SecRule TX:1 "@ipMatchFromFile %s/%s" "t:none"`, o.Dir, FileBlockedIPs)
		}
	}
	out := b.String()
	if o.Trusted {
		// LiteSpeed ignores the trusted rule's ctl:ruleRemoveById: the
		// rules it removes also test tx.xg_trusted.
		out = guardChains(out, `SecRule &TX:xg_trusted "@eq 0" "t:none,chain"`, IDRootProbe, IDRootProbe+1000, IDEmptyUAWP, IDEmptyUAWP+1000,
			IDXMLRPCGet, IDGateNoCookie, IDGateBadCookie, IDCentralGate, IDCentralNoBrowser, IDCentralGateBadCookie, IDCentralNoBrowserBadCookie, IDNoUAPost, IDNoUAPost+1000, IDFakeSearchBot, IDFakeSearchBot+1000, IDFakeSearchBot+2000)
	}
	// The shop filter rules test the same-site marker (IDShopScrape+2000 and
	// +5000; a negated header test would not match a request without the
	// header).
	out = guardChains(out, `SecRule &TX:xg_same_origin "@eq 0" "t:none,chain"`, IDShopScrape, IDShopScrape+1000)
	// And for the theme colour stylesheets (IDThemeColorCSS).
	out = guardChains(out, `SecRule &TX:xg_color_css "@eq 0" "t:none,chain"`, IDStaticPHP, IDPHPInAssets)
	return applyMonitor(out, Monitored(o.Intel))
}

// guardChains adds cond (a chained rule) as the second rule of the chained
// rules with the given ids, so they skip what cond excludes without relying
// on ctl:ruleRemoveById, which LiteSpeed's ModSecurity ignores.
func guardChains(text, cond string, ids ...int) string {
	want := map[int]bool{}
	for _, id := range ids {
		want[id] = true
	}
	lines := strings.Split(text, "\n")
	out := make([]string, 0, len(lines)+len(ids))
	for i, l := range lines {
		out = append(out, l)
		if !strings.HasPrefix(l, "SecRule ") || !strings.HasSuffix(l, `,chain"`) {
			continue
		}
		m := reRuleID.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		if id, _ := strconv.Atoi(m[1]); !want[id] || (i+1 < len(lines) && strings.TrimSpace(lines[i+1]) == cond) {
			continue
		}
		out = append(out, "  "+cond)
	}
	return strings.Join(out, "\n")
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
		FileCFRanges:    strings.Join(cloudflareRanges(), "\n") + "\n",
		FileLocalProxys: "127.0.0.1\n::1\n",
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

func validAddr(a string) bool { return settings.ValidAddr(a) }

func filter(l []string, ok func(string) bool) []string {
	var out []string
	for _, v := range l {
		if ok(v) {
			out = append(out, v)
		}
	}
	return out
}

func quoteAll(l []string) []string {
	out := make([]string, len(l))
	for i, v := range l {
		out[i] = regexp.QuoteMeta(v)
	}
	return out
}

// reAPIHeader: header names (lowercase) of authenticated API calls and
// signed webhooks; such calls skip the IPDB POST rule.
var reAPIHeader = regexp.MustCompile(`^(?:authorization|x-api-key|api-key|apikey|x-auth-token|x-access-token|x-[a-z0-9-]*-(?:token|key|hmac[a-z0-9-]*)|[a-z0-9-]*signature[a-z0-9-]*)$`)

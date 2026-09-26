// Package waf manages XMart Guard's ModSecurity rule set on Apache (and
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
	"strings"

	"github.com/xmarthost/xmartguard/agent/internal/settings"
)

// Rule id ranges by category.
const (
	IDWhitelist     = 7700001
	IDWhiteDomains  = 7700002
	IDDisable       = 7700003
	IDUploadMalware = 7700101
	IDUploadPHP     = 7700102
	IDSensitive     = 7700201
	IDUploadsPHP    = 7700301
	IDXMLRPCMulti   = 7700302
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
)

// RuleInfo describes one of our rules for the settings page.
type RuleInfo struct {
	ID       int    `json:"id"`
	Category string `json:"category"`
	Title    string `json:"title"`
	Action   string `json:"action"`
}

// Catalog lists every rule XMart Guard can load.
var Catalog = []RuleInfo{
	{IDUploadMalware, "upload_scan", "Scan uploaded files with the XMart Guard malware engine", "block"},
	{IDUploadPHP, "block_php_upload", "Block uploads of PHP files through web forms", "block"},
	{IDSensitive, "sensitive_files", "Block access to .env, .git, config backups, logs and SQL dumps", "block"},
	{IDUploadsPHP, "wordpress", "Block running PHP files inside wp-content/uploads", "block"},
	{IDXMLRPCMulti, "wordpress", "Block XML-RPC system.multicall (password guessing amplification)", "block"},
	{IDLoginWP, "bruteforce", "Count failed WordPress logins", "count"},
	{IDLoginXMLRPC, "bruteforce", "Count WordPress XML-RPC login calls", "count"},
	{IDLoginJoomla, "bruteforce", "Count Joomla administrator logins", "count"},
	{IDLoginOpenCart, "bruteforce", "Count OpenCart administrator logins", "count"},
	{IDLoginCustom, "bruteforce", "Count logins on the other protected login URLs", "count"},
	{IDWebshell, "webshell", "Block requests to well-known web shell files", "block"},
	{IDWebshellDir, "webshell", "Block requests into web shell working folders", "block"},
	{IDBadBots, "bad_bots", "Block vulnerability scanners and abusive tools", "block"},
	{IDSEOBots, "seo_bots", "Block aggressive SEO crawlers", "block"},
	{IDAIBots, "ai_bots", "Block AI training crawlers", "block"},
	{IDCustomBots, "custom_bots", "Block custom User-Agents", "block"},
}

// Bot lists (matched case-insensitively as substrings of the User-Agent).
var (
	BadBots = []string{"sqlmap", "nikto", "nmap scripting engine", "masscan", "zgrab", "nuclei", "wpscan", "acunetix",
		"netsparker", "dirbuster", "gobuster", "feroxbuster", "fuzz faster u fool", "whatweb", "jorgee", "zmeu",
		"morfeus", "havij", "w3af", "openvas", "arachni", "skipfish", "commix", "wfuzz"}
	SEOBots = []string{"ahrefsbot", "semrushbot", "mj12bot", "dotbot", "blexbot", "petalbot", "dataforseobot",
		"serpstatbot", "megaindex", "barkrowler", "seekportbot", "linkpadbot", "seznambot", "zoominfobot"}
	AIBots = []string{"gptbot", "ccbot", "bytespider", "amazonbot", "perplexitybot", "claudebot", "anthropic-ai",
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
)

// Options tune rendering for what the local ModSecurity supports.
type Options struct {
	Dir         string // where the rules and bot lists live
	InspectPath string // upload approver script
	UploadScan  bool   // false when @inspectFile is unusable
}

// Render builds the rules file for the given settings.
func Render(c settings.WAF, o Options) string {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }
	w("# XMart Guard WAF rules. Managed by xmartguard-agent: changes here are overwritten.")
	w("# Configure them in the XMart Guard portal (Settings » WAF & Bruteforce).")
	w("")
	if len(c.WhitelistIPs) > 0 {
		w(`SecRule REMOTE_ADDR "@ipMatch %s" "id:%d,phase:1,pass,nolog,ctl:ruleRemoveById=7700002-7709999"`, strings.Join(c.WhitelistIPs, ","), IDWhitelist)
	}
	if len(c.WhitelistDomains) > 0 {
		var alt []string
		for _, d := range c.WhitelistDomains {
			alt = append(alt, strings.ReplaceAll(regexp.QuoteMeta(d), `\*`, `[^.]+`))
		}
		w(`SecRule SERVER_NAME "@rx ^(?:%s)$" "id:%d,phase:1,t:none,t:lowercase,pass,nolog,ctl:ruleRemoveById=7700003-7709999"`, strings.Join(alt, "|"), IDWhiteDomains)
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
		w(`SecRule FILES_TMPNAMES "@inspectFile %s" "id:%d,phase:2,t:none,deny,status:403,log,msg:'XMartGuard - Malware upload blocked',tag:'xmartguard/upload'"`, o.InspectPath, IDUploadMalware)
	}
	if c.BlockPHPUpload {
		w(`SecRule FILES "@rx \.(?:php[0-9]?|phtml|phar|pht|phps)$" "id:%d,phase:2,t:none,t:lowercase,deny,status:403,log,msg:'XMartGuard - PHP file upload blocked',tag:'xmartguard/upload'"`, IDUploadPHP)
	}
	if c.SensitiveFiles {
		w(`SecRule REQUEST_FILENAME "@rx /(?:\.env$|\.git/|\.svn/|\.hg/|\.htpasswd$|\.DS_Store$|wp-config\.php(?:\.bak|\.old|\.orig|\.save|\.swp|\.txt|~)$|debug\.log$|error_log$|[^/]+\.sql(?:\.gz|\.zip)?$)" "id:%d,phase:1,t:none,t:urlDecodeUni,t:lowercase,deny,status:403,log,msg:'XMartGuard - Access to sensitive file blocked',tag:'xmartguard/files'"`, IDSensitive)
	}
	if c.WordPress {
		w(`SecRule REQUEST_FILENAME "@rx /wp-content/uploads/.*\.(?:php[0-9]?|phtml|phar|pht)$" "id:%d,phase:1,t:none,t:urlDecodeUni,t:lowercase,deny,status:403,log,msg:'XMartGuard - PHP execution in uploads blocked',tag:'xmartguard/wordpress'"`, IDUploadsPHP)
		w(`SecRule REQUEST_FILENAME "@endsWith /xmlrpc.php" "id:%d,phase:2,t:none,t:lowercase,deny,status:403,log,msg:'XMartGuard - XML-RPC multicall blocked',tag:'xmartguard/wordpress',chain"`, IDXMLRPCMulti)
		w(`  SecRule REQUEST_BODY "@contains system.multicall" "t:none,t:lowercase"`)
	}
	if c.BruteForce {
		// Successful WordPress logins redirect (302); a failed one shows the form again (200).
		w(`SecRule REQUEST_METHOD "@streq POST" "id:%d,phase:3,pass,log,msg:'XMartGuard - Failed login: WordPress',tag:'xmartguard/login',chain"`, IDLoginWP)
		w(`  SecRule REQUEST_FILENAME "@endsWith /wp-login.php" "t:none,t:lowercase,chain"`)
		w(`  SecRule RESPONSE_STATUS "@streq 200" "t:none"`)
		w(`SecRule REQUEST_METHOD "@streq POST" "id:%d,phase:2,pass,log,msg:'XMartGuard - Login attempt: XML-RPC',tag:'xmartguard/login',chain"`, IDLoginXMLRPC)
		w(`  SecRule REQUEST_FILENAME "@endsWith /xmlrpc.php" "t:none,t:lowercase"`)
		w(`SecRule REQUEST_METHOD "@streq POST" "id:%d,phase:2,pass,log,msg:'XMartGuard - Login attempt: Joomla',tag:'xmartguard/login',chain"`, IDLoginJoomla)
		w(`  SecRule REQUEST_FILENAME "@endsWith /administrator/index.php" "t:none,t:lowercase,chain"`)
		w(`  SecRule ARGS:task "@streq login" "t:none,t:lowercase"`)
		w(`SecRule REQUEST_METHOD "@streq POST" "id:%d,phase:2,pass,log,msg:'XMartGuard - Login attempt: OpenCart',tag:'xmartguard/login',chain"`, IDLoginOpenCart)
		w(`  SecRule REQUEST_FILENAME "@endsWith /admin/index.php" "t:none,t:lowercase,chain"`)
		w(`  SecRule ARGS:route "@rx ^common/login" "t:none,t:lowercase"`)
		var custom []string
		for _, u := range c.LoginURLs {
			if !knownLogin[strings.ToLower(u)] {
				custom = append(custom, regexp.QuoteMeta(strings.ToLower(u)))
			}
		}
		if len(custom) > 0 {
			w(`SecRule REQUEST_METHOD "@streq POST" "id:%d,phase:2,pass,log,msg:'XMartGuard - Login attempt: protected URL',tag:'xmartguard/login',chain"`, IDLoginCustom)
			w(`  SecRule REQUEST_FILENAME "@rx (?:%s)$" "t:none,t:urlDecodeUni,t:lowercase"`, strings.Join(custom, "|"))
		}
	}
	if c.Webshell {
		w(`SecRule REQUEST_FILENAME "@rx /(?:%s)$" "id:%d,phase:1,t:none,t:urlDecodeUni,t:lowercase,deny,status:403,log,msg:'XMartGuard - Web shell request blocked',tag:'xmartguard/webshell'"`, strings.Join(quoteAll(WebshellNames), "|"), IDWebshell)
		w(`SecRule REQUEST_FILENAME "@rx /(?:alfa_data|alfacgiapi|wso_data)/" "id:%d,phase:1,t:none,t:urlDecodeUni,t:lowercase,deny,status:403,log,msg:'XMartGuard - Web shell folder request blocked',tag:'xmartguard/webshell'"`, IDWebshellDir)
	}
	bot := func(on bool, file string, id int, what string) {
		if on {
			w(`SecRule REQUEST_HEADERS:User-Agent "@pmFromFile %s/%s" "id:%d,phase:1,t:none,deny,status:403,log,msg:'XMartGuard - %s blocked',tag:'xmartguard/bot'"`, o.Dir, file, id, what)
		}
	}
	bot(c.BadBots, FileBadBots, IDBadBots, "Bad bot")
	bot(c.SEOBots, FileSEOBots, IDSEOBots, "SEO crawler")
	bot(c.AIBots, FileAIBots, IDAIBots, "AI crawler")
	bot(len(c.CustomBots) > 0, FileCustomBots, IDCustomBots, "Custom bot")
	return b.String()
}

// BotFiles returns the bot list files to write next to the rules.
func BotFiles(c settings.WAF) map[string]string {
	join := func(l []string) string { return strings.Join(l, "\n") + "\n" }
	return map[string]string{
		FileBadBots:    join(BadBots),
		FileSEOBots:    join(SEOBots),
		FileAIBots:     join(AIBots),
		FileCustomBots: join(c.CustomBots),
	}
}

func quoteAll(l []string) []string {
	out := make([]string, len(l))
	for i, v := range l {
		out[i] = regexp.QuoteMeta(v)
	}
	return out
}

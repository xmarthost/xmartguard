# WAF Rule Sets

**Portal » WAF Rule Sets** holds one ModSecurity configuration for all
servers. Saving it sends `waf.sync` to every online server; offline servers
apply it when they connect (agents also check every 15 minutes). Each server
reports back what it applied, shown under **Rollout**.

| Rule set | Source | Price | How it reaches the server | Updates |
|---|---|---|---|---|
| XMart Guard rules | built in | free | agent renders them (`/etc/xmartguard/waf/rules.conf`) | with agent releases |
| OWASP Core Rule Set | [github.com/coreruleset/coreruleset](https://github.com/coreruleset/coreruleset) (Apache 2.0) | free | portal downloads the official release, agents install it next to our rules | portal checks GitHub every 12 h; "latest" follows new releases, or pin a version |
| Malware.Expert | [malware.expert](https://malware.expert/modsecurity-rules/) | paid (single server / 50 / unlimited) | cPanel vendor: agent runs `whmapi1 modsec_add_vendor url=…` with the vendor URL from your subscription, then enables it with automatic updates | by WHM from the vendor |
| Comodo WAF (CWAF) | [waf.comodo.com](https://waf.comodo.com/) | free (registration) | cPanel vendor (`meta_comodo_apache.yaml`; LiteSpeed servers get `meta_comodo_litespeed.yaml`) | by WHM; the service has been unreliable, servers report download errors |
| Any other cPanel vendor | vendor YAML URL | depends | cPanel vendor | by WHM |
| Custom rules | typed in the portal | free | `/etc/xmartguard/waf/custom.conf`, loaded last | when you save |

Not included:

- **ConfigServer ModSecurity rules**: ConfigServer closed on 31 August 2025;
  its vendor URL no longer works.
- **Imunify360 / BitNinja / cPGuard's own feeds**: proprietary, licensed with
  those products.
- **Atomicorp (ASL / Atomic ModSecurity Rules)**: commercial, installed with
  Atomicorp's own tools; the old free "delayed" feed is no longer offered.
  If Atomicorp gives you a cPanel vendor URL, add it as "Other cPanel vendor".

## Defaults

OWASP CRS is **on by default** (paranoia level 1). XMart Guard's own rules
stay on next to it for what CRS does not cover: WordPress hardening (PHP
running in uploads, images, fonts, css and js folders; hidden `.php` files;
GET on `xmlrpc.php`; requests without a User-Agent to WordPress files; user
enumeration), PHP backups and `.env.*` files, upload scanning with the
malware engine, bad bots and login brute force.

## How blocking works

- XMart Guard rules deny directly (403).
- OWASP CRS scores each request; a request is blocked (403, rule 949110)
  when its score reaches the threshold (5 = one critical match). Paranoia
  level 1 is the right choice for shared hosting; levels 2–4 add rules and
  false positives.
- Vendors use their own actions (Malware.Expert answers 406).

Where the web server already loads its own CRS (cPanel's OWASP vendor
`OWASP3`, Debian's `modsecurity-crs` or RHEL's `mod_security_crs` package),
the portal's CRS copy is skipped, because loading CRS twice fails on
duplicate rule ids. Blocks by CRS are named after the attack that scored
(for example "SQL Injection Attack Detected via libinjection (Total Score: 5)"). Before anything is loaded the web server
configuration is tested; if it fails, the extra rule sets are left out
(and reported), and XMart Guard's rules stay active.

## Self-test

After every change the agent requests `/xmartguard-waf-selftest` from the
local web server (127.0.0.1, http then https); rule 7700000 must answer 403.
With OWASP CRS active it also sends a harmless XSS-looking query that CRS
must block. Rollout shows "self-test passed" or the exact problem (for
example "a test request that must be blocked got HTTP 200"), and the
dashboard marks the WAF as not working. Self-test requests are not counted
as attacks.

On cPanel the rules are hooked in through `/etc/apache2/conf.d/zz-xmartguard-waf.conf`
(httpd.conf loads every `conf.d/*.conf`; Apache and LiteSpeed both read it).
Agents before 0.7.7 used `conf.d/includes/`, which cPanel does not load.

## Where the hits are counted

The agent reads ModSecurity hits from

- the web server error log (Apache `ModSecurity:` lines, LiteSpeed
  `[Module:mod_security]` lines), and
- the ModSecurity audit log (serial `modsec_audit.log`, or concurrent logs
  through their index file) — the same log WHM » ModSecurity Tools shows.

A hit that appears in both is recorded once (by ModSecurity's unique id).
Only blocked requests are counted as web attacks; OWASP CRS's per-rule
warnings are not recorded. The logs being read are listed per server under
Rollout ("Reads hits from").

## Licensed feeds and linked servers (Malware.Expert)

Every WHM vendor and remote feed (SecRemoteRules) has **Linked servers**:
"All servers" (default) or "Only selected servers". The portal sends a feed
only to the servers it is linked to (`/api/agent/waf/config` filters by the
calling server), so a feed licensed for one IP is never loaded elsewhere.
Unlinked servers drop it on the next sync (WHM vendors that XMart Guard
added are disabled).

"Add a remote feed… » Malware.Expert" fills in:

- URL `https://rules.malware.expert/download.php?rules=generic` with all
  **extra rules** (`&extra=webshell,scanner,crawler,rbl,proxy,recaptcha`);
  each module can be switched off with its checkbox.
- **Captcha by Malware.Expert** (`recaptcha`): Malware.Expert's reCaptcha for
  bots on WordPress/Joomla logins, on the linked servers only. XMart Guard's
  own CAPTCHA keeps working for firewall bans; Settings » WAF shows which
  one a server uses.
- An optional POST blocklist: `POST` requests from addresses listed on
  `rbl.malware.expert` are dropped (rule 7700801, chained on
  `REMOTE_ADDR @rbl`).
- The first server as the only linked server.

The license/serial key is entered in the portal only (never in this
repository), is shown masked and is sent only to the linked servers.
After applying, the agent reads what ModSecurity logged while loading the
feed (`Loaded N rules from: '…'` or `Problems loading external resources`)
in the web server's error log and reports "N rules loaded" or the error
under Rollout, because ModSecurity itself only logs a warning
(`SecRemoteRulesFailAction Warn`) and keeps serving. The agent does not
download the feed itself: Malware.Expert answers other clients with
"Are you going to steal our rules ?" (HTTP 505).

Malware.Expert replaces the OWASP CRS: on every server linked to an
enabled Malware.Expert feed (or WHM vendor) the portal sends CRS switched
off ("replaced by Malware.Expert on this server" under Rollout), so two
generic rule sets never run together. Other servers keep CRS. The agent
reports whether it runs CRS (`crs_enabled`), so servers that are already up
to date switch at their next sync.

The WHM ModSecurity vendors card is the older way to install the same rule
sets; it is hidden unless a vendor is configured. Use either the WHM vendor
or the remote feed for the same rules on a server, not both.

## Settings clean-up (0.9.6)

- Captcha is switched on and set up on the Firewall page only; Settings »
  WAF shows its state with a link.
- IPDB switches live on the Firewall page only (Settings » IPDB removed).
- AI crawler blocking lives in Settings » WAF only.
- "Block PHP file uploads" appears once (Settings » WAF).
- "Block SEO crawlers" merged into the Bad Bot blocker list (its crawlers
  are added to the list while the blocker is on).
- Malware.Expert rows show only on servers linked to Malware.Expert; rows
  it also covers carry a "+ Malware.Expert" badge.

## Custom rules

Only ModSecurity rule directives are accepted: `SecRule`, `SecAction`,
`SecMarker`, `SecRuleRemoveById/ByTag/ByMsg` and `SecRuleUpdate…`. Apache
directives, `exec:`, `setenv:`, `@inspectFile` and `@…FromFile` operators
are rejected (by the portal and again by the agent), so the portal cannot be
used to run commands on servers. Ids 7700000–7709999 are reserved for
XMart Guard; use 1000000–1999999.

Example (the Gravity SMTP data exposure seen in the Malware.Expert log):

```
SecRule REQUEST_URI "@beginsWith /wp-json/gravitysmtp/v1/tests/mock-data" \
  "id:1000001,phase:1,deny,status:403,log,msg:'Gravity SMTP sensitive information exposure'"
```

## Security

Adding a vendor lets that vendor's rules run on every server; only the
account owner can add a vendor that is not in the preset list. Every save
is recorded in the Security Log (`waf.rulesets_saved`), and servers apply
changes only after the web server accepts the configuration.

## Portal behind a WAF (0.9.7)

The web app sends PUT/PATCH/DELETE as `POST` with `X-HTTP-Method-Override`
(many WAFs, including OWASP CRS rule 911100, allow only GET/HEAD/POST).
`deploy/setup-almalinux.sh` also turns ModSecurity off for the portal's own
vhost: the portal saves ModSecurity rules, keys and rule URLs by design,
which any WAF would block. On an existing install run:

```
F=$(ls /etc/apache2/conf.d/userdata/ssl/2_4/*/YOUR-PORTAL-DOMAIN/xmartguard.conf)
printf '<IfModule security2_module>\n  SecRuleEngine Off\n</IfModule>\n' >> "$F"
/usr/local/cpanel/scripts/rebuildhttpdconf && /usr/local/cpanel/scripts/restartsrv_httpd
```

## Login-page CAPTCHA (0.9.10)

Settings » WAF » **Captcha Protected URLs** has a switch: while on, every
visitor of those URLs (by default `/wp-login.php`, `/xmlrpc.php`,
`/administrator/index.php`, `/admin/index.php`) is sent to the CAPTCHA
before the page opens; the rest of the website never shows it.

- Rules 7700902 (no Cookie header) and 7700903 (no valid `xg_gate` in it):
  a request for a protected URL is redirected (302) to
  `https://<host>:<captcha HTTPS port>/.xmartguard/gate?back=<uri>`. They use
  no TX counters or SERVER_PORT, which LiteSpeed's own engine did not run.
  Logged by the web server, but not recorded as attacks.
- Solving it sets `xg_gate` (HttpOnly, SameSite=Lax, valid for the CAPTCHA
  allow time) and returns the visitor to the login page. The cookie value is
  an HMAC of the UTC day with a per-server secret; today's and yesterday's
  are accepted and the WAF is re-applied when the day changes.
- It does not unban or allow the address in the firewall. Banned addresses
  still get the CAPTCHA on the whole site and are unbanned when they solve
  it (Firewall » CAPTCHA).
- The CAPTCHA ports (default 7780/7743) are opened in XMart Guard's port
  filter and, under CSF, with an `iptables -I INPUT … xmartguard-captcha`
  rule that csfpost.sh restores after `csf -r`.

Malware.Expert on LiteSpeed: LiteSpeed does not log "Loaded N rules", so a
feed is shown as working once its own blocks (`[tag "MEWAF"]`) appear in the
error log. With the `rbl` extra, Malware.Expert's rule 400010 already drops
POSTs from rbl.malware.expert and XMart Guard's 7700801 is left out.

When the Malware.Expert feed linked to a server has the `recaptcha` extra,
its CAPTCHA protects the login pages there (rule 1000050: addresses on
blacklist.recaptcha.cloud are sent to recaptcha.cloud) and XMart Guard's
login-page CAPTCHA is not rendered on that server, since it would stop every
visitor before Malware.Expert's rule. Settings » WAF shows "Captcha by
Malware.Expert" instead of the switch.

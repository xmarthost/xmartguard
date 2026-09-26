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

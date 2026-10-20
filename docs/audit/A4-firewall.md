# A4 firewall audit: agent/internal/firewall, hostfw, tor, trusted, reputation

## F1. Log injection in the brute-force rules lets an attacker get any IP banned, and reported to the fleet IPDB
- Severity: HIGH
- Kind: security
- Confidence: HIGH (checked by running the regexes on crafted lines)
- Where: agent/internal/firewall/bruteforce.go:27, :29, :41, :43 (also :45, :47); the ban path goes bruteforce.go:186 -> firewall.go:942 AutoBan -> ipdb.go:237 IPDBReports (source `bruteforce`)
- Scenario: the user name in SSH and the SET_ID or envelope sender in Exim are attacker-controlled, and none of the patterns is anchored to the end of the line.
  - SSH: an attacker at 5.6.7.8 logs in as the user `x from 9.9.9.9`. sshd writes `Invalid user x from 9.9.9.9 from 5.6.7.8 port 4000`, and rule :27 captures **9.9.9.9**. The same trick works for `Failed password for invalid user ...`, and for `Disconnected from invalid user x 9.9.9.9 ...` (rule :29).
  - Exim: `authenticator failed for (helo) [5.6.7.8]:4000: 535 ... (set_id=a[9.9.9.9])` matches :41 with 9.9.9.9, because the greedy `.*\[` takes the last bracket.
  - Exim: `H=(helo) [5.6.7.8] F=<a[9.9.9.9]@x> rejected RCPT ...: relay not permitted` matches :43 with 9.9.9.9.
  - Result: five such attempts temp-ban any address that is not protected, trusted or whitelisted (a customer's office, an admin's home IP, a monitoring service that is not on the list). The ban is then sent to the portal as a `bruteforce` IPDB report, so it can spread to the whole fleet. The real attacker is never counted.
- Fix: anchor every pattern to the fixed text that follows the IP, the way fail2ban does.
  - sshd: `from <IP> port \d+( ssh2)?(: .*)?( \[preauth\])?\s*$`, or take the last `from <IP> port` on the line.
  - Exim: take the IP from `H=... [IP]` or `for (...) [IP]:port:` with a non-greedy match before the first `]:`, not the last bracket.
  - Regression test: inert lines like the ones above must yield 5.6.7.8, or no match.

## F2. Whitelisted countries, trusted services and "ignore" entries bypass the port filter and the DoS limit
- Severity: HIGH
- Kind: security
- Confidence: HIGH
- Where: firewall.go:288-305 (Protected, Trusted, IgnoredCountries and KindIgnore all go into `rs.Ignore`); iptables.go:185 and :323 (`xg_allow` = Allow+Ignore, RETURN before the DoS and port-filter rules :363-382); nft.go:150-151 and :219 (`allow4/6` = Allow+Ignore, `accept` before the DoS and `xg-port` rules :261-274)
- Scenario: the admin turns the port filter on with only 22/80/443 open, then whitelists the country PK (meant only to exempt that country from the IPDB, bans and CAPTCHA). Every address in PK can now reach every closed TCP/UDP port (MySQL 3306, Redis, memcached and so on), and the DoS rate limit no longer applies to them. The same happens for every trusted-service range: all of Cloudflare, CloudFront, Fastly, Meta's AS, Google user-triggered fetchers, Telegram and the custom trusted list. The UI calls these "exempt from blocks", not "all ports open".
- Fix: keep two sets.
  - `allow` holds only the explicit whitelist (KindAllow) and the protected addresses. It may bypass everything.
  - `exempt` holds Ignore, the trusted services and the whitelisted countries. It only skips the IPDB, deny, tempban and country drops: the input chain should jump past those drops for `exempt` and still fall through to the DoS and port-filter rules.
  - Render this the same way in both backends, and leave the CAPTCHA nat chain matching both sets.
  - Test: an address in a whitelisted country gets past the IPDB rule but not the port filter.

## F3. The port filter can lock SSH out: sshd ports are read only from the main sshd_config
- Severity: HIGH
- Kind: failure-mode
- Confidence: HIGH
- Where: firewall.go:1122-1138 (SSHPorts); used in portFilter at :1101
- Scenario: on AlmaLinux/CloudLinux 9, `sshd_config` has `Include /etc/ssh/sshd_config.d/*.conf`. An admin who sets `Port 2222` in a drop-in has it missed: SSHPorts returns [22], and 2222 is not in DefaultTCPIn. When the port filter is turned on, new SSH connections to 2222 are dropped for everyone who is not whitelisted (an existing session survives through ESTABLISHED). The same happens with `ListenAddress x:2222`. The comment on portFilter promises the filter "cannot lock anyone out".
- Fix: take the effective ports from `sshd -T` (lines `port N`, `listenaddress host:port`). If that fails, read the main file and follow its `Include` globs. Never drop the ports sshd is actually listening on: as a safety net, also add the TCP ports of the sshd process found in `/proc/net/tcp{,6}`. Test with a drop-in fixture.

## F4. Country blocks are never applied to IPv6, though the portal sends IPv6 networks and Check reports them as blocked
- Severity: MEDIUM
- Kind: bug
- Confidence: HIGH
- Where: nft.go:147-148 and :255-259 (`cb4, _ := split(...)`, IPv4 rule only); iptables.go:187-188 and :357 (`!v6` only); the source is server/src/ipdb/geo.ts:57-59 (`cidrs()` includes v6); firewall.go:845-852 (Check uses Geo.Lookup, which matches v6)
- Scenario: country CN is blocked on a server with IPv6. A visitor from CN on IPv6 (all big mobile carriers) reaches every site and port. "Check IP" for that IPv6 address says `country-blocked (CN)`, but the kernel lets it in. Whitelisted countries do get IPv6 (they go through Ignore), so the two lists behave differently.
- Fix:
  - Add `country_block6` / `country_allow6` sets (nft `ipv6_addr interval`; ipset `xg_cblock6` / `xg_callow6` hash:net inet6) and `ip6 saddr` rules or ip6tables rules.
  - Keep the IPv4-only ipdeny fallback as is.
  - Test: render with a v6 country CIDR and assert the v6 drop rule is present.

## F5. The Safe Browsing API key (the master's global key) leaks into the error returned to the portal
- Severity: MEDIUM
- Kind: security
- Confidence: HIGH
- Where: reputation/domains.go:127-131; core/core.go:1707-1710 (`"warning": err.Error()`); core/mailguard.go:73 (the portal's global key is used when the server has none)
- Scenario: the key is put in the URL query (`?key=...`). On any transport error (DNS failure, timeout, TLS), Go's `*url.Error` text is `Post "https://safebrowsing.googleapis.com/...?key=<KEY>": dial tcp ...`. `domainrep.check` sends that text back as `warning`, and the scheduled run can log it. A customer who runs a domain check on their own server during a network hiccup is shown the master's global Safe Browsing key.
- Fix: send the key in the `X-Goog-Api-Key` header instead of the URL. Also wrap client errors so they never include the URL (e.g. `fmt.Errorf("safe browsing: %v", urlErr.Err)`).

## F6. IPv4-mapped CIDRs get past the "too large" limits ("::ffff:0:0/96" becomes 0.0.0.0/0)
- Severity: MEDIUM
- Kind: bug
- Confidence: HIGH (checked: `net.ParseCIDR("::ffff:0:0/96")` gives the mask 96/128 and `n.String()` gives "0.0.0.0/0")
- Where: firewall/nft.go:567-578 (ParseAddr); trusted/trusted.go:359-366 (clean, which also handles the custom trusted list from the portal); hostfw/hostfw.go:328-332 (normAddr)
- Scenario: the size check uses `bits == 128 && ones < 16`, but the canonical string that is returned is the IPv4 form.
  - A whitelist or ignore entry `::ffff:0:0/96` is stored as `0.0.0.0/0`. The whole IPv4 Internet then skips every xPGuard block, including the port filter (F2).
  - hostfw then runs `csf -a 0.0.0.0/0` and `firewall-cmd --zone=trusted --add-source=0.0.0.0/0`, which opens the server in the other firewalls too.
  - `::ffff:64.0.0.0/98` gives a `/2`.
  - Deny is safe only because isProtected happens to match.
- Fix: normalise with `netip.ParsePrefix(s)`. If `p.Addr().Is4In6()`, convert to `netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)`, refusing `Bits() < 96`, and then apply the IPv4 limit (/8). Use the same helper in the three places. Test with `::ffff:0:0/96`, which must be rejected.

## F7. Firewall Apply calls are not serialised, so an older snapshot can overwrite a newer one
- Severity: MEDIUM
- Kind: bug
- Confidence: HIGH for the missing lock; MEDIUM for the xtables-lock failures
- Where: firewall.go:338-374 (Apply has no mutex). It is called at the same time from Run (:1018/:1037/:1044/:1055), Add/Remove/Unblock/AddMany/RemoveMany, CaptchaSolved, AutoBan's fallback (:977), ApplyIPDB, core setFleet (core.go:435), refreshTrusted (hosttrust.go:153), the settings background apply, and `fw.apply` from csfpost.sh. Also iptables.go:492 and :498 (`iptables-restore --noflush` without `-w`).
- Scenario:
  - Snapshot overwrite: Apply A (from the Geo or DDNS loop) builds the ruleset, and its Build can take seconds (F10). Meanwhile the admin unblocks 1.2.3.4, and Apply B loads a ruleset without it. Then A's swap loads the older sets, and 1.2.3.4 is blocked again in the kernel while the DB and UI say "unblocked". This lasts until the next unrelated Apply, which for a deny can be hours.
  - The same overwrite can also re-add a lifted temp ban, or drop a just-added whitelist entry.
  - xtables lock: with legacy iptables (CloudLinux 7/8), two concurrent `iptables-restore` runs without `-w`, or one running alongside `csf -r`, fail on the xtables lock. The apply error is then hidden by the "retry without LOG" branch.
- Fix:
  - Add an `applyMu sync.Mutex` held across Build+Apply in `Manager.Apply`, with a dirty flag so calls made during a run coalesce into one more run.
  - Pass `-w` (`--wait`) to iptables-restore and ip6tables-restore.
  - Only retry without LOG when the error mentions the LOG target.

## F8. nftables DoS limit counts UDP and ICMP; iptables counts only TCP. Busy DNS resolvers get banned
- Severity: MEDIUM
- Kind: bug
- Confidence: HIGH
- Where: nft.go:266-267 (`ct state new update @dos4 {...}`, no protocol match); iptables.go:368 (`-p tcp`)
- Scenario: a cPanel server that is the authoritative DNS for its domains, with DoS on (threshold 150/min) and provider nftables. Google Public DNS or Cloudflare resolver egress addresses send more than 150 new UDP queries a minute. Each query is a new conntrack flow, so the address is added to `tempban4` and dropped. DNS for hosted domains then fails for everyone behind that resolver. The same server on iptables is not affected.
- Fix: add `meta l4proto tcp` (to match iptables) to both nft DoS rules. Test that the render contains `tcp` in the xg-dos rules.

## F9. Every full Apply wipes kernel-made DoS bans that were not yet recorded, and each CAPTCHA solve triggers a full reload
- Severity: MEDIUM
- Kind: failure-mode
- Confidence: HIGH
- Where: nft.go:141 (the table is deleted and recreated) and iptables.go:218-222 (`xg_tban*` swapped with DB contents); firewall.go:1060-1092 (syncDoSBans runs only once a minute); firewall.go:724 (CaptchaSolved -> Add -> Apply)
- Scenario:
  - DoS bans are created by the kernel (`add @tempban4` / `SET --add-set xg_tban`) and copied into the DB only by the next minute tick. Any Apply in between (a CAPTCHA solve, a WAF AutoBan fallback, a portal command, IPDB sync) rebuilds the tempban sets from the DB and removes those bans. During an attack with CAPTCHA traffic, DoS bans keep disappearing.
  - Each CAPTCHA solve also rebuilds the whole ruleset, including an IPDB of up to 800,000 entries and the country lists. With many visitors solving, that is a multi-second nft/ipset load per solve, and it makes F7 worse.
- Fix:
  - Before building, record the kernel's current tempban members (`syncDoSBans()` at the start of Apply, under the apply lock).
  - In CaptchaSolved, add the temp-allow with `AddElement` / `ipset add` and delete the tempban element, instead of a full Apply, the way AutoBan already does with `AddTempBan`.

## F10. Country-list downloads run inside Build, so a firewall apply can block for minutes when the portal is down
- Severity: MEDIUM
- Kind: failure-mode
- Confidence: HIGH
- Where: firewall.go:301-305 -> geo.go:125-130 (CIDRs -> Refresh) -> geo.go:68-91. Each call to Portal has a 90 s timeout (core.go:202), and ipdeny has 60 s.
- Scenario:
  - A list cached from ipdeny (source != "portal") is re-requested from the portal on **every** Build (geo.go:65). A country with no list at all retries both sources on every Build.
  - With the portal unreachable and three blocked or whitelisted countries, each Apply waits about 4.5 min. That covers every unblock, CAPTCHA solve, auto-ban fallback and the Run loop (which stops expiring rules and checking health meanwhile).
- Fix: Build should use only cached lists (`g.load`). Do network refreshes only in the Run loop or the settings apply, with a back-off per country (for example, no retry for 1 h after a failure), and then call Apply once.

## F11. Trusted lists for Meta and Yandex are taken from unverified RADb route objects
- Severity: MEDIUM
- Kind: security
- Confidence: MEDIUM
- Where: trusted/trusted.go:75 and :97 (`Format: "radb"`), :309-336 (radbRoutes), :497-511 (accepted without checks other than the /8 limit)
- Scenario: RADb is not an authoritative registry. Any RADb maintainer can create a `route:` object with `origin: AS32934` for a prefix they control, and stale objects remain. On the next daily refresh every agent adds that prefix to the trusted set. Through F2 that exempts it from the IPDB, bans and country blocks, and opens every port, fleet-wide.
- Fix:
  - Prefer published lists: Meta's crawler list, which also has rDNS `*.fbsv.facebook.com`/UA verification, and Yandex rDNS verification (VerifyCrawler already exists).
  - If RADb stays, intersect it with RPKI-valid/IRR-authoritative sources, or only accept prefixes that are also in the built-in list's supernets. Cap the number of routes.

## F12. hostfw forgets its own entries when a firewall is temporarily absent, so they are never removed later
- Severity: LOW
- Kind: bug
- Confidence: HIGH
- Where: hostfw/hostfw.go:402-420 (entries of tools with `!r.Present` are not added to `keep`)
- Scenario: firewalld is stopped during an hourly sync, so Present is false and its state entries are dropped from host-trust.json. After firewalld starts again, the `--permanent` trusted-zone sources we added are still there, but they are no longer "ours". When the admin later removes that whitelist entry in xPGuard, it stays fully trusted in firewalld (and the same applies to CSF and APF entries) for good.
- Fix: keep the state entries of tools that are not present (`if !r.Present { keep = append(keep, ownEntries...) }`) and reconcile them when the tool comes back.

## F13. AutoBan records, notifies and reports bans to the IPDB while the firewall is disabled
- Severity: LOW
- Kind: bug
- Confidence: HIGH
- Where: firewall.go:941-984 (only the kernel add is gated by `cfg.Enabled`); called from waf/waf.go:1087 and :1134, which do not check Firewall.Enabled
- Scenario: the firewall is off and WAF brute-force or WAF ban is on. Failed logins create `tempban` rules and `blocked` events, send "IP banned" notifications, and send `waf` reports to the shared IPDB, although nothing was blocked. The UI shows active blocks that do not exist.
- Fix: return early in AutoBan when `!cfg.Enabled`, or record the event with status "not enforced" and skip OnBan and the IPDB report.

## F14. Deleting a temp-ban log entry also removes an unrelated permanent deny for that IP
- Severity: LOW
- Kind: bug
- Confidence: HIGH
- Where: firewall.go:916-928 -> Unblock (:630-644, which deletes `kind IN ('deny','tempban')`)
- Scenario: 1.2.3.4 is in the blacklist (deny) and also has an older auto-ban event that is still "blocked". The admin deletes that log row on Firewall Logs, and the permanent blacklist entry is silently removed as well.
- Fix: lift only the block the event stands for: tempban for automatic sources, deny for `manual` events with expires_at=0.

## Area summary

**What I read, in full:**
- firewall/: firewall.go, iptables.go, nft.go, ipdb.go, csf.go, geo.go, bruteforce.go, connlog.go.
- hostfw/hostfw.go, tor/tor.go, trusted/trusted.go, reputation/dnsbl.go and domains.go.
- How they are wired up in core (core.go Protected/Trusted/fleet/ipdb.apply, hosttrust.go, extras.go, mailguard.go).
- The portal's geo zone endpoint and the IPDB list cap (800k, under the agent's 1,048,576 maxelem).

`go vet` is clean and the package tests pass.

**Overall health:** the rule rendering is careful. Nft loads atomically, with fallbacks. Reply traffic is accepted before every drop. Protected and portal addresses are filtered out of the IPDB and refused for deny/ban. Interval sets are collapsed. ipset is swapped through temporary sets. No shell is used: every command is an exec with an argument list, and addresses are validated before they reach rule text, so I found no rule injection.

**Riskiest spots:**
1. Unanchored log regexes, which let an attacker get any IP banned and reported to the fleet (F1).
2. The single "allow" set mixing a real whitelist with mere exemptions, which opens filtered ports to whole countries and to CDN/cloud ranges (F2).
3. sshd port detection for the port filter (F3).
4. IPv6 gaps: country blocks (F4) and mapped CIDRs (F6).
5. No apply mutex, plus full reloads on hot paths and network I/O inside Build (F7, F9, F10).

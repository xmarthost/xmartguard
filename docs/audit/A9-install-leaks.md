# A9: install / deploy / supply chain / leaks

No secret values appear in this report. Where a leak is reported, only its location and kind are given.

## F1. Agent binaries are not signed: the portal, or anyone who can push to `main`, gets root on every server
- Severity: HIGH
- Kind: security
- Confidence: HIGH
- Where: agent/internal/updater/updater.go:24-75; server/src/routes/agent.ts:46-58 (auto-update); server/src/routes/agent-cmd.ts:150-153; server/src/routes/mass.ts:171-216; server/src/routes/downloads.ts:27-44; installer/install.sh:123-127; scripts/build-agent.sh:14-17; Dockerfile:1-9; server/src/config.ts:140 (`AUTO_UPDATE_AGENTS` is on by default)
- Scenario: the only integrity check is a SHA-256 that comes from the same place as the binary. `Update()` downloads `<portal>/downloads/xpguard-agent-linux-<arch>.sha256` and the binary from the same portal and compares them. The optional `expectSHA` value also comes from that portal, in the `agent.update` command, and is `""` when an arch has no `.sha256` file. install.sh does the same. Two ways in:
  1. Anyone who can write to the portal's `/app/downloads`, or run code in the portal container, can send `agent.update`. A Node RCE, a stolen admin session (`/api/mass/run update_agent` covers every server in scope) or a compromised Docker host are all enough. The forged binary runs as root with no sandbox on every enrolled server.
  2. Anyone who can push to `main` gets the same result. The owner's documented update command builds `main` into the image, and agents auto-update 3 s after they reconnect, so a malicious commit reaches the whole fleet within minutes of the next `setup.sh` run.
- Fix:
  - Sign each release with an offline Ed25519 key. `build-agent.sh` writes `xpguard-agent-linux-<arch>.sig` over the hash and version. The private key stays on the owner's machine or in a CI secret, never on the portal.
  - Compile the public key into the agent. `updater.Update` checks the signature, and refuses a version lower than the running one, before `os.Rename`.
  - Pin the same public key in install.sh and verify there too (for example with `openssl pkeyutl -verify -rawin`).
  - Tests: an unsigned binary, a wrongly signed binary and a downgrade are each refused.

## F2. `TRUST_PROXY=true` lets any visitor choose their own IP, which bypasses the CAPTCHA address checks and the login and enroll rate limits
- Severity: HIGH
- Kind: security
- Confidence: HIGH
- Where: deploy/docker-compose.yml:32 (`TRUST_PROXY: "true"`); server/src/config.ts:131; server/src/app.ts:60 (`trustProxy: cfg.trustProxy`, i.e. trust every hop); server/src/routes/captcha.ts:222-226 (`cf-connecting-ip` is trusted whenever trustProxy is on); server/src/routes/auth.ts:29 (rate limit keyed on `req.ip`); server/src/routes/agent.ts:63,125; deploy/setup-almalinux.sh:361-367 (Apache proxy)
- Scenario:
  - **CAPTCHA, both deploy modes.** No setup puts the portal behind Cloudflare, but any client can send `CF-Connecting-IP: <blocked visitor IP>` to `/v/verify`. The verify handler then takes the spoofed address as `ip`. As a result:
    - `sameIP(ip, p.ip)` is true, so `strict_ip` and `allowOtherAddress` pass.
    - `sameNetwork` and `hostingAddress` are checked against the spoofed address, not the real cloud solver's.
    - The rate-limit `keyGenerator` uses the same header, so it can be rotated without limit.

    The cloud solvers that 0.22.17 meant to refuse (Tencent and Alibaba addresses) pass ALTCHA as if they were on the blocked visitor's own network.
  - **Login and enroll, cPanel mode.** Apache `mod_proxy` appends the client address to any `X-Forwarded-For` the client already sent. Fastify with `trustProxy: true` returns the left-most address, which the attacker controls. Rotating `X-Forwarded-For` therefore removes the 10-per-5-minutes login limit (unlimited password guessing) and forges the IPs recorded in the audit log.
- Fix:
  - Set `trustProxy` to a hop count of 1, or to the Docker bridge gateway address. Both Apache and Caddy are exactly one hop away.
  - Trust `cf-connecting-ip` only behind an explicit `CLOUDFLARE=true` setting, and only when the peer address is in Cloudflare's published ranges.
  - Regression tests: a spoofed `CF-Connecting-IP` and a spoofed left-most `X-Forwarded-For` must not change `req.ip` or `visitorIP`.

## F3. Git history holds a real JWT secret, a plaintext admin password, a hard-coded fallback admin password and allow-listed IPs
- Severity: HIGH
- Kind: leak
- Confidence: HIGH
- Where: commit 7d34684 ("Initial upload", 2026-02-05). Branch `main` contains it, and the repository appears to be public: setup-almalinux.sh clones it and the update command fetches it from raw.githubusercontent.com without a token.
  - `.env` and `.env.backup`: a real `JWT_SECRET` (43 characters), a plaintext `ADMIN_PASSWORD` (16 characters), `ADMIN_EMAIL`, `DOMAIN` and `APP_URL`. The Stripe and SMTP values are placeholders or empty, and `MONGODB_URI` has no credentials.
  - `utils/initializeApp.js:13` and `cpanel-migration-patch.sh:710`: a hard-coded fallback admin password. It is a different value from the one in `.env` and does not look like a placeholder.
  - `.htaccess:4-7`: four real public IPv4 addresses on an access allow-list (most likely the owner's own addresses).
  - Files that should not be in Git at all: `node_modules/`, `logs/*.log`, `stderr.log`, `tmp/restart.txt`, and `public/index.html.backup.*`.
- Scenario: anyone who clones the repository can read the old admin credentials and JWT secret. If the owner reused either password, or the JWT secret, on any live service, that service is exposed.
- Fix:
  - Treat both passwords and the JWT secret as compromised. Change them wherever they were reused (portal, WHM, email, GitHub).
  - Optionally rewrite history with `git filter-repo` to drop those paths, then force-push. Forks and clones keep the old copies, so changing the passwords is the part that matters.
  - Add a pre-commit or CI secret scan (gitleaks) so it cannot happen again.

## F4. A bad agent release takes down the whole fleet with no way back
- Severity: MEDIUM
- Kind: failure-mode
- Confidence: HIGH
- Where: agent/internal/updater/updater.go:60-75 (the old binary is overwritten, no copy kept); agent/cmd/xpguard-agent/main.go (`ExitForUpdate` exits 3); installer/install.sh:224-226 (`Restart=on-failure`, `RestartSec=5`); server/src/routes/agent.ts:46-58 (auto-update fires 3 s after every connect of an older agent, with no staging)
- Scenario: a release passes `version`, the only check the updater runs, but crashes or cannot connect under `run`. For example, a migration panics on a real server's database. Every agent auto-updates within seconds of reconnecting, then restart-loops or stays offline. The portal can no longer reach them to push a fix, so every server needs SSH.
- Fix:
  - Before the rename, keep the old binary as `xpguard-agent.prev`.
  - On start, a new binary writes a pending marker and clears it after its first successful portal connection.
  - A small `ExecStartPre` step, or the agent itself, restores `.prev` when the marker survives N starts or M minutes.
  - Auto-update in waves (a few servers first, the rest after they report healthy) or with random jitter.

## F5. Agent downloads load the whole 18 MB binary into memory for each request: an update wave can exhaust the portal's memory
- Severity: MEDIUM
- Kind: failure-mode
- Confidence: HIGH
- Where: server/src/routes/downloads.ts:30-43 (`fs.readFile` of the whole binary per request); server/src/routes/agent.ts:46-58
- Scenario: a release restarts the portal, and all N agents reconnect at once. Each one is older than the bundled version, so each gets `agent.update` about 3 s later. Each update downloads the binary, and the portal holds it in memory once per request (about 18 MB). With 300 servers that is about 5.4 GB at the same moment. setup-almalinux.sh explicitly supports portals with less than 3 GB of RAM (it only adds 2 GB of swap). The Node container is OOM-killed, every agent's update fails, and the next restart repeats the same cycle.
- Fix: stream the file (`fs.createReadStream` or `reply.sendFile`), or cache one Buffer per arch in memory. Add jitter and a concurrency cap to `maybeAutoUpdate`.

## F6. `http://` and `--insecure` are accepted and kept forever, so a network attacker can take over the agent and its updates
- Severity: MEDIUM
- Kind: security
- Confidence: HIGH
- Where: installer/install.sh:70,98,185; agent/internal/config/config.go:76-82 (`NormalizeURL` accepts http); agent/cmd/xpguard-agent/main.go:202 (`InsecureTLS` is saved to agent.json); agent/internal/core/core.go:1819 (`portal.move` accepts http)
- Scenario: a server enrolled with `--server http://…` or `--insecure` keeps it for good. From then on, the websocket, the commands and `agent.update` (checksum included) all go over a channel a man in the middle can rewrite. That gives root on the server. A `portal.move` command can also switch a server that uses https to an http address.
- Fix:
  - Accept only https, except for loopback addresses.
  - Allow `--insecure` only for loopback or behind an explicit test environment variable, and never save it to agent.json.
  - `checkPortalURL` must not downgrade https to http.
  - F1's signature check closes the binary path in any case.

## F7. The setup script prints the billing secret and the first admin password on every run
- Severity: MEDIUM
- Kind: leak
- Confidence: HIGH
- Where: deploy/setup-almalinux.sh:461-474; deploy/docker-compose.yml:34-35
- Scenario:
  - The owner's routine update command re-runs this script on every release. Each run prints `BILLING_SECRET` (which forges signed billing calls: licences, accounts) and `ADMIN_PASSWORD` to the terminal. Setup output is often pasted into support chats or tickets.
  - `ADMIN_PASSWORD` also stays in `deploy/.env` and in the container's environment (`docker inspect`) long after first boot, although it is only used on the first run (server/src/index.ts:16-20).
- Fix:
  - Print both values only on the run that creates them, or behind a `--show-secrets` flag.
  - After the owner account exists, remove `ADMIN_PASSWORD` from `.env` (or blank it in setup when the database already has users).

## F8. The agent log is never rotated and grows until the disk is full
- Severity: MEDIUM
- Kind: failure-mode
- Confidence: HIGH
- Where: installer/install.sh:227-228 (`StandardOutput=append:/opt/xpguard/logs/agent.log`). There is no logrotate file, and no rotation code anywhere in agent/ (grep for agent.log, logrotate or rotate finds none).
- Scenario: the agent logs at Info level for scans, WAF and firewall events. The file grows without limit under `/opt`, which on most cPanel servers is the root filesystem. Over months it fills the disk and takes MySQL and Exim down on the customer's server.
- Fix:
  - Have install.sh write `/etc/logrotate.d/xpguard-agent` (`copytruncate`, size-based, a few compressed copies), record it in the manifest, and add it to `safe_path` in uninstall.sh. Alternatively, have the agent rotate the file itself.
  - Add a test in `scripts/test-installer.sh`.

## F9. The GitHub token is left in `.git/config` when clone or fetch fails
- Severity: LOW
- Kind: leak
- Confidence: HIGH
- Where: deploy/setup-almalinux.sh:160-170
- Scenario: `--token` is written into the remote URL at line 163. If the `git fetch` at line 164 fails (network error, wrong branch), `set -E` and the ERR trap call `die`, so the reset at line 170 never runs. The token stays in `/opt/xmartguard-portal/.git/config`. While git runs, the token is also visible in other users' `ps` output.
- Fix: pass the token through `GIT_ASKPASS` or `git -c http.extraHeader="Authorization: …"` taken from the environment, instead of the URL. At minimum, reset the URL in an EXIT trap.

## F10. Real customer domains, cPanel users, server hostnames and visitor IPs in fixtures and docs
- Severity: LOW
- Kind: leak
- Confidence: MEDIUM (they are named like real sites, and HANDOFF calls them real servers)
- Where:
  - agent/internal/waf/learn_test.go:47-211 (seven customer site domains)
  - agent/internal/scanner/binary_test.go:10-13 and agent/internal/monitor/masquerade_test.go:9-14 (a customer domain and cPanel username, named as a compromised site)
  - agent/internal/captcha/captcha_test.go:236-246 (a customer domain and a server hostname)
  - agent/internal/cms/dbscan_iframe_test.go:10 (a customer domain)
  - server/test/captcha.test.ts:380-387 and docs/HANDOFF.md:120-126,148 (real visitor and CGNAT IPs, two customer domains and a server name)
- Scenario: in a public repository these identify paying customers and their incidents ("botnet of <site>"), and expose visitors' IP addresses.
- Fix: replace them with `example.com` / `.test` names, neutral usernames and RFC 5737 / RFC 3849 addresses. The test logic stays the same.

## F11. `.gitignore` misses several kinds of secret and runtime files
- Severity: LOW
- Kind: leak
- Confidence: HIGH
- Where: .gitignore (it covers `node_modules/`, `dist/`, `*.log`, `.env`, `deploy/.env` and `/data/`)
- Scenario: `.env.backup`, which was committed in 7d34684, is still not ignored. Neither are `logs/`, `*.pem`, `*.key`, `identity.key`, `agent.json`, `*.db`, `*.sqlite` or any local sample folder (for example `bench/` or `quarantine/`). The next accidental `git add .` from a dev or portal checkout commits them.
- Fix: add `.env.*` (with `!deploy/.env.example`), `logs/`, `*.pem`, `*.key`, `identity.key`, `agent.json`, `*.db`, `*.sqlite`, `bench/` and `quarantine/`.

## F12. Container images and CI actions are not pinned
- Severity: LOW
- Kind: security
- Confidence: HIGH
- Where: deploy/docker-compose.yml:8,44 (`postgres:16-alpine`, `caddy:2-alpine`); Dockerfile:3,12,19,26 (golang and node images by tag); .github/workflows/ci.yml:22-27 (`actions/*@v4`/`@v5`)
- Scenario: a moved or compromised tag changes what the portal runs on its next `setup.sh` (which runs `--build`), without any change in the repository.
- Fix: pin images by `@sha256:` digest and actions by commit SHA, and update them on purpose.

## F13. The self-test still checks the old firewall chain name
- Severity: LOW
- Kind: dead-code
- Confidence: HIGH
- Where: installer/selftest.sh:73-74
- Scenario: it prints the `XMARTGUARD` chain and its INPUT jump, but current agents use `XPGUARD` (line 78 checks that one). The report then shows "(no jump)" on a healthy server, which misleads whoever reads it.
- Fix: print `XPGUARD` (falling back to the old name).

## Area summary

**Read in full:**
- installer/install.sh, installer/uninstall.sh, installer/selftest.sh
- deploy/setup-almalinux.sh, Caddyfile, docker-compose.yml, docker-fw-check.sh, remove-portal.sh
- scripts/build-agent.sh, scripts/test-installer.sh
- Dockerfile, .dockerignore, .github/workflows/ci.yml
- server/src/agent-sign.ts, server/src/routes/downloads.ts, server/src/agents/release.ts, and the update dispatch in agent.ts, agent-cmd.ts and mass.ts
- agent/internal/updater, the `agent.update` and `portal.move` handlers, the enroll path in cmd/xpguard-agent, config and identity saving, agent/internal/panel/panel.go, and the layout reference fixer

**Leak sweep:**
- Every file ever added in all branches (3,398 paths).
- A pattern scan of the full `git log -p --all` (node_modules and lockfiles excluded) for GitHub, Google, Groq, OpenRouter, OpenAI/Anthropic, Stripe, Turnstile, Telegram, Slack, AWS, JWT, private-key, 80-hex (AbuseIPDB-style), Spamhaus DQS and serial-key formats.
- The Turnstile-format, `sk-` and serial hits are all synthetic test values.
- No private keys, DQS or AbuseIPDB keys, Malware.Expert serials or rules, cPGuard files or quarantine samples were found. `docs/CPGUARD-PARITY.md` is study notes only, and `sigdata/hashes.txt` holds xPGuard's own hash list.
- `data/` and `dist/` are not tracked and are ignored.

**Good:**
- agent.json and identity.key are written 0600 inside a 0700 directory.
- The manifest is 0600, and uninstall checks every path against an allow-list.
- The portal's port is bound to 127.0.0.1 only, and the database is not published.
- The download route uses a fixed-name allow-list.
- The portal `.env` is created with mode 600.

**Riskiest spots:**
1. The update path has no signature (F1), auto-updates the whole fleet at once and has no rollback (F4/F5).
2. The deploy's `TRUST_PROXY=true` together with the trusted `CF-Connecting-IP` header (F2).
3. The plaintext credentials in the public history (F3).

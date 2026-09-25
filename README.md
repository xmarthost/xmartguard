# XMart Guard

Server security platform for hosting servers: a cloud portal (`xmartguard.com`) plus a lightweight agent installed on each server with one command.

```
Portal (React UI + Node.js API + PostgreSQL)  <== outbound WebSocket (TLS, Ed25519-signed auth) ==  xmartguard-agent (Go, systemd)
```

The agent connects **out** to the portal, so managed servers don't need any inbound port or IP whitelist.

## Repository layout

| Path | What |
|---|---|
| `agent/` | Go agent: enrollment, identity key, inventory/metrics collection, portal session, commands |
| `server/` | Portal API (Fastify + PostgreSQL): auth, users/roles, enrollment tokens, agent WebSocket hub, metrics, audit log, installer/binary downloads |
| `web/` | Portal UI (React + Tailwind + Recharts) |
| `installer/` | One-line `install.sh` / `uninstall.sh` and the real-server `selftest.sh` (served by the portal with its URL baked in) |
| `deploy/` | Docker Compose stack for the portal (PostgreSQL + portal + Caddy auto-HTTPS) |
| `scripts/` | `build-agent.sh`, `test-installer.sh` |
| `docs/` | `PLAN.md` (roadmap), `TESTING.md` (real-server test procedure) |

## Install / uninstall on a server

The portal's **Add Server** page generates a one-time token (valid 24 h, single use) and the command:

```bash
curl -fsSL https://xmartguard.com/install.sh | bash -s -- --token XG-XXXX-XXXX-XXXX-XXXX-XXXX
```

Uninstall (removes exactly what the installer recorded in `/opt/xmartguard/manifest`, including the cPanel/WHM plugins, and prints a residue report):

```bash
curl -fsSL https://xmartguard.com/uninstall.sh | bash
# or offline:  bash /opt/xmartguard/uninstall.sh [--dry-run] [--keep-logs]
```

Files on a managed server (same `/etc` + `/opt` layout as other hosting security suites):

| Path | Purpose |
|---|---|
| `/etc/xmartguard/agent.json` (0600) | portal URL and server ID |
| `/etc/xmartguard/identity.key` (0600) | Ed25519 private key; never leaves the server |
| `/etc/xmartguard/settings.json` (0600) | security policy (scanner, firewall, IPDB, notifications) |
| `/opt/xmartguard/bin/xmartguard-agent` | agent binary (linked as `/usr/local/bin/xmartguard-agent` and `xmartguard`) |
| `/opt/xmartguard/data/` (0700) | local database, signature updates, IPDB list, `quarantine/` |
| `/opt/xmartguard/logs/` | `agent.log`, `install.log` |
| `/opt/xmartguard/manifest`, `uninstall.sh` | install manifest and local uninstaller |
| `/run/xmartguard/agent.sock` | local control socket (plugins, `xmartguard call`) |
| `/etc/systemd/system/xmartguard-agent.service` | systemd unit |

Servers installed with 0.2.x (`/var/lib/xmartguard`) are migrated automatically when the agent updates.

### cPanel / WHM plugins

On cPanel servers the agent installs two plugins (and refreshes them on every update):

- **WHM » Plugins » XMart Guard** (root): overview, virus scans (quick/full/path), detected files with quarantine/restore/disable/delete/ignore, firewall block/allow/check, IPDB status.
- **cPanel » Security » XMart Guard** (every account): scan your own website and quarantine, restore or delete your own detected files.

The plugins have no logic of their own: they talk to the agent's local socket, which identifies the caller by its Unix uid (kernel `SO_PEERCRED`). A cPanel account can only see and act on files inside its own home directory. To disable the plugins: `touch /etc/xmartguard/no-panel-plugin && xmartguard-agent panel uninstall`.

Command line (root): `xmartguard-agent call overview`, `xmartguard-agent call fw.add '{"kind":"deny","addr":"203.0.113.9"}'`, `xmartguard-agent check /home/user/public_html` (offline scan).

## IPDB — shared attacker blocklist

Every server reports the attackers it bans automatically (brute force, DoS). The portal lists an address once it has been reported by `IPDB_MIN_REPORTERS` servers (default 2) or `IPDB_MIN_REPORTS` times (default 3) within `IPDB_WINDOW_DAYS` (7); entries expire `IPDB_TTL_DAYS` (30) after the last report. Public feeds (`IPDB_FEEDS`, default Spamhaus DROP) and operator-managed manual entries and whitelist are merged in. Every agent drops the list in its own ipset/nftables set, counts hits per address and reports them back for the **IPDB** page: world map of attack origins, live monitor, daily chart and top attackers. Addresses of your own servers and private ranges are never listed. Country data: [DB-IP Lite](https://db-ip.com) (CC BY 4.0), downloaded by the portal into `DATA_DIR`.

## Deploy the portal

On a fresh Ubuntu 22.04/24.04 VPS with Docker installed and the domain's A record pointing at it:

```bash
git clone git@github.com:xmarthost/xmartguard.git && cd xmartguard/deploy
cp .env.example .env && nano .env     # DOMAIN, POSTGRES_PASSWORD, ADMIN_EMAIL, ADMIN_PASSWORD
docker compose up -d --build
```

Caddy obtains the TLS certificate automatically. Log in with `ADMIN_EMAIL` / `ADMIN_PASSWORD` and change the password under **Account**.

## Development

Requirements: Go 1.24+, Node 22+, PostgreSQL 16.

```bash
scripts/build-agent.sh                       # agent binaries -> dist/downloads
cd server && npm ci && ADMIN_EMAIL=admin@example.com ADMIN_PASSWORD=change-me-now npm run dev
cd web && npm ci && npm run dev              # http://localhost:5173 (proxies /api to :8080)
```

Tests:

```bash
(cd agent && go test ./...)
(cd server && npm test)          # needs postgres://xg:xg@localhost:5432/xmartguard_test (TEST_DATABASE_URL)
PORTAL=http://localhost:8080 ADMIN_EMAIL=... ADMIN_PASSWORD=... scripts/test-installer.sh   # destructive; disposable machine only
```

CI (`.github/workflows/ci.yml`) runs all of the above, including a real-systemd install/uninstall.

## Security model (M1)

- One-time, 24-hour enrollment tokens; only their SHA-256 is stored.
- Each agent generates an Ed25519 key locally; the portal stores only the public key. Every WebSocket session is authenticated by signing a fresh server nonce; unenroll requests are signed and time-bounded.
- Removing a server in the portal revokes it: the agent is disconnected and stops itself.
- Portal sessions are httpOnly cookies (hashed at rest), roles `owner > admin > operator > viewer`, tenant isolation on every query, JSON-only + same-origin checks on mutations, rate-limited login and enrollment, audit log of security events.
- Installer verifies the SHA-256 of the downloaded agent and refuses to run without systemd or as non-root.

# Real-server testing (GitHub workflow)

Claude builds and pushes code; you run the steps below on your servers and send back the output.

**Use only disposable test servers — never a production server with customer data.**

You need two servers:

| Server | Purpose | Suggested spec |
|---|---|---|
| **Portal VPS** | runs `xmartguard.com` (portal) | Ubuntu 24.04, 2 GB RAM, Docker installed, DNS A record → this VPS |
| **Test server** | a hosting server to protect | AlmaLinux/CloudLinux 8/9 with cPanel (trial is fine) |

---

## 1. One-time: give the portal VPS read access to the private repo

```bash
ssh-keygen -t ed25519 -f ~/.ssh/xmartguard_deploy -N ""
cat ~/.ssh/xmartguard_deploy.pub
```

GitHub → `xmarthost/xmartguard` → Settings → Deploy keys → **Add deploy key** → paste the key (leave "Allow write access" **off**).

```bash
cat >> ~/.ssh/config <<'EOF'
Host github.com
  IdentityFile ~/.ssh/xmartguard_deploy
EOF
git clone git@github.com:xmarthost/xmartguard.git /opt/xmartguard-portal
```

## 2. Start the portal (portal VPS)

```bash
cd /opt/xmartguard-portal
git checkout claude/dreamy-davinci-10tcgi      # the branch Claude pushes to
cd deploy && cp .env.example .env && nano .env  # set DOMAIN, POSTGRES_PASSWORD, ADMIN_EMAIL, ADMIN_PASSWORD
docker compose up -d --build
docker compose ps
curl -fsS https://YOUR_DOMAIN/api/health        # -> {"ok":true}
```

Open `https://YOUR_DOMAIN`, log in with ADMIN_EMAIL / ADMIN_PASSWORD.

**Updating after Claude pushes new code:**

```bash
cd /opt/xmartguard-portal && git pull && cd deploy && docker compose up -d --build
```

## 3. Install the agent (test server)

Portal → **Server List → Add Server → Create token** → copy the command and run it as root on the test server:

```bash
curl -fsSL https://YOUR_DOMAIN/install.sh | bash -s -- --token XG-....
```

The server should appear in the portal within a minute.

## 4. Run the self test and send the output back

On the test server, as root:

```bash
curl -fsSL https://YOUR_DOMAIN/selftest.sh -o /root/selftest.sh
bash /root/selftest.sh               # checks the installed agent
bash /root/selftest.sh --uninstall   # also uninstalls and checks for leftovers
```

Send back the full output (it is also saved as `/root/xmartguard-selftest-*.txt`). It contains no secrets.

Also useful to send: screenshots of the portal's server dashboard and System Monitoring pages.

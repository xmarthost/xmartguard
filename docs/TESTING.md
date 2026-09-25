# Real-server testing (GitHub workflow)

Claude builds and pushes code; you run the steps below on your servers and send back the output.

**Use only disposable test servers — never a production server with customer data.**

You need two servers:

| Server | Purpose | Suggested spec |
|---|---|---|
| **Portal VPS** | runs `xmartguard.com` (portal) | AlmaLinux 9, 2 GB RAM, DNS A record → this VPS |
| **Test server** | a hosting server to protect | AlmaLinux/CloudLinux 8/9 with cPanel (trial is fine) |

---

## 1. Start the portal (AlmaLinux 9 VPS)

Point the domain's A record at the VPS, then as root:

```bash
curl -fsSL https://raw.githubusercontent.com/xmarthost/xmartguard/main/deploy/setup-almalinux.sh -o setup.sh
bash setup.sh --domain YOUR_DOMAIN --email you@example.com
```

It installs Docker, opens ports 80/443, clones the repo to `/opt/xmartguard`, generates passwords, starts the portal with automatic HTTPS and prints the login password.

## 2. Update after Claude pushes new code

```bash
bash /opt/xmartguard/deploy/setup-almalinux.sh --domain YOUR_DOMAIN --email you@example.com
```

(add `--branch claude/dreamy-davinci-10tcgi` to test unmerged work)

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

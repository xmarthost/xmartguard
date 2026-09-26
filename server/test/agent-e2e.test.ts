// End-to-end: the real Go agent binary enrolls, connects over WebSocket,
// reports inventory/metrics, answers commands and stops when revoked.
import { spawn, execFile, execFileSync, type ChildProcess } from 'node:child_process';
import { promisify } from 'node:util';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Client, startHarness, waitFor, type Harness } from './helpers.js';

const repo = path.resolve(import.meta.dirname, '..', '..');
const agentBin = path.join(os.tmpdir(), 'xg-agent-e2e');

let h: Harness;
let c: Client;
let confDir: string;
let stateDir: string;
let webDir: string;
let proc: ChildProcess | null = null;
let serverId = '';

beforeAll(async () => {
  execFileSync('go', ['build', '-o', agentBin, './cmd/xmartguard-agent'], { cwd: path.join(repo, 'agent'), stdio: 'inherit' });
  h = await startHarness({ metricsIntervalSeconds: 5 });
  c = new Client(h.url);
  await c.login();
  confDir = fs.mkdtempSync(path.join(os.tmpdir(), 'xg-conf-'));
  stateDir = fs.mkdtempSync(path.join(os.tmpdir(), 'xg-state-'));
  webDir = fs.mkdtempSync(path.join(os.tmpdir(), 'xg-web-'));
}, 120_000);

afterAll(async () => {
  proc?.kill('SIGTERM');
  await h.close();
  for (const d of [confDir, stateDir, webDir]) fs.rmSync(d, { recursive: true, force: true });
});

// Async: the portal runs in this same process, so a sync exec would deadlock.
const run = async (args: string[], e: NodeJS.ProcessEnv) => (await promisify(execFile)(agentBin, args, { env: e })).stdout;

const env = () => ({ ...process.env, XG_CONFIG_DIR: confDir, XG_STATE_DIR: stateDir, XG_SOCKET: path.join(stateDir, 'agent.sock') });

const cmd = (action: string, body: unknown = {}) => c.req('POST', `/api/servers/${serverId}/agent/${action}`, body);

describe('agent end-to-end', () => {
  it('enrolls with a one-time token', async () => {
    const { body } = await c.req('POST', '/api/enrollment-tokens', {});
    const out = await run(['enroll', '--server', h.url, '--token', body.token], env());
    expect(out).toMatch(/Enrolled\. Server ID: /);
    const cfg = JSON.parse(fs.readFileSync(path.join(confDir, 'agent.json'), 'utf8'));
    serverId = cfg.server_id;
    // Keep the dev/CI host's firewall untouched by the test agent.
    fs.writeFileSync(path.join(confDir, 'settings.json'), JSON.stringify({ firewall: { enabled: false }, scanner: { realtime: false, daily_scan: false, weekly_scan: false }, waf: { enabled: false }, cms: { enabled: false }, domain_reputation: { enabled: false }, osm: { enabled: false } }));
    expect(fs.statSync(path.join(confDir, 'identity.key')).mode & 0o777).toBe(0o600);
    // Token is single-use: a second enroll must fail.
    await expect(run(['enroll', '--force', '--server', h.url, '--token', body.token], env())).rejects.toThrow(/already used/);
  });

  it('connects and reports inventory and metrics', async () => {
    proc = spawn(agentBin, ['run'], { env: env(), stdio: ['ignore', 'ignore', 'pipe'] });
    const srv = await waitFor(async () => {
      const r = await c.req('GET', `/api/servers/${serverId}`);
      return r.body.server?.online && r.body.server.last_metrics ? r.body.server : null;
    }, 15_000);
    expect(srv.hostname).toBe(os.hostname());
    expect(srv.inventory.cpu_cores).toBeGreaterThan(0);
    expect(srv.last_metrics.mem_total).toBeGreaterThan(0);
    expect(Array.isArray(srv.last_metrics.top_processes)).toBe(true);
    const ov = await c.req('GET', '/api/overview');
    expect(ov.body.servers_online).toBe(1);
  });

  it('persists metrics history', async () => {
    const r = await waitFor(async () => {
      const m = await c.req('GET', `/api/servers/${serverId}/metrics?range=1h`);
      return m.body.points?.length ? m : null;
    });
    expect(r.body.points[0]).toHaveProperty('cpu');
  });

  it('answers ping and live-mode commands', async () => {
    const ping = await c.req('POST', `/api/servers/${serverId}/ping`, {});
    expect(ping.status).toBe(200);
    expect(ping.body.data.pong).toBe(true);
    const live = await c.req('POST', `/api/servers/${serverId}/live`, {});
    expect(live.body.live_seconds).toBe(120);
  });

  it('runs a path scan and manages findings through the portal', async () => {
    const shell = ['<?php sys', 'tem($_GET["c"]); ?>'].join('');
    fs.mkdirSync(path.join(webDir, 'up'), { recursive: true });
    fs.writeFileSync(path.join(webDir, 'up', 'x.php'), shell);
    fs.writeFileSync(path.join(webDir, 'index.php'), '<?php echo "hello";');
    const start = await cmd('scan.start', { kind: 'path', path: webDir });
    expect(start.status).toBe(200);
    const scan = await waitFor(async () => {
      const r = await cmd('scan.list');
      const s = r.body.scans.find((x: any) => x.id === start.body.id);
      return s && s.status === 'completed' ? s : null;
    }, 15_000);
    expect(scan).toMatchObject({ files: 2, infected: 1, initiator: 'owner@example.com' });
    const f = await cmd('findings.list', { scan_id: scan.id });
    expect(f.body.total).toBe(1);
    const finding = f.body.findings[0];
    expect(finding.signature).toMatch(/^PHP\.Backdoor\./);
    const q = await cmd('finding.action', { ids: [finding.id], action: 'quarantine' });
    expect(q.body.done).toBe(1);
    expect(fs.existsSync(path.join(webDir, 'up', 'x.php'))).toBe(false);
    const r = await cmd('finding.action', { ids: [finding.id], action: 'restore' });
    expect(r.body.done).toBe(1);
    expect(fs.readFileSync(path.join(webDir, 'up', 'x.php'), 'utf8')).toBe(shell);
    expect((await cmd('scan.start', { kind: 'path', path: '/etc' })).status).toBe(409);
    const stats = await cmd('stats.get');
    expect(stats.body.summary.scanner.threats_total).toBe(1);
  });

  it('reads and updates settings with validation', async () => {
    const g = await cmd('settings.get');
    expect(g.body.settings.scanner.virus_action).toBe('notify');
    expect(g.body.settings.firewall.provider).toBe('iptables');
    const bad = await cmd('settings.set', { scanner: { virus_action: 'explode' } });
    expect(bad.status).toBe(409);
    const ok = await cmd('settings.set', { scanner: { virus_action: 'quarantine', whitelist_users: ['bob'] } });
    expect(ok.body.settings.scanner.virus_action).toBe('quarantine');
    expect((await cmd('settings.get')).body.settings.scanner.whitelist_users).toEqual(['bob']);
  });

  it('manages firewall lists and IP checks', async () => {
    expect((await cmd('fw.add', { kind: 'deny', addr: '198.51.100.0/24', comment: 'test' })).status).toBe(200);
    expect((await cmd('fw.add', { kind: 'deny', addr: 'not-an-ip' })).status).toBe(409);
    const chk = await cmd('fw.check', { ip: '198.51.100.9' });
    expect(chk.body.status).toBe('blocked');
    const list = await cmd('fw.list', { kind: 'deny' });
    expect(list.body.rules.map((r: any) => r.cidr)).toEqual(['198.51.100.0/24']);
    const ev = await cmd('fw.events');
    expect(ev.body.total).toBe(1);
    expect((await cmd('fw.unblock', { addr: '198.51.100.0/24' })).status).toBe(200);
    expect((await cmd('fw.check', { ip: '198.51.100.9' })).body.status).toBe('none');
  });

  it('asks the portal AI, trims injected code and serves xgcli', async () => {
    // A fake OpenAI-compatible API: marks lines with eval( as injected.
    const calls: any[] = [];
    const api = http.createServer((req, res) => {
      let raw = '';
      req.on('data', (d) => (raw += d));
      req.on('end', () => {
        const body = JSON.parse(raw || '{}');
        calls.push(body);
        const user: string = body.messages?.[1]?.content ?? '';
        const results = [...user.matchAll(/<file id=(\d+)[^>]*>\n([\s\S]*?)\n<\/file>/g)].map(([, id, text]) => {
          const bad = text.split('\n').filter((l) => l.includes('eval(')).map((l) => Number(l.split('|')[0]));
          return bad.length
            ? { id, verdict: 'malicious', confidence: 96, reason: 'eval of POST data added to a plugin', injected: true, cut: bad.map((n) => ({ from: n, to: n })) }
            : { id, verdict: 'clean', confidence: 90, reason: 'ordinary code', injected: false, cut: [] };
        });
        res.setHeader('content-type', 'application/json');
        res.end(JSON.stringify({ choices: [{ message: { content: JSON.stringify({ results }) } }], usage: { prompt_tokens: 50, completion_tokens: 10 } }));
      });
    });
    await new Promise<void>((r) => api.listen(0, '127.0.0.1', r));
    try {
      const url = `http://127.0.0.1:${(api.address() as any).port}/v1`;
      expect((await c.req('POST', '/api/ai/providers', { kind: 'custom', name: 'Fake Gemini', base_url: url, api_key: 'k', model: 'm', priority: 1 })).status).toBe(200);
      const set = await cmd('settings.set', { ai: { enabled: true, provider: 'portal', learn: true }, scanner: { trim: true, virus_action: 'notify' } });
      expect(set.status).toBe(200);

      const legit = ['function my_plugin_init() {', "  add_action('init', 'my_plugin_setup');", '}', ...Array.from({ length: 40 }, (_, i) => `// plugin line ${i}`)].join('\n');
      const injected = ['<?php @ev', "al($_POST['x']); ?>"].join('') + '\n<?php\n' + legit + '\n';
      const dir = path.join(webDir, 'plugin');
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(path.join(dir, 'plugin.php'), injected);
      const start = await cmd('scan.start', { kind: 'path', path: dir });
      const trimmed = await waitFor(async () => {
        const r = await cmd('findings.list', { scan_id: start.body.id });
        const f = r.body.findings?.[0];
        return f && f.status === 'trimmed' ? f : null;
      }, 30_000);
      expect(trimmed.ai_verdict).toBe('malicious');
      expect(trimmed.ai_injected).toBe(true);
      // The site keeps running with only the injected line removed.
      expect(fs.readFileSync(path.join(dir, 'plugin.php'), 'utf8')).toBe('<?php\n' + legit + '\n');
      // The original is viewable from the logs, with the AI's cut marked.
      const content = await cmd('finding.content', { id: trimmed.id });
      expect(content.body.content).toBe(injected);
      expect(content.body.ai.cut).toEqual([{ from: 1, to: 1 }]);
      // The request carried an excerpt with line numbers, not the raw file.
      expect(calls[0].messages[1].content).toContain("1|<?php @ev");
      // The verdict joined the fleet's knowledge base.
      const kb = await c.req('GET', '/api/ai/kb?verdict=malicious');
      expect(kb.body.entries[0]).toMatchObject({ name: 'plugin.php', injected: true });

      // xgcli talks to the same agent over the local socket.
      const status = await run(['cli', 'status'], env());
      expect(status).toContain('AI scanner');
      expect(status).toMatch(/portal/);
      const logs = await run(['cli', 'logs', '--status', 'trimmed'], env());
      expect(logs).toContain('plugin.php');
      const view = await run(['cli', 'view', String(trimmed.id)], env());
      expect(view).toMatch(/^>\s+1 \| <\?php @eval/m);
      await run(['cli', 'whitelist', '--user', '--add', 'carol'], env());
      expect((await cmd('settings.get')).body.settings.scanner.whitelist_users).toContain('carol');
    } finally {
      api.close();
    }
  }, 60_000);

  it('rejects unknown actions and enforces roles on agent commands', async () => {
    expect((await cmd('shell.exec', { cmd: 'id' })).status).toBe(404);
    await c.req('POST', '/api/users', { email: 'v2@example.com', password: 'viewer-password-2', role: 'viewer' });
    const viewer = new Client(h.url);
    await viewer.login('v2@example.com', 'viewer-password-2');
    expect((await viewer.req('POST', `/api/servers/${serverId}/agent/findings.list`, {})).status).toBe(200);
    expect((await viewer.req('POST', `/api/servers/${serverId}/agent/scan.start`, { kind: 'full' })).status).toBe(403);
    expect((await viewer.req('POST', `/api/servers/${serverId}/agent/settings.set`, {})).status).toBe(403);
  });

  it('rejects a WebSocket session signed with the wrong key', async () => {
    const other = fs.mkdtempSync(path.join(os.tmpdir(), 'xg-conf2-'));
    const { body } = await c.req('POST', '/api/enrollment-tokens', {});
    await run(['enroll', '--server', h.url, '--token', body.token], { ...process.env, XG_CONFIG_DIR: other, XG_STATE_DIR: path.join(other, 'state'), XG_SOCKET: path.join(other, 'agent.sock') });
    // Point the second identity at the first server's id: auth must fail.
    const cfgPath = path.join(other, 'agent.json');
    const cfg = JSON.parse(fs.readFileSync(cfgPath, 'utf8'));
    cfg.server_id = serverId;
    fs.writeFileSync(cfgPath, JSON.stringify(cfg));
    fs.writeFileSync(path.join(other, 'settings.json'), JSON.stringify({ firewall: { enabled: false }, scanner: { realtime: false, daily_scan: false, weekly_scan: false }, waf: { enabled: false }, cms: { enabled: false }, domain_reputation: { enabled: false }, osm: { enabled: false } }));
    const imposter = spawn(agentBin, ['run'], { env: { ...process.env, XG_CONFIG_DIR: other, XG_STATE_DIR: path.join(other, 'state'), XG_SOCKET: path.join(other, 'agent.sock') }, stdio: ['ignore', 'ignore', 'pipe'] });
    let log = '';
    imposter.stderr!.on('data', (d) => (log += d));
    await waitFor(async () => log.includes('authentication failed'), 10_000);
    imposter.kill('SIGTERM');
    fs.rmSync(other, { recursive: true, force: true });
    // Real agent is still the one online.
    expect((await c.req('GET', `/api/servers/${serverId}`)).body.server.online).toBe(true);
  });

  it('shares automatic bans through the IPDB and distributes the list', async () => {
    const { DatabaseSync } = await import('node:sqlite');
    const db = new DatabaseSync(path.join(stateDir, 'agent.db'));
    db.exec('PRAGMA busy_timeout = 5000');
    const now = Math.floor(Date.now() / 1000);
    const ins = db.prepare('INSERT INTO fw_events (ip, reason, source, created_at, expires_at, status) VALUES (?,?,?,?,?,?)');
    for (let i = 0; i < 3; i++) ins.run('203.0.113.50', '5 failed SSH logins', 'bruteforce', now, now + 3600, 'blocked');
    ins.run('10.0.0.5', 'private', 'bruteforce', now, now + 3600, 'blocked');
    ins.run('198.51.100.3', 'manual block', 'manual', now, 0, 'blocked');
    db.prepare('INSERT INTO ipdb_hits (entry, country, hits, pending, first_seen, last_seen) VALUES (?,?,?,?,?,?)')
      .run('192.0.2.77', 'NL', 9, 9, now, now);
    db.close();

    await h.ipdb.syncServer(serverId);
    const rep = await h.pool.query('SELECT host(ip) AS ip, source FROM ipdb_reports WHERE server_id = $1', [serverId]);
    expect(rep.rows.map((r) => r.ip).sort()).toEqual(['203.0.113.50', '203.0.113.50', '203.0.113.50']);
    await h.ipdb.rebuild();
    expect(h.ipdb.entries).toContain('203.0.113.50');

    // Second round: the agent's list is stale, so the portal pushes it.
    await h.ipdb.syncServer(serverId);
    expect(fs.readFileSync(path.join(stateDir, 'ipdb.txt'), 'utf8')).toContain('203.0.113.50');
    const st = await cmd('ipdb.status');
    expect(st.body.version).toBe(h.ipdb.version);
    expect(st.body.entries).toBeGreaterThanOrEqual(1);

    const sum = await c.req('GET', '/api/ipdb/summary');
    expect(sum.body.listed).toBe(h.ipdb.entries.length);
    expect(sum.body.servers.find((x: { id: string }) => x.id === serverId).synced).toBe(true);
    expect(sum.body.can_manage).toBe(true);
    const live = await c.req('GET', '/api/ipdb/live');
    expect(live.body.events[0]).toMatchObject({ entry: '192.0.2.77', country: 'NL', hits: 9 });
    expect(sum.body.countries).toEqual([{ country: 'NL', hits: 9, ips: 1 }]);

    const chk = await c.req('GET', '/api/ipdb/check?ip=203.0.113.50');
    expect(chk.body).toMatchObject({ listed: true, reports: 3, reporters: 1 });

    // Operator management: manual entries, whitelist, protection of own servers.
    expect((await c.req('POST', '/api/ipdb/entries', { cidr: '198.51.100.0/24', note: 'bad net' })).status).toBe(200);
    expect(h.ipdb.entries).toContain('198.51.100.0/24');
    const srv = await c.req('GET', `/api/servers/${serverId}`);
    const own = srv.body.server.inventory.ips?.[0] ?? srv.body.server.primary_ip;
    if (own) expect((await c.req('POST', '/api/ipdb/entries', { cidr: own })).status).toBe(400);
    expect((await c.req('POST', '/api/ipdb/entries', { cidr: '1.2.3.4/4' })).status).toBe(400);
    expect((await c.req('POST', '/api/ipdb/whitelist', { cidr: '203.0.113.50' })).status).toBe(200);
    expect(h.ipdb.entries).not.toContain('203.0.113.50');
    expect((await c.req('GET', '/api/ipdb/check?ip=203.0.113.50')).body.listed).toBe(false);
    await c.req('DELETE', '/api/ipdb/whitelist?cidr=203.0.113.50');
    expect(h.ipdb.entries).toContain('203.0.113.50');
    const list = await c.req('GET', '/api/ipdb/entries?source=manual');
    expect(list.body.entries.map((e: { cidr: string }) => e.cidr)).toEqual(['198.51.100.0/24']);
    expect((await c.req('DELETE', '/api/ipdb/entries?cidr=198.51.100.0/24')).status).toBe(200);
    expect(h.ipdb.entries).not.toContain('198.51.100.0/24');
  });

  it('stops cleanly when the server is removed in the portal', async () => {
    const exited = new Promise<number | null>((r) => proc!.once('exit', (code) => r(code)));
    expect((await c.req('DELETE', `/api/servers/${serverId}`)).status).toBe(200);
    expect(await exited).toBe(0);
    proc = null;
    // A restarted agent must not reconnect.
    const out = spawn(agentBin, ['run'], { env: env() });
    expect(await new Promise((r) => out.once('exit', r))).toBe(0);
  });
});

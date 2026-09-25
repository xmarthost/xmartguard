// End-to-end: the real Go agent binary enrolls, connects over WebSocket,
// reports inventory/metrics, answers commands and stops when revoked.
import { spawn, execFile, execFileSync, type ChildProcess } from 'node:child_process';
import { promisify } from 'node:util';
import fs from 'node:fs';
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

const env = () => ({ ...process.env, XG_CONFIG_DIR: confDir, XG_STATE_DIR: stateDir });

const cmd = (action: string, body: unknown = {}) => c.req('POST', `/api/servers/${serverId}/agent/${action}`, body);

describe('agent end-to-end', () => {
  it('enrolls with a one-time token', async () => {
    const { body } = await c.req('POST', '/api/enrollment-tokens', {});
    const out = await run(['enroll', '--server', h.url, '--token', body.token], env());
    expect(out).toMatch(/Enrolled\. Server ID: /);
    const cfg = JSON.parse(fs.readFileSync(path.join(confDir, 'agent.json'), 'utf8'));
    serverId = cfg.server_id;
    // Keep the dev/CI host's firewall untouched by the test agent.
    fs.writeFileSync(path.join(confDir, 'settings.json'), JSON.stringify({ firewall: { enabled: false }, scanner: { realtime: false } }));
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
    expect(finding.signature).toBe('PHP.Backdoor.ExecInput');
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
    await run(['enroll', '--server', h.url, '--token', body.token], { ...process.env, XG_CONFIG_DIR: other });
    // Point the second identity at the first server's id: auth must fail.
    const cfgPath = path.join(other, 'agent.json');
    const cfg = JSON.parse(fs.readFileSync(cfgPath, 'utf8'));
    cfg.server_id = serverId;
    fs.writeFileSync(cfgPath, JSON.stringify(cfg));
    const imposter = spawn(agentBin, ['run'], { env: { ...process.env, XG_CONFIG_DIR: other }, stdio: ['ignore', 'ignore', 'pipe'] });
    let log = '';
    imposter.stderr!.on('data', (d) => (log += d));
    await waitFor(async () => log.includes('authentication failed'), 10_000);
    imposter.kill('SIGTERM');
    fs.rmSync(other, { recursive: true, force: true });
    // Real agent is still the one online.
    expect((await c.req('GET', `/api/servers/${serverId}`)).body.server.online).toBe(true);
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
